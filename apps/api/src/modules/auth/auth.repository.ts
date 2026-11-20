import { Inject, Injectable } from '@nestjs/common';

import { DomainError } from '../../common/errors/domain-error.js';
import { authSessions } from '../../db/schema/auth-sessions.js';
import { tenants } from '../../db/schema/tenants.js';
import { userCredentials } from '../../db/schema/user-credentials.js';
import { userRoles } from '../../db/schema/user-roles.js';
import { users } from '../../db/schema/users.js';
import { and, eq, isNull } from '../../db/sql.js';
import { TenantContext } from '../../db/tenant-context.js';
import { TenantDb, type Tx } from '../../db/tenant-db.js';
import { buildAad, PiiService } from '../../security/pii/pii-crypto.js';
import type { AssignableRole } from '../users/users.types.js';

/**
 * Tenant-scoped access to credentials and account state (T06, ADR-007
 * A2/A18/A19). Every query runs through TenantDb with RLS and takes the tenant
 * from TenantContext — never from an argument or the client. Pre-auth lookups
 * are NOT here: they go through AuthLookupService.
 */

export interface CredentialState {
  readonly passwordHash: string;
  readonly mustChangePassword: boolean;
  readonly temporaryPasswordExpiresAt: Date | null;
  readonly failedAttempts: number;
  /** Row update time — a change token older than this is stale (A19). */
  readonly updatedAt: Date;
}

@Injectable()
export class AuthRepository {
  constructor(
    @Inject(TenantDb) private readonly tenantDb: TenantDb,
    @Inject(TenantContext) private readonly tenantContext: TenantContext,
    @Inject(PiiService) private readonly pii: PiiService,
  ) {}

  private tenantId(): string {
    return this.tenantContext.require().tenantId;
  }

  /**
   * Credential writes can fail with raw PG errors whose message embeds SQL
   * parameters (a hash). Operator tooling prints Error.message, so translate
   * anything unexpected into a parameter-free DomainError (T08 review M3).
   */
  private async runGuarded<T>(work: () => Promise<T>): Promise<T> {
    try {
      return await work();
    } catch (error) {
      if (error instanceof DomainError) {
        throw error;
      }
      throw DomainError.internal();
    }
  }

  /** A2: a successful login clears the delay counters. */
  async resetFailures(userId: string): Promise<void> {
    const tenantId = this.tenantId();
    await this.tenantDb.run((tx) =>
      tx
        .update(userCredentials)
        .set({ failedAttempts: 0, nextAttemptAt: null })
        .where(and(eq(userCredentials.tenantId, tenantId), eq(userCredentials.userId, userId))),
    );
  }

  /**
   * A19 operator tooling: stores the first one-time password. Always sets
   * `must_change_password` and the expiry together (the CHECK keeps them in
   * sync). Callers hash the password with PasswordService first.
   */
  async createCredentials(userId: string, passwordHash: string, expiresAt: Date): Promise<void> {
    const tenantId = this.tenantId();
    await this.runGuarded(() =>
      this.tenantDb.run((tx) =>
        tx.insert(userCredentials).values({
          tenantId,
          userId,
          passwordHash,
          mustChangePassword: true,
          temporaryPasswordExpiresAt: expiresAt,
        }),
      ),
    );
  }

  /**
   * A19 operator reset: replaces the stored hash with a fresh one-time
   * password, forces a change, resets the delay counters and revokes every
   * live session — one transaction. Returns false when the user has no
   * credential row (nothing was written).
   */
  async setOneTimePassword(
    userId: string,
    expectedPasswordHash: string,
    passwordHash: string,
    expiresAt: Date,
  ): Promise<boolean> {
    const tenantId = this.tenantId();
    const now = new Date();
    return this.runGuarded(() =>
      this.tenantDb.run(async (tx) => {
        // Compare-and-swap on the hash the operator saw: two concurrent
        // resets cannot both succeed, so a printed password is never dead on
        // arrival (T08 review LOW 7).
        const updated = await tx
          .update(userCredentials)
          .set({
            passwordHash,
            mustChangePassword: true,
            temporaryPasswordExpiresAt: expiresAt,
            failedAttempts: 0,
            nextAttemptAt: null,
          })
          .where(
            and(
              eq(userCredentials.tenantId, tenantId),
              eq(userCredentials.userId, userId),
              eq(userCredentials.passwordHash, expectedPasswordHash),
            ),
          );
        if ((updated.rowCount ?? 0) === 0) {
          return false;
        }
        await tx
          .update(authSessions)
          .set({ revokedAt: now, revokeReason: 'password_reset' })
          .where(
            and(
              eq(authSessions.tenantId, tenantId),
              eq(authSessions.userId, userId),
              isNull(authSessions.revokedAt),
            ),
          );
        return true;
      }),
    );
  }

  /** Credentials for a known user (password change, A19), or null. */
  async getCredentials(userId: string): Promise<CredentialState | null> {
    const tenantId = this.tenantId();
    const rows = await this.tenantDb.run((tx) =>
      tx
        .select({
          passwordHash: userCredentials.passwordHash,
          mustChangePassword: userCredentials.mustChangePassword,
          temporaryPasswordExpiresAt: userCredentials.temporaryPasswordExpiresAt,
          failedAttempts: userCredentials.failedAttempts,
          updatedAt: userCredentials.updatedAt,
        })
        .from(userCredentials)
        .where(and(eq(userCredentials.tenantId, tenantId), eq(userCredentials.userId, userId)))
        .limit(1),
    );
    return rows[0] ?? null;
  }

  /** Current role codes — re-read at refresh and before a password change (A18). */
  async getRoles(userId: string): Promise<AssignableRole[]> {
    const tenantId = this.tenantId();
    const rows = await this.tenantDb.run((tx) =>
      tx
        .select({ roleCode: userRoles.roleCode })
        .from(userRoles)
        .where(and(eq(userRoles.tenantId, tenantId), eq(userRoles.userId, userId))),
    );
    return rows.map((row) => row.roleCode as AssignableRole);
  }

  /**
   * Every form of the login identifier for the A20 "new password must never
   * equal the identifier" rule: the bare username, `username@tenant-code`, and
   * the normalized phone for phone-carrying accounts. The phone is decrypted
   * inside this call and never leaves the service.
   */
  async getIdentifiers(userId: string): Promise<{
    readonly username: string | null;
    readonly tenantCode: string;
    readonly phone: string | null;
  }> {
    const tenantId = this.tenantId();
    const data = await this.tenantDb.run(async (tx) => {
      const userRows = await tx
        .select({ id: users.id, username: users.username, phoneEnc: users.phoneEnc })
        .from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.id, userId)))
        .limit(1);
      const tenantRows = await tx
        .select({ code: tenants.code })
        .from(tenants)
        .where(eq(tenants.id, tenantId))
        .limit(1);
      return { user: userRows[0], tenantCode: tenantRows[0]?.code ?? '' };
    });
    const user = data.user;
    const phone =
      user === undefined || user.phoneEnc === null
        ? null
        : this.pii.decrypt(user.phoneEnc, buildAad(tenantId, 'users.phone_enc', user.id));
    return {
      username: data.user?.username ?? null,
      tenantCode: data.tenantCode,
      phone,
    };
  }

  /**
   * A18: the account may act only if the user is active and not deleted AND
   * its tenant is active and not deleted. A missing row reads as inactive.
   */
  async isAccountActive(userId: string): Promise<boolean> {
    const tenantId = this.tenantId();
    return this.tenantDb.run((tx) => this.accountActiveInTx(tx, tenantId, userId));
  }

  /** Same check inside a caller-owned transaction (used by the password CAS). */
  private async accountActiveInTx(tx: Tx, tenantId: string, userId: string): Promise<boolean> {
    const userRows = await tx
      .select({ status: users.status, deletedAt: users.deletedAt })
      .from(users)
      .where(and(eq(users.tenantId, tenantId), eq(users.id, userId)))
      .limit(1);
    const user = userRows[0];
    if (!user || user.status !== 'active' || user.deletedAt !== null) {
      return false;
    }
    const tenantRows = await tx
      .select({ status: tenants.status, deletedAt: tenants.deletedAt })
      .from(tenants)
      .where(eq(tenants.id, tenantId))
      .limit(1);
    const tenant = tenantRows[0];
    return tenant !== undefined && tenant.status === 'active' && tenant.deletedAt === null;
  }

  /**
   * A19: sets the new Argon2id hash, clears the forced-change and temp-password
   * state, resets the delay counters and revokes every live session — one
   * transaction, so a half-applied change cannot leave old sessions alive.
   *
   * The update is a compare-and-swap on the hash the caller verified: two
   * concurrent changes (or a replayed change token) can never both apply, and
   * the loser is told `false` and answers the generic 401. Sessions are only
   * revoked when this call actually changed the password.
   */
  async setPasswordAndRevokeAll(
    userId: string,
    expectedPasswordHash: string,
    newPasswordHash: string,
  ): Promise<boolean> {
    const tenantId = this.tenantId();
    const now = new Date();
    return this.tenantDb.run(async (tx) => {
      // Re-check activity INSIDE the mutation transaction: a disable committed
      // before this point is caught (no write, generic 401). Under READ
      // COMMITTED a disable landing between this SELECT and the CAS UPDATE is
      // still a millisecond-scale operator race; the first refresh revokes the
      // session under A18 (recorded LOW, not blocking).
      if (!(await this.accountActiveInTx(tx, tenantId, userId))) {
        return false;
      }
      const changed = await tx
        .update(userCredentials)
        .set({
          passwordHash: newPasswordHash,
          mustChangePassword: false,
          temporaryPasswordExpiresAt: null,
          failedAttempts: 0,
          nextAttemptAt: null,
        })
        .where(
          and(
            eq(userCredentials.tenantId, tenantId),
            eq(userCredentials.userId, userId),
            eq(userCredentials.passwordHash, expectedPasswordHash),
          ),
        );
      if ((changed.rowCount ?? 0) === 0) {
        return false;
      }
      await tx
        .update(authSessions)
        .set({ revokedAt: now, revokeReason: 'password_change' })
        .where(
          and(
            eq(authSessions.tenantId, tenantId),
            eq(authSessions.userId, userId),
            isNull(authSessions.revokedAt),
          ),
        );
      return true;
    });
  }
}

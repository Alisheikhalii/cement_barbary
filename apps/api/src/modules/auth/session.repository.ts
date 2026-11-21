import { Inject, Injectable } from '@nestjs/common';

import { DomainError } from '../../common/errors/domain-error.js';
import { authSessions } from '../../db/schema/auth-sessions.js';
import { tenants } from '../../db/schema/tenants.js';
import { userRoles } from '../../db/schema/user-roles.js';
import { users } from '../../db/schema/users.js';
import { and, eq, gt, isNull, ne } from '../../db/sql.js';
import { TenantContext } from '../../db/tenant-context.js';
import { TenantDb, type Tx } from '../../db/tenant-db.js';
import type { AssignableRole } from '../users/users.types.js';
import { constantTimeEquals } from './refresh-token.js';

/**
 * The only read/write path for `auth_sessions` (ADR-007 A8–A10). Every query
 * runs through TenantDb.run() with RLS; the tenant comes from TenantContext,
 * never from an argument. DELETE is revoked from the runtime role — sessions
 * die via `revoked_at` only.
 */

export interface NewSession {
  readonly userId: string;
  readonly familyId: string;
  readonly refreshHash: Buffer;
  readonly expiresAt: Date;
  readonly ip: string | null;
  readonly userAgent: string | null;
}

export interface RotateSessionInput {
  readonly sessionId: string;
  /** The hash of the token the client presented. */
  readonly oldHash: Buffer;
  /** The hash of the freshly generated token. */
  readonly newHash: Buffer;
  readonly ip?: string | null;
  readonly userAgent?: string | null;
}

/**
 * Outcome of a rotation attempt. `reuse` means the presented hash was the
 * session's rotated-out token: the whole family has already been revoked
 * inside the same transaction.
 */
export type RotateOutcome =
  | {
      readonly outcome: 'rotated';
      readonly familyId: string;
      readonly userId: string;
      /** Roles read in the SAME transaction as the rotation (Z7a). */
      readonly roles: readonly AssignableRole[];
    }
  | { readonly outcome: 'reuse'; readonly familyId: string; readonly revokedSessions: number }
  | { readonly outcome: 'inactive' }
  | { readonly outcome: 'missing' | 'revoked' | 'expired' | 'mismatch' };

@Injectable()
export class SessionRepository {
  constructor(
    @Inject(TenantDb) private readonly tenantDb: TenantDb,
    @Inject(TenantContext) private readonly tenantContext: TenantContext,
  ) {}

  private tenantId(): string {
    return this.tenantContext.require().tenantId;
  }

  /**
   * Inserts a session row (the token itself never reaches the database). With
   * `revokeOtherSessions`, the user row is locked FOR UPDATE first and every
   * other live session is revoked in the SAME transaction — BR-18 (A10). The
   * lock is what makes concurrent driver logins serialize: the second login
   * waits, then sees and revokes the first session, so exactly one survives.
   */
  async create(
    input: NewSession,
    options: { readonly revokeOtherSessions?: boolean } = {},
  ): Promise<{ readonly id: string }> {
    const tenantId = this.tenantId();
    const exclusive = options.revokeOtherSessions === true;
    return this.tenantDb.run(async (tx) => {
      if (exclusive) {
        await tx
          .select({ id: users.id })
          .from(users)
          .where(and(eq(users.tenantId, tenantId), eq(users.id, input.userId)))
          .for('update');
      }
      const rows = await tx
        .insert(authSessions)
        .values({
          tenantId,
          userId: input.userId,
          familyId: input.familyId,
          refreshHash: input.refreshHash,
          expiresAt: input.expiresAt,
          ip: input.ip,
          userAgent: input.userAgent,
        })
        .returning({ id: authSessions.id });
      const row = rows[0];
      if (!row) {
        throw DomainError.internal();
      }
      if (exclusive) {
        await tx
          .update(authSessions)
          .set({ revokedAt: new Date(), revokeReason: 'sibling' })
          .where(
            and(
              eq(authSessions.tenantId, tenantId),
              eq(authSessions.userId, input.userId),
              ne(authSessions.id, row.id),
              isNull(authSessions.revokedAt),
            ),
          );
      }
      return { id: row.id };
    });
  }

  /**
   * Atomically rotates a live session's refresh hash (A8/A9) AND reads the
   * account state and roles in the SAME transaction (Z7a). The user row is
   * locked FOR UPDATE, so a concurrent role change (which locks the same row
   * before writing) either commits before this read or waits until after the
   * rotation and then revokes the session.
   *
   * The conditional UPDATE remains the serialization point for concurrent
   * refreshes. A loser whose presented hash is now `previous_refresh_hash` is
   * a REUSE — the whole family is revoked in this same transaction.
   */
  async rotate(input: RotateSessionInput): Promise<RotateOutcome> {
    const tenantId = this.tenantId();
    return this.tenantDb.run(async (tx) => {
      const now = new Date();
      const sessionRows = await tx
        .select({
          userId: authSessions.userId,
          familyId: authSessions.familyId,
          refreshHash: authSessions.refreshHash,
          previousRefreshHash: authSessions.previousRefreshHash,
          revokedAt: authSessions.revokedAt,
          expiresAt: authSessions.expiresAt,
        })
        .from(authSessions)
        .where(and(eq(authSessions.tenantId, tenantId), eq(authSessions.id, input.sessionId)))
        .limit(1);
      const session = sessionRows[0];
      if (!session) {
        return { outcome: 'missing' };
      }
      if (session.revokedAt !== null) {
        return { outcome: 'revoked' };
      }
      if (session.expiresAt.getTime() <= now.getTime()) {
        return { outcome: 'expired' };
      }

      // A token that is already rotated out is reuse, regardless of account
      // state: revoke the family without revealing anything to the client.
      if (!constantTimeEquals(session.refreshHash, input.oldHash)) {
        if (
          session.previousRefreshHash !== null &&
          constantTimeEquals(session.previousRefreshHash, input.oldHash)
        ) {
          const revoked = await this.revokeFamilyInTx(
            tx,
            tenantId,
            session.familyId,
            'reuse_detected',
            now,
          );
          return {
            outcome: 'reuse',
            familyId: session.familyId,
            revokedSessions: revoked,
          };
        }
        return { outcome: 'mismatch' };
      }

      // A18/Z7a: account and tenant freshness in this transaction. The user
      // row lock serializes against UsersRepository role writes.
      const userRows = await tx
        .select({ status: users.status, deletedAt: users.deletedAt })
        .from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.id, session.userId)))
        .for('update');
      const user = userRows[0];
      const tenantRows = await tx
        .select({ status: tenants.status, deletedAt: tenants.deletedAt })
        .from(tenants)
        .where(eq(tenants.id, tenantId))
        .limit(1);
      const tenant = tenantRows[0];
      if (
        !user ||
        user.status !== 'active' ||
        user.deletedAt !== null ||
        !tenant ||
        tenant.status !== 'active' ||
        tenant.deletedAt !== null
      ) {
        await tx
          .update(authSessions)
          .set({ revokedAt: now, revokeReason: 'disabled' })
          .where(
            and(
              eq(authSessions.tenantId, tenantId),
              eq(authSessions.id, input.sessionId),
              isNull(authSessions.revokedAt),
            ),
          );
        return { outcome: 'inactive' };
      }

      const roleRows = await tx
        .select({ roleCode: userRoles.roleCode })
        .from(userRoles)
        .where(and(eq(userRoles.tenantId, tenantId), eq(userRoles.userId, session.userId)));

      const updated = await tx
        .update(authSessions)
        .set({
          refreshHash: input.newHash,
          previousRefreshHash: input.oldHash,
          rotatedAt: now,
          lastUsedAt: now,
          ...(input.ip === undefined || input.ip === null ? {} : { ip: input.ip }),
          ...(input.userAgent === undefined || input.userAgent === null
            ? {}
            : { userAgent: input.userAgent }),
        })
        .where(
          and(
            eq(authSessions.tenantId, tenantId),
            eq(authSessions.id, input.sessionId),
            eq(authSessions.refreshHash, input.oldHash),
            isNull(authSessions.revokedAt),
            gt(authSessions.expiresAt, now),
          ),
        )
        .returning({
          id: authSessions.id,
          familyId: authSessions.familyId,
          userId: authSessions.userId,
        });
      const rotated = updated[0];
      if (rotated) {
        return {
          outcome: 'rotated',
          familyId: rotated.familyId,
          userId: rotated.userId,
          roles: roleRows.map((row) => row.roleCode as AssignableRole),
        };
      }

      // A concurrent rotation won after our pre-read; re-check for reuse.
      const afterRows = await tx
        .select({
          familyId: authSessions.familyId,
          previousRefreshHash: authSessions.previousRefreshHash,
          revokedAt: authSessions.revokedAt,
          expiresAt: authSessions.expiresAt,
        })
        .from(authSessions)
        .where(and(eq(authSessions.tenantId, tenantId), eq(authSessions.id, input.sessionId)))
        .limit(1);
      const after = afterRows[0];
      if (!after) {
        return { outcome: 'missing' };
      }
      if (after.revokedAt !== null) {
        return { outcome: 'revoked' };
      }
      if (after.expiresAt.getTime() <= now.getTime()) {
        return { outcome: 'expired' };
      }
      if (
        after.previousRefreshHash !== null &&
        constantTimeEquals(after.previousRefreshHash, input.oldHash)
      ) {
        const revoked = await this.revokeFamilyInTx(
          tx,
          tenantId,
          after.familyId,
          'reuse_detected',
          now,
        );
        return { outcome: 'reuse', familyId: after.familyId, revokedSessions: revoked };
      }
      return { outcome: 'mismatch' };
    });
  }

  /** Revokes one session (logout). True when it was live. */
  async revokeSession(sessionId: string, reason: string): Promise<boolean> {
    const tenantId = this.tenantId();
    return this.tenantDb.run(async (tx) => {
      const result = await tx
        .update(authSessions)
        .set({ revokedAt: new Date(), revokeReason: reason })
        .where(
          and(
            eq(authSessions.tenantId, tenantId),
            eq(authSessions.id, sessionId),
            isNull(authSessions.revokedAt),
          ),
        );
      return (result.rowCount ?? 0) > 0;
    });
  }

  /**
   * Revokes every live session in a token family (A8). Called on reuse from
   * within rotate(), and directly when a rotated-out token is replayed.
   */
  async revokeFamily(familyId: string, reason = 'reuse_detected'): Promise<number> {
    const tenantId = this.tenantId();
    return this.tenantDb.run((tx) =>
      this.revokeFamilyInTx(tx, tenantId, familyId, reason, new Date()),
    );
  }

  /**
   * Revokes every live session of a user — password change / operator reset
   * (A19). Returns the number revoked.
   */
  async revokeAllForUser(userId: string, reason: string): Promise<number> {
    const tenantId = this.tenantId();
    return this.tenantDb.run(async (tx) => {
      const result = await tx
        .update(authSessions)
        .set({ revokedAt: new Date(), revokeReason: reason })
        .where(
          and(
            eq(authSessions.tenantId, tenantId),
            eq(authSessions.userId, userId),
            isNull(authSessions.revokedAt),
          ),
        );
      return result.rowCount ?? 0;
    });
  }

  /**
   * BR-18 hook (A10): revokes the user's other live sessions, keeping the one
   * just issued ("last device wins"). T06 calls this inside the driver login
   * transaction; the policy itself lives here, not in the login flow.
   */
  async revokeOtherSessions(
    userId: string,
    keepSessionId: string,
    reason = 'sibling',
  ): Promise<number> {
    const tenantId = this.tenantId();
    return this.tenantDb.run(async (tx) => {
      const result = await tx
        .update(authSessions)
        .set({ revokedAt: new Date(), revokeReason: reason })
        .where(
          and(
            eq(authSessions.tenantId, tenantId),
            eq(authSessions.userId, userId),
            ne(authSessions.id, keepSessionId),
            isNull(authSessions.revokedAt),
          ),
        );
      return result.rowCount ?? 0;
    });
  }

  private async revokeFamilyInTx(
    tx: Tx,
    tenantId: string,
    familyId: string,
    reason: string,
    at: Date,
  ): Promise<number> {
    const result = await tx
      .update(authSessions)
      .set({ revokedAt: at, revokeReason: reason })
      .where(
        and(
          eq(authSessions.tenantId, tenantId),
          eq(authSessions.familyId, familyId),
          isNull(authSessions.revokedAt),
        ),
      );
    return result.rowCount ?? 0;
  }
}

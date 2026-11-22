import { randomUUID } from 'node:crypto';

import { Inject, Injectable } from '@nestjs/common';

import { DomainError } from '../../common/errors/domain-error.js';
import { userRoles } from '../../db/schema/user-roles.js';
import { users } from '../../db/schema/users.js';
import { and, eq, isNull, sql } from '../../db/sql.js';
import { TenantContext } from '../../db/tenant-context.js';
import { TenantDb } from '../../db/tenant-db.js';
import { maskPhone } from '../../security/pii/mask.js';
import { normalizePhone } from '../../security/pii/normalize.js';
import { buildAad, PiiService } from '../../security/pii/pii-crypto.js';
import {
  createUserInputSchema,
  roleCodeSchema,
  toUserDto,
  USERNAME_PATTERN,
  userIdSchema,
  type AssignableRole,
  type CreateUserInput,
  type UserDto,
} from './users.types.js';

/**
 * The only write/read path for tenant users (ADR-006 U15). Every query runs
 * through TenantDb.run() as the runtime role with RLS; the tenant always comes
 * from TenantContext — never from an argument. No HTTP, no national-ID writes
 * (owner Q3): no method accepts or writes national_id_enc/national_id_hash.
 *
 * PII rules: phones are normalized → blind-indexed → encrypted with the row id
 * generated app-side BEFORE insert (U7); DTOs never carry ciphertext or
 * hashes; decryption happens only in getMaskedPhone / decryptPhonePlaintext.
 */
@Injectable()
export class UsersRepository {
  constructor(
    @Inject(TenantDb) private readonly tenantDb: TenantDb,
    @Inject(TenantContext) private readonly tenantContext: TenantContext,
    @Inject(PiiService) private readonly pii: PiiService,
  ) {}

  /**
   * Runs tenant work and translates PG failures into domain errors. Only the
   * SQLSTATEs in `translate` get a specific mapping; ANY other PG error becomes
   * a generic 500 — the raw drizzle/PG error message embeds the SQL text and
   * parameter values (PII), which key-based log redaction cannot catch (U11).
   */
  private async runGuarded<T>(
    work: () => Promise<T>,
    translate: Record<string, () => DomainError> = {},
  ): Promise<T> {
    try {
      return await work();
    } catch (err) {
      if (err instanceof DomainError) {
        throw err; // thrown by our own callbacks (validation) — already safe
      }
      const code = pgCode(err);
      if (code === undefined) {
        throw err; // not a PG failure (PII, context) — already generic
      }
      const mapped = translate[code];
      if (mapped) {
        throw mapped();
      }
      throw DomainError.internal({ pgCode: code });
    }
  }

  /** The active tenant — throws TENANT_CONTEXT_MISSING when there is none (fail closed). */
  private tenantId(): string {
    return this.tenantContext.require().tenantId;
  }

  /**
   * Creates a user. `status`/`createdBy` take their DB defaults — input can
   * never set them (strict schema). A duplicate username or phone inside the
   * tenant surfaces as a CONFLICT DomainError, never a raw PG error.
   */
  async create(input: CreateUserInput): Promise<UserDto> {
    const parsed = createUserInputSchema.safeParse(input);
    if (!parsed.success) {
      throw DomainError.badInput();
    }
    const tenantId = this.tenantId();
    const id = randomUUID();
    let phoneEnc: Buffer | null = null;
    let phoneHash: Buffer | null = null;
    if (parsed.data.phone !== undefined) {
      // normalizePhone throws badInput on invalid input and never echoes it.
      const normalized = normalizePhone(parsed.data.phone);
      phoneHash = this.pii.blindIndex('phone', tenantId, normalized);
      phoneEnc = this.pii.encrypt(normalized, buildAad(tenantId, 'users.phone_enc', id));
    }
    // 23505 = the per-tenant partial unique indexes on username/phone_hash.
    const rows = await this.runGuarded(
      () =>
        this.tenantDb.run((tx) =>
          tx
            .insert(users)
            .values({
              id,
              tenantId,
              username: parsed.data.username ?? null,
              displayName: parsed.data.displayName,
              phoneEnc,
              phoneHash,
            })
            .returning(),
        ),
      { '23505': () => DomainError.conflict() },
    );
    const row = rows[0];
    if (!row) {
      throw new Error('users insert returned no row');
    }
    return toUserDto(row);
  }

  /** Finds a live user by id in the current tenant; soft-deleted and other tenants' rows are invisible (RLS). */
  async findById(id: string): Promise<UserDto | null> {
    if (!userIdSchema.safeParse(id).success) {
      throw DomainError.badInput();
    }
    const tenantId = this.tenantId();
    const rows = await this.runGuarded(() =>
      this.tenantDb.run((tx) =>
        tx
          .select()
          .from(users)
          .where(and(eq(users.tenantId, tenantId), eq(users.id, id), isNull(users.deletedAt)))
          .limit(1),
      ),
    );
    return rows[0] ? toUserDto(rows[0]) : null;
  }

  /** Finds a live user by username. A syntactically impossible username needs no query. */
  async findByUsername(username: string): Promise<UserDto | null> {
    if (!USERNAME_PATTERN.test(username)) {
      return null;
    }
    const tenantId = this.tenantId();
    const rows = await this.runGuarded(() =>
      this.tenantDb.run((tx) =>
        tx
          .select()
          .from(users)
          .where(
            and(
              eq(users.tenantId, tenantId),
              eq(users.username, username),
              isNull(users.deletedAt),
            ),
          )
          .limit(1),
      ),
    );
    return rows[0] ? toUserDto(rows[0]) : null;
  }

  /**
   * Finds a live user by phone through the blind index (U8): normalize →
   * HMAC with the tenant inside → compare hashes only. Accepts the common
   * input forms (+98…, Persian/Arabic digits, spaces).
   */
  async findByPhone(phone: string): Promise<UserDto | null> {
    const normalized = normalizePhone(phone);
    const tenantId = this.tenantId();
    const hash = this.pii.blindIndex('phone', tenantId, normalized);
    const rows = await this.runGuarded(() =>
      this.tenantDb.run((tx) =>
        tx
          .select()
          .from(users)
          .where(
            and(eq(users.tenantId, tenantId), eq(users.phoneHash, hash), isNull(users.deletedAt)),
          )
          .limit(1),
      ),
    );
    return rows[0] ? toUserDto(rows[0]) : null;
  }

  /**
   * The user's phone masked for display (`0912***0001`, ADR-006 U11). The
   * plaintext is decrypted and masked inside this call; null when the user is
   * absent or has no phone.
   */
  async getMaskedPhone(id: string): Promise<string | null> {
    const plain = await this.decryptPhonePlaintext(id);
    return plain === null ? null : maskPhone(plain);
  }

  /**
   * PLAINTEXT phone — reserved for F4+ flows that genuinely need it (e.g. SMS
   * dispatch). NO caller exists in F1-03; do not call. Never log the result.
   */
  async decryptPhonePlaintext(id: string): Promise<string | null> {
    if (!userIdSchema.safeParse(id).success) {
      throw DomainError.badInput();
    }
    const tenantId = this.tenantId();
    const rows = await this.runGuarded(() =>
      this.tenantDb.run((tx) =>
        tx
          .select({ id: users.id, phoneEnc: users.phoneEnc })
          .from(users)
          .where(and(eq(users.tenantId, tenantId), eq(users.id, id), isNull(users.deletedAt)))
          .limit(1),
      ),
    );
    const row = rows[0];
    if (!row || row.phoneEnc === null) {
      return null;
    }
    // AAD from the STORED id (canonical form), not the caller's string: PG
    // uuid comparison is case-insensitive but the AAD string is not.
    return this.pii.decrypt(row.phoneEnc, buildAad(tenantId, 'users.phone_enc', row.id));
  }

  /**
   * Assigns a role through app.assign_user_role() (SR-05): the database derives
   * the tenant from the request context, validates the role against the
   * catalog, locks the live user row and revokes sessions in the same
   * transaction. Input can never supply tenant, scope or status. Idempotent:
   * re-assigning returns false inside the function and changes nothing.
   */
  async assignRole(userId: string, roleCode: string): Promise<void> {
    if (!userIdSchema.safeParse(userId).success) {
      throw DomainError.badInput();
    }
    const parsed = roleCodeSchema.safeParse(roleCode);
    if (!parsed.success) {
      throw DomainError.badInput();
    }
    await this.runGuarded(
      () =>
        this.tenantDb.run(async (tx) => {
          await tx.execute(sql`select app.assign_user_role(${userId}, ${parsed.data})`);
        }),
      {
        P0002: () => DomainError.badInput(),
        '22023': () => DomainError.badInput(),
        '23503': () => DomainError.badInput(),
        '23514': () => DomainError.badInput(),
      },
    );
  }

  /**
   * Revokes a role through app.revoke_user_role() (SR-05). The function locks
   * the live user row, deletes only a same-tenant link and revokes sessions in
   * the same transaction. Returns true only when a link was actually removed.
   */
  async revokeRole(userId: string, roleCode: string): Promise<boolean> {
    if (!userIdSchema.safeParse(userId).success) {
      throw DomainError.badInput();
    }
    const parsed = roleCodeSchema.safeParse(roleCode);
    if (!parsed.success) {
      throw DomainError.badInput();
    }
    return this.runGuarded(
      () =>
        this.tenantDb.run(async (tx) => {
          const result = await tx.execute(
            sql`select app.revoke_user_role(${userId}, ${parsed.data}) as removed`,
          );
          const row = result.rows[0] as { removed: boolean } | undefined;
          return row?.removed === true;
        }),
      {
        P0002: () => DomainError.badInput(),
        '22023': () => DomainError.badInput(),
      },
    );
  }

  /** The role codes a user holds in the current tenant (FK guarantees catalog membership). */
  async listRoles(userId: string): Promise<AssignableRole[]> {
    if (!userIdSchema.safeParse(userId).success) {
      throw DomainError.badInput();
    }
    const tenantId = this.tenantId();
    const rows = await this.runGuarded(() =>
      this.tenantDb.run((tx) =>
        tx
          .select({ roleCode: userRoles.roleCode })
          .from(userRoles)
          .where(and(eq(userRoles.tenantId, tenantId), eq(userRoles.userId, userId))),
      ),
    );
    return rows.map((r) => r.roleCode as AssignableRole);
  }

  /** Soft delete only (U13): sets deleted_at; hard DELETE is revoked from the runtime role. True when a row was marked. */
  async softDelete(id: string): Promise<boolean> {
    if (!userIdSchema.safeParse(id).success) {
      throw DomainError.badInput();
    }
    const tenantId = this.tenantId();
    const result = await this.runGuarded(() =>
      this.tenantDb.run((tx) =>
        tx
          .update(users)
          .set({ deletedAt: new Date() })
          .where(and(eq(users.tenantId, tenantId), eq(users.id, id), isNull(users.deletedAt))),
      ),
    );
    return (result.rowCount ?? 0) > 0;
  }
}

/** Walks drizzle's "Failed query" wrapper to the original 5-char SQLSTATE. */
function pgCode(err: unknown): string | undefined {
  let cur: unknown = err;
  for (let i = 0; i < 5 && cur !== null && cur !== undefined; i += 1) {
    const code = (cur as { code?: unknown }).code;
    if (typeof code === 'string' && code.length === 5) {
      return code;
    }
    cur = (cur as { cause?: unknown }).cause;
  }
  return undefined;
}

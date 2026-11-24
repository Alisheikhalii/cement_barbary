import { Inject, Injectable } from '@nestjs/common';

import { DomainError } from '../../../common/errors/domain-error.js';
import { likeContains } from '../../../common/pagination/like.js';
import { paginationOffset } from '../../../common/pagination/pagination.js';
import { normalizeNameKey } from '../../../common/text/name-key.js';
import { destinations } from '../../../db/schema/destinations.js';
import { and, asc, desc, eq, isNull, sql } from '../../../db/sql.js';
import { TenantDb } from '../../../db/tenant-db.js';
import { AccessScope } from '../../../security/authz/access-scope.js';
import type { DestinationListQuery } from './destinations.schemas.js';
import type { DestinationRow } from './destinations.types.js';

/**
 * The only read/write path for destinations (ADR-011 B7, T04).
 *
 * Every method takes an `AccessScope` and ANDs its tenant id into the query —
 * the tenant never comes from an argument or the body. The runtime role is
 * also constrained by RLS, so a forgotten filter still cannot cross tenants.
 * Soft-deleted rows are invisible to every method. A missing row and another
 * tenant's row are the same `null`, which the service turns into one generic
 * 404.
 */

export interface CreateDestinationRow {
  readonly name: string;
  readonly nameKey: string;
  readonly provinceName: string | null;
  readonly isActive: boolean;
  readonly displayOrder: number;
}

export interface UpdateDestinationRow {
  readonly name?: string;
  readonly nameKey?: string;
  readonly provinceName?: string;
  readonly isActive?: boolean;
  readonly displayOrder?: number;
}

export type DestinationCasResult =
  | { readonly kind: 'updated'; readonly row: DestinationRow }
  | { readonly kind: 'missing' }
  | { readonly kind: 'stale' };

const SORT_COLUMNS = {
  displayOrder: destinations.displayOrder,
  name: destinations.name,
  createdAt: destinations.createdAt,
} as const;

function scopeTenant(scope: AccessScope): string {
  // A forged/look-alike scope must never widen a query, and a carrier/own
  // scope must never act on tenant-wide base data (defense in depth: the guard
  // cannot mint one for `destination.*` today).
  if (!AccessScope.is(scope) || scope.carrierId !== null || scope.driverUserId !== null) {
    throw DomainError.forbidden();
  }
  return scope.tenantId;
}

@Injectable()
export class DestinationsRepository {
  constructor(@Inject(TenantDb) private readonly tenantDb: TenantDb) {}

  async create(scope: AccessScope, input: CreateDestinationRow): Promise<DestinationRow> {
    const tenantId = scopeTenant(scope);
    return this.runGuarded(
      () =>
        this.tenantDb.run(async (tx) => {
          const rows = await tx
            .insert(destinations)
            .values({
              tenantId,
              name: input.name,
              nameKey: input.nameKey,
              provinceName: input.provinceName,
              isActive: input.isActive,
              displayOrder: input.displayOrder,
            })
            .returning();
          const row = rows[0];
          if (row === undefined) {
            throw DomainError.internal({ reason: 'destination_insert' });
          }
          return row as DestinationRow;
        }),
      // The partial unique index on (tenant_id, name_key) WHERE deleted_at IS NULL.
      { '23505': () => DomainError.conflict({ field: 'name' }) },
    );
  }

  async list(
    scope: AccessScope,
    query: DestinationListQuery,
  ): Promise<{ readonly rows: DestinationRow[]; readonly total: number }> {
    const tenantId = scopeTenant(scope);
    const conditions = [eq(destinations.tenantId, tenantId), isNull(destinations.deletedAt)];
    if (query.isActive !== undefined) {
      conditions.push(eq(destinations.isActive, query.isActive));
    }
    if (query.q !== undefined) {
      // Normalize first (B4/T04 carry-over), then escape LIKE metacharacters.
      const pattern = likeContains(normalizeNameKey(query.q));
      conditions.push(sql`${destinations.nameKey} like ${pattern} escape '\\'`);
    }
    const where = and(...conditions);
    const orderBy = query.sort.map(({ field, direction }) =>
      direction === 'desc' ? desc(SORT_COLUMNS[field]) : asc(SORT_COLUMNS[field]),
    );
    // Stable pagination: the id tiebreak is server-only, never client-selectable.
    orderBy.push(asc(destinations.id));

    return this.runGuarded(() =>
      this.tenantDb.run(async (tx) => {
        const rows = await tx
          .select()
          .from(destinations)
          .where(where)
          .orderBy(...orderBy)
          .limit(query.pageSize)
          .offset(paginationOffset(query));
        const totals = await tx
          .select({ total: sql<number>`count(*)::int` })
          .from(destinations)
          .where(where);
        return { rows: rows as DestinationRow[], total: totals[0]?.total ?? 0 };
      }),
    );
  }

  async findById(scope: AccessScope, id: string): Promise<DestinationRow | null> {
    return this.findByIdWithLock(scope, id, false);
  }

  /**
   * The write path's visibility check. Locking the row makes `before` exact
   * under READ COMMITTED: a concurrent writer cannot commit between the read
   * and the CAS, so the audit snapshot and the version compare describe the
   * same row state.
   */
  async findByIdForUpdate(scope: AccessScope, id: string): Promise<DestinationRow | null> {
    return this.findByIdWithLock(scope, id, true);
  }

  private async findByIdWithLock(
    scope: AccessScope,
    id: string,
    forUpdate: boolean,
  ): Promise<DestinationRow | null> {
    const tenantId = scopeTenant(scope);
    const rows = await this.runGuarded(() =>
      this.tenantDb.run((tx) => {
        const query = tx
          .select()
          .from(destinations)
          .where(
            and(
              eq(destinations.tenantId, tenantId),
              eq(destinations.id, id),
              isNull(destinations.deletedAt),
            ),
          )
          .limit(1);
        return forUpdate ? query.for('update') : query;
      }),
    );
    const row = rows[0];
    return row === undefined ? null : (row as DestinationRow);
  }

  /**
   * B6 compare-and-swap. A zero-row update is resolved by a re-read in the
   * same transaction: a still-visible row means the version moved (409), an
   * absent/deleted row means 404. The caller never receives both outcomes for
   * the same observation.
   */
  async updateCas(
    scope: AccessScope,
    id: string,
    patch: UpdateDestinationRow,
    expectedVersion: number,
  ): Promise<DestinationCasResult> {
    const tenantId = scopeTenant(scope);
    return this.runGuarded(
      () =>
        this.tenantDb.run(async (tx) => {
          const rows = await tx
            .update(destinations)
            .set({
              ...(patch.name === undefined ? {} : { name: patch.name }),
              ...(patch.nameKey === undefined ? {} : { nameKey: patch.nameKey }),
              ...(patch.provinceName === undefined ? {} : { provinceName: patch.provinceName }),
              ...(patch.isActive === undefined ? {} : { isActive: patch.isActive }),
              ...(patch.displayOrder === undefined ? {} : { displayOrder: patch.displayOrder }),
              version: sql`${destinations.version} + 1`,
              updatedAt: sql`now()`,
            })
            .where(
              and(
                eq(destinations.tenantId, tenantId),
                eq(destinations.id, id),
                eq(destinations.version, expectedVersion),
                isNull(destinations.deletedAt),
              ),
            )
            .returning();
          const row = rows[0];
          if (row !== undefined) {
            return { kind: 'updated', row: row as DestinationRow };
          }
          const live = await tx
            .select({ id: destinations.id })
            .from(destinations)
            .where(
              and(
                eq(destinations.tenantId, tenantId),
                eq(destinations.id, id),
                isNull(destinations.deletedAt),
              ),
            )
            .limit(1);
          return live.length > 0 ? { kind: 'stale' } : { kind: 'missing' };
        }),
      // A PATCH that renames onto another live row is the same conflict as create.
      { '23505': () => DomainError.conflict({ field: 'name' }) },
    );
  }

  /** Soft delete with the same CAS contract as `updateCas` (B5/B6). */
  async softDeleteCas(
    scope: AccessScope,
    id: string,
    expectedVersion: number,
  ): Promise<DestinationCasResult> {
    const tenantId = scopeTenant(scope);
    return this.runGuarded(() =>
      this.tenantDb.run(async (tx) => {
        const rows = await tx
          .update(destinations)
          .set({
            deletedAt: sql`now()`,
            version: sql`${destinations.version} + 1`,
            updatedAt: sql`now()`,
          })
          .where(
            and(
              eq(destinations.tenantId, tenantId),
              eq(destinations.id, id),
              eq(destinations.version, expectedVersion),
              isNull(destinations.deletedAt),
            ),
          )
          .returning();
        const row = rows[0];
        if (row !== undefined) {
          return { kind: 'updated', row: row as DestinationRow };
        }
        const live = await tx
          .select({ id: destinations.id })
          .from(destinations)
          .where(
            and(
              eq(destinations.tenantId, tenantId),
              eq(destinations.id, id),
              isNull(destinations.deletedAt),
            ),
          )
          .limit(1);
        return live.length > 0 ? { kind: 'stale' } : { kind: 'missing' };
      }),
    );
  }

  /** Translates PG failures; any unmapped error is a generic 500 (never raw SQL). */
  private async runGuarded<T>(
    work: () => Promise<T>,
    translate: Record<string, () => DomainError> = {},
  ): Promise<T> {
    try {
      return await work();
    } catch (error) {
      if (error instanceof DomainError) {
        throw error;
      }
      const code = pgCode(error);
      if (code === undefined) {
        throw error;
      }
      // Unstorable text is bad input, not a server failure (22021 invalid byte
      // sequence / 22P05 untranslatable character). The schemas already reject
      // it; this is the DB-level backstop.
      const mapped = translate[code] ?? DB_BAD_INPUT[code];
      if (mapped) {
        throw mapped();
      }
      throw DomainError.internal({ pgCode: code });
    }
  }
}

const DB_BAD_INPUT: Readonly<Record<string, () => DomainError>> = Object.freeze({
  '22021': () => DomainError.badInput(),
  '22P05': () => DomainError.badInput(),
});

/** Walks drizzle's "Failed query" wrapper to the original 5-char SQLSTATE. */
function pgCode(error: unknown): string | undefined {
  let current: unknown = error;
  for (let i = 0; i < 5 && current !== null && current !== undefined; i += 1) {
    const code = (current as { code?: unknown }).code;
    if (typeof code === 'string' && code.length === 5) {
      return code;
    }
    current = (current as { cause?: unknown }).cause;
  }
  return undefined;
}

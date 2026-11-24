import { Inject, Injectable } from '@nestjs/common';

import { DomainError } from '../../../common/errors/domain-error.js';
import { likeContains } from '../../../common/pagination/like.js';
import { paginationOffset } from '../../../common/pagination/pagination.js';
import { normalizeNameKey } from '../../../common/text/name-key.js';
import { halls } from '../../../db/schema/halls.js';
import { and, asc, desc, eq, isNull, sql } from '../../../db/sql.js';
import { TenantDb } from '../../../db/tenant-db.js';
import type { AccessScope } from '../../../security/authz/access-scope.js';
import { runGuarded, scopeTenant } from '../repository-support.js';
import type { HallListQuery } from './halls.schemas.js';
import type { HallRow } from './halls.types.js';

/** Halls repository (ADR-011 B7, T05). Same contract as destinations. */

export interface CreateHallRow {
  readonly name: string;
  readonly nameKey: string;
  readonly isActive: boolean;
  readonly displayOrder: number;
}

export interface UpdateHallRow {
  readonly name?: string;
  readonly nameKey?: string;
  readonly isActive?: boolean;
  readonly displayOrder?: number;
}

export type HallCasResult =
  | { readonly kind: 'updated'; readonly row: HallRow }
  | { readonly kind: 'missing' }
  | { readonly kind: 'stale' };

const SORT_COLUMNS = {
  displayOrder: halls.displayOrder,
  name: halls.name,
  createdAt: halls.createdAt,
} as const;

@Injectable()
export class HallsRepository {
  constructor(@Inject(TenantDb) private readonly tenantDb: TenantDb) {}

  async create(scope: AccessScope, input: CreateHallRow): Promise<HallRow> {
    const tenantId = scopeTenant(scope);
    return runGuarded(
      () =>
        this.tenantDb.run(async (tx) => {
          const rows = await tx
            .insert(halls)
            .values({
              tenantId,
              name: input.name,
              nameKey: input.nameKey,
              isActive: input.isActive,
              displayOrder: input.displayOrder,
            })
            .returning();
          const row = rows[0];
          if (row === undefined) {
            throw DomainError.internal({ reason: 'hall_insert' });
          }
          return row as HallRow;
        }),
      { '23505': () => DomainError.conflict({ field: 'name' }) },
    );
  }

  async list(
    scope: AccessScope,
    query: HallListQuery,
  ): Promise<{ readonly rows: HallRow[]; readonly total: number }> {
    const tenantId = scopeTenant(scope);
    const conditions = [eq(halls.tenantId, tenantId), isNull(halls.deletedAt)];
    if (query.isActive !== undefined) {
      conditions.push(eq(halls.isActive, query.isActive));
    }
    if (query.q !== undefined) {
      conditions.push(
        sql`${halls.nameKey} like ${likeContains(normalizeNameKey(query.q))} escape '\\'`,
      );
    }
    const where = and(...conditions);
    const orderBy = query.sort.map(({ field, direction }) =>
      direction === 'desc' ? desc(SORT_COLUMNS[field]) : asc(SORT_COLUMNS[field]),
    );
    orderBy.push(asc(halls.id));

    return runGuarded(() =>
      this.tenantDb.run(async (tx) => {
        const rows = await tx
          .select()
          .from(halls)
          .where(where)
          .orderBy(...orderBy)
          .limit(query.pageSize)
          .offset(paginationOffset(query));
        const totals = await tx
          .select({ total: sql<number>`count(*)::int` })
          .from(halls)
          .where(where);
        return { rows: rows as HallRow[], total: totals[0]?.total ?? 0 };
      }),
    );
  }

  async findById(scope: AccessScope, id: string): Promise<HallRow | null> {
    return this.findByIdWithLock(scope, id, false);
  }

  /** Locks the live hall. Used by updates, deletes, and every terminal write (AT-11). */
  async findByIdForUpdate(scope: AccessScope, id: string): Promise<HallRow | null> {
    return this.findByIdWithLock(scope, id, true);
  }

  private async findByIdWithLock(
    scope: AccessScope,
    id: string,
    forUpdate: boolean,
  ): Promise<HallRow | null> {
    const tenantId = scopeTenant(scope);
    const rows = await runGuarded(() =>
      this.tenantDb.run((tx) => {
        const query = tx
          .select()
          .from(halls)
          .where(and(eq(halls.tenantId, tenantId), eq(halls.id, id), isNull(halls.deletedAt)))
          .limit(1);
        return forUpdate ? query.for('update') : query;
      }),
    );
    const row = rows[0];
    return row === undefined ? null : (row as HallRow);
  }

  async updateCas(
    scope: AccessScope,
    id: string,
    patch: UpdateHallRow,
    expectedVersion: number,
  ): Promise<HallCasResult> {
    const tenantId = scopeTenant(scope);
    return runGuarded(
      () =>
        this.tenantDb.run(async (tx) => {
          const rows = await tx
            .update(halls)
            .set({
              ...(patch.name === undefined ? {} : { name: patch.name }),
              ...(patch.nameKey === undefined ? {} : { nameKey: patch.nameKey }),
              ...(patch.isActive === undefined ? {} : { isActive: patch.isActive }),
              ...(patch.displayOrder === undefined ? {} : { displayOrder: patch.displayOrder }),
              version: sql`${halls.version} + 1`,
              updatedAt: sql`now()`,
            })
            .where(
              and(
                eq(halls.tenantId, tenantId),
                eq(halls.id, id),
                eq(halls.version, expectedVersion),
                isNull(halls.deletedAt),
              ),
            )
            .returning();
          const row = rows[0];
          if (row !== undefined) {
            return { kind: 'updated', row: row as HallRow };
          }
          const live = await tx
            .select({ id: halls.id })
            .from(halls)
            .where(and(eq(halls.tenantId, tenantId), eq(halls.id, id), isNull(halls.deletedAt)))
            .limit(1);
          return live.length > 0 ? { kind: 'stale' } : { kind: 'missing' };
        }),
      { '23505': () => DomainError.conflict({ field: 'name' }) },
    );
  }

  /** Soft delete. The service has already locked the row and checked live terminals. */
  async softDeleteCas(
    scope: AccessScope,
    id: string,
    expectedVersion: number,
  ): Promise<HallCasResult> {
    const tenantId = scopeTenant(scope);
    return runGuarded(() =>
      this.tenantDb.run(async (tx) => {
        const rows = await tx
          .update(halls)
          .set({
            deletedAt: sql`now()`,
            version: sql`${halls.version} + 1`,
            updatedAt: sql`now()`,
          })
          .where(
            and(
              eq(halls.tenantId, tenantId),
              eq(halls.id, id),
              eq(halls.version, expectedVersion),
              isNull(halls.deletedAt),
            ),
          )
          .returning();
        const row = rows[0];
        if (row !== undefined) {
          return { kind: 'updated', row: row as HallRow };
        }
        const live = await tx
          .select({ id: halls.id })
          .from(halls)
          .where(and(eq(halls.tenantId, tenantId), eq(halls.id, id), isNull(halls.deletedAt)))
          .limit(1);
        return live.length > 0 ? { kind: 'stale' } : { kind: 'missing' };
      }),
    );
  }
}

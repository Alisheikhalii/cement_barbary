import { Inject, Injectable } from '@nestjs/common';

import { DomainError } from '../../../common/errors/domain-error.js';
import { likeContains } from '../../../common/pagination/like.js';
import { paginationOffset } from '../../../common/pagination/pagination.js';
import { normalizeNameKey } from '../../../common/text/name-key.js';
import { loaderTypeGroups } from '../../../db/schema/loader-type-groups.js';
import { and, asc, desc, eq, isNull, sql } from '../../../db/sql.js';
import { TenantDb } from '../../../db/tenant-db.js';
import type { AccessScope } from '../../../security/authz/access-scope.js';
import { runGuarded, scopeTenant } from '../repository-support.js';
import type { LoaderTypeGroupListQuery } from './loader-types.schemas.js';
import type { LoaderTypeGroupRow } from './loader-types.types.js';

/** Loader-type groups repository (ADR-011 B7, T06). Same contract as halls. */

export interface CreateLoaderTypeGroupRow {
  readonly name: string;
  readonly nameKey: string;
  readonly isActive: boolean;
  readonly displayOrder: number;
}

export interface UpdateLoaderTypeGroupRow {
  readonly name?: string;
  readonly nameKey?: string;
  readonly isActive?: boolean;
  readonly displayOrder?: number;
}

export type LoaderTypeGroupCasResult =
  | { readonly kind: 'updated'; readonly row: LoaderTypeGroupRow }
  | { readonly kind: 'missing' }
  | { readonly kind: 'stale' };

const SORT_COLUMNS = {
  displayOrder: loaderTypeGroups.displayOrder,
  name: loaderTypeGroups.name,
  createdAt: loaderTypeGroups.createdAt,
} as const;

@Injectable()
export class LoaderTypeGroupsRepository {
  constructor(@Inject(TenantDb) private readonly tenantDb: TenantDb) {}

  async create(scope: AccessScope, input: CreateLoaderTypeGroupRow): Promise<LoaderTypeGroupRow> {
    const tenantId = scopeTenant(scope);
    return runGuarded(
      () =>
        this.tenantDb.run(async (tx) => {
          const rows = await tx
            .insert(loaderTypeGroups)
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
            throw DomainError.internal({ reason: 'loader_type_group_insert' });
          }
          return row as LoaderTypeGroupRow;
        }),
      { '23505': () => DomainError.conflict({ field: 'name' }) },
    );
  }

  async list(
    scope: AccessScope,
    query: LoaderTypeGroupListQuery,
  ): Promise<{ readonly rows: LoaderTypeGroupRow[]; readonly total: number }> {
    const tenantId = scopeTenant(scope);
    const conditions = [
      eq(loaderTypeGroups.tenantId, tenantId),
      isNull(loaderTypeGroups.deletedAt),
    ];
    if (query.isActive !== undefined) {
      conditions.push(eq(loaderTypeGroups.isActive, query.isActive));
    }
    if (query.q !== undefined) {
      conditions.push(
        sql`${loaderTypeGroups.nameKey} like ${likeContains(normalizeNameKey(query.q))} escape '\\'`,
      );
    }
    const where = and(...conditions);
    const orderBy = query.sort.map(({ field, direction }) =>
      direction === 'desc' ? desc(SORT_COLUMNS[field]) : asc(SORT_COLUMNS[field]),
    );
    orderBy.push(asc(loaderTypeGroups.id));

    return runGuarded(() =>
      this.tenantDb.run(async (tx) => {
        const rows = await tx
          .select()
          .from(loaderTypeGroups)
          .where(where)
          .orderBy(...orderBy)
          .limit(query.pageSize)
          .offset(paginationOffset(query));
        const totals = await tx
          .select({ total: sql<number>`count(*)::int` })
          .from(loaderTypeGroups)
          .where(where);
        return { rows: rows as LoaderTypeGroupRow[], total: totals[0]?.total ?? 0 };
      }),
    );
  }

  async findById(scope: AccessScope, id: string): Promise<LoaderTypeGroupRow | null> {
    return this.findByIdWithLock(scope, id, false);
  }

  /** Locks the live group (type create/move, group update/delete — AT-11). */
  async findByIdForUpdate(scope: AccessScope, id: string): Promise<LoaderTypeGroupRow | null> {
    return this.findByIdWithLock(scope, id, true);
  }

  private async findByIdWithLock(
    scope: AccessScope,
    id: string,
    forUpdate: boolean,
  ): Promise<LoaderTypeGroupRow | null> {
    const tenantId = scopeTenant(scope);
    const rows = await runGuarded(() =>
      this.tenantDb.run((tx) => {
        const query = tx
          .select()
          .from(loaderTypeGroups)
          .where(
            and(
              eq(loaderTypeGroups.tenantId, tenantId),
              eq(loaderTypeGroups.id, id),
              isNull(loaderTypeGroups.deletedAt),
            ),
          )
          .limit(1);
        return forUpdate ? query.for('update') : query;
      }),
    );
    const row = rows[0];
    return row === undefined ? null : (row as LoaderTypeGroupRow);
  }

  async updateCas(
    scope: AccessScope,
    id: string,
    patch: UpdateLoaderTypeGroupRow,
    expectedVersion: number,
  ): Promise<LoaderTypeGroupCasResult> {
    const tenantId = scopeTenant(scope);
    return runGuarded(
      () =>
        this.tenantDb.run(async (tx) => {
          const rows = await tx
            .update(loaderTypeGroups)
            .set({
              ...(patch.name === undefined ? {} : { name: patch.name }),
              ...(patch.nameKey === undefined ? {} : { nameKey: patch.nameKey }),
              ...(patch.isActive === undefined ? {} : { isActive: patch.isActive }),
              ...(patch.displayOrder === undefined ? {} : { displayOrder: patch.displayOrder }),
              version: sql`${loaderTypeGroups.version} + 1`,
              updatedAt: sql`now()`,
            })
            .where(
              and(
                eq(loaderTypeGroups.tenantId, tenantId),
                eq(loaderTypeGroups.id, id),
                eq(loaderTypeGroups.version, expectedVersion),
                isNull(loaderTypeGroups.deletedAt),
              ),
            )
            .returning();
          const row = rows[0];
          if (row !== undefined) {
            return { kind: 'updated', row: row as LoaderTypeGroupRow };
          }
          const live = await tx
            .select({ id: loaderTypeGroups.id })
            .from(loaderTypeGroups)
            .where(
              and(
                eq(loaderTypeGroups.tenantId, tenantId),
                eq(loaderTypeGroups.id, id),
                isNull(loaderTypeGroups.deletedAt),
              ),
            )
            .limit(1);
          return live.length > 0 ? { kind: 'stale' } : { kind: 'missing' };
        }),
      { '23505': () => DomainError.conflict({ field: 'name' }) },
    );
  }

  /** Soft delete. The service has locked the row and checked live types. */
  async softDeleteCas(
    scope: AccessScope,
    id: string,
    expectedVersion: number,
  ): Promise<LoaderTypeGroupCasResult> {
    const tenantId = scopeTenant(scope);
    return runGuarded(() =>
      this.tenantDb.run(async (tx) => {
        const rows = await tx
          .update(loaderTypeGroups)
          .set({
            deletedAt: sql`now()`,
            version: sql`${loaderTypeGroups.version} + 1`,
            updatedAt: sql`now()`,
          })
          .where(
            and(
              eq(loaderTypeGroups.tenantId, tenantId),
              eq(loaderTypeGroups.id, id),
              eq(loaderTypeGroups.version, expectedVersion),
              isNull(loaderTypeGroups.deletedAt),
            ),
          )
          .returning();
        const row = rows[0];
        if (row !== undefined) {
          return { kind: 'updated', row: row as LoaderTypeGroupRow };
        }
        const live = await tx
          .select({ id: loaderTypeGroups.id })
          .from(loaderTypeGroups)
          .where(
            and(
              eq(loaderTypeGroups.tenantId, tenantId),
              eq(loaderTypeGroups.id, id),
              isNull(loaderTypeGroups.deletedAt),
            ),
          )
          .limit(1);
        return live.length > 0 ? { kind: 'stale' } : { kind: 'missing' };
      }),
    );
  }
}

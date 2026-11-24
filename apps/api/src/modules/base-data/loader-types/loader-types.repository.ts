import { Inject, Injectable } from '@nestjs/common';

import { DomainError } from '../../../common/errors/domain-error.js';
import { likeContains } from '../../../common/pagination/like.js';
import { paginationOffset } from '../../../common/pagination/pagination.js';
import { normalizeNameKey } from '../../../common/text/name-key.js';
import { loaderTypes } from '../../../db/schema/loader-types.js';
import { and, asc, desc, eq, isNull, sql } from '../../../db/sql.js';
import { TenantDb } from '../../../db/tenant-db.js';
import type { AccessScope } from '../../../security/authz/access-scope.js';
import { runGuarded, scopeTenant } from '../repository-support.js';
import type { LoaderTypeListQuery } from './loader-types.schemas.js';
import type { LoaderTypeRow } from './loader-types.types.js';

/**
 * Loader types repository (ADR-011 B7, T06).
 *
 * Every query filters tenant + id. The optional `groupId` list filter is
 * applied only after the service has resolved the group inside the tenant
 * scope, so a foreign or deleted group is the same generic 404 as a missing
 * one. The service locks the target group FOR UPDATE before a create or a move
 * (AT-11); the composite FK alone only takes KEY SHARE.
 */

export interface CreateLoaderTypeRow {
  readonly groupId: string;
  readonly name: string;
  readonly nameKey: string;
  readonly isActive: boolean;
  readonly displayOrder: number;
}

export interface UpdateLoaderTypeRow {
  readonly groupId?: string;
  readonly name?: string;
  readonly nameKey?: string;
  readonly isActive?: boolean;
  readonly displayOrder?: number;
}

export type LoaderTypeCasResult =
  | { readonly kind: 'updated'; readonly row: LoaderTypeRow }
  | { readonly kind: 'missing' }
  | { readonly kind: 'stale' };

const SORT_COLUMNS = {
  displayOrder: loaderTypes.displayOrder,
  name: loaderTypes.name,
  createdAt: loaderTypes.createdAt,
} as const;

@Injectable()
export class LoaderTypesRepository {
  constructor(@Inject(TenantDb) private readonly tenantDb: TenantDb) {}

  async create(scope: AccessScope, input: CreateLoaderTypeRow): Promise<LoaderTypeRow> {
    const tenantId = scopeTenant(scope);
    return runGuarded(
      () =>
        this.tenantDb.run(async (tx) => {
          const rows = await tx
            .insert(loaderTypes)
            .values({
              tenantId,
              groupId: input.groupId,
              name: input.name,
              nameKey: input.nameKey,
              isActive: input.isActive,
              displayOrder: input.displayOrder,
            })
            .returning();
          const row = rows[0];
          if (row === undefined) {
            throw DomainError.internal({ reason: 'loader_type_insert' });
          }
          return row as LoaderTypeRow;
        }),
      { '23505': () => DomainError.conflict({ field: 'name' }) },
    );
  }

  async list(
    scope: AccessScope,
    query: LoaderTypeListQuery,
  ): Promise<{ readonly rows: LoaderTypeRow[]; readonly total: number }> {
    const tenantId = scopeTenant(scope);
    const conditions = [eq(loaderTypes.tenantId, tenantId), isNull(loaderTypes.deletedAt)];
    if (query.groupId !== undefined) {
      conditions.push(eq(loaderTypes.groupId, query.groupId));
    }
    if (query.isActive !== undefined) {
      conditions.push(eq(loaderTypes.isActive, query.isActive));
    }
    if (query.q !== undefined) {
      conditions.push(
        sql`${loaderTypes.nameKey} like ${likeContains(normalizeNameKey(query.q))} escape '\\'`,
      );
    }
    const where = and(...conditions);
    const orderBy = query.sort.map(({ field, direction }) =>
      direction === 'desc' ? desc(SORT_COLUMNS[field]) : asc(SORT_COLUMNS[field]),
    );
    orderBy.push(asc(loaderTypes.id));

    return runGuarded(() =>
      this.tenantDb.run(async (tx) => {
        const rows = await tx
          .select()
          .from(loaderTypes)
          .where(where)
          .orderBy(...orderBy)
          .limit(query.pageSize)
          .offset(paginationOffset(query));
        const totals = await tx
          .select({ total: sql<number>`count(*)::int` })
          .from(loaderTypes)
          .where(where);
        return { rows: rows as LoaderTypeRow[], total: totals[0]?.total ?? 0 };
      }),
    );
  }

  async findById(scope: AccessScope, id: string): Promise<LoaderTypeRow | null> {
    return this.findByIdWithLock(scope, id, false);
  }

  /** Locks the type row so the audit `before` is exact for the CAS. */
  async findByIdForUpdate(scope: AccessScope, id: string): Promise<LoaderTypeRow | null> {
    return this.findByIdWithLock(scope, id, true);
  }

  private async findByIdWithLock(
    scope: AccessScope,
    id: string,
    forUpdate: boolean,
  ): Promise<LoaderTypeRow | null> {
    const tenantId = scopeTenant(scope);
    const rows = await runGuarded(() =>
      this.tenantDb.run((tx) => {
        const query = tx
          .select()
          .from(loaderTypes)
          .where(
            and(
              eq(loaderTypes.tenantId, tenantId),
              eq(loaderTypes.id, id),
              isNull(loaderTypes.deletedAt),
            ),
          )
          .limit(1);
        return forUpdate ? query.for('update') : query;
      }),
    );
    const row = rows[0];
    return row === undefined ? null : (row as LoaderTypeRow);
  }

  async updateCas(
    scope: AccessScope,
    id: string,
    patch: UpdateLoaderTypeRow,
    expectedVersion: number,
  ): Promise<LoaderTypeCasResult> {
    const tenantId = scopeTenant(scope);
    return runGuarded(
      () =>
        this.tenantDb.run(async (tx) => {
          const rows = await tx
            .update(loaderTypes)
            .set({
              ...(patch.groupId === undefined ? {} : { groupId: patch.groupId }),
              ...(patch.name === undefined ? {} : { name: patch.name }),
              ...(patch.nameKey === undefined ? {} : { nameKey: patch.nameKey }),
              ...(patch.isActive === undefined ? {} : { isActive: patch.isActive }),
              ...(patch.displayOrder === undefined ? {} : { displayOrder: patch.displayOrder }),
              version: sql`${loaderTypes.version} + 1`,
              updatedAt: sql`now()`,
            })
            .where(
              and(
                eq(loaderTypes.tenantId, tenantId),
                eq(loaderTypes.id, id),
                eq(loaderTypes.version, expectedVersion),
                isNull(loaderTypes.deletedAt),
              ),
            )
            .returning();
          const row = rows[0];
          if (row !== undefined) {
            return { kind: 'updated', row: row as LoaderTypeRow };
          }
          const live = await tx
            .select({ id: loaderTypes.id })
            .from(loaderTypes)
            .where(
              and(
                eq(loaderTypes.tenantId, tenantId),
                eq(loaderTypes.id, id),
                isNull(loaderTypes.deletedAt),
              ),
            )
            .limit(1);
          return live.length > 0 ? { kind: 'stale' } : { kind: 'missing' };
        }),
      { '23505': () => DomainError.conflict({ field: 'name' }) },
    );
  }

  async softDeleteCas(
    scope: AccessScope,
    id: string,
    expectedVersion: number,
  ): Promise<LoaderTypeCasResult> {
    const tenantId = scopeTenant(scope);
    return runGuarded(() =>
      this.tenantDb.run(async (tx) => {
        const rows = await tx
          .update(loaderTypes)
          .set({
            deletedAt: sql`now()`,
            version: sql`${loaderTypes.version} + 1`,
            updatedAt: sql`now()`,
          })
          .where(
            and(
              eq(loaderTypes.tenantId, tenantId),
              eq(loaderTypes.id, id),
              eq(loaderTypes.version, expectedVersion),
              isNull(loaderTypes.deletedAt),
            ),
          )
          .returning();
        const row = rows[0];
        if (row !== undefined) {
          return { kind: 'updated', row: row as LoaderTypeRow };
        }
        const live = await tx
          .select({ id: loaderTypes.id })
          .from(loaderTypes)
          .where(
            and(
              eq(loaderTypes.tenantId, tenantId),
              eq(loaderTypes.id, id),
              isNull(loaderTypes.deletedAt),
            ),
          )
          .limit(1);
        return live.length > 0 ? { kind: 'stale' } : { kind: 'missing' };
      }),
    );
  }
}

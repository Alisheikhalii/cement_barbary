import { Inject, Injectable } from '@nestjs/common';

import { DomainError } from '../../../common/errors/domain-error.js';
import { likeContains } from '../../../common/pagination/like.js';
import { paginationOffset } from '../../../common/pagination/pagination.js';
import { normalizeNameKey } from '../../../common/text/name-key.js';
import { hallTerminals } from '../../../db/schema/hall-terminals.js';
import { and, asc, desc, eq, isNull, sql } from '../../../db/sql.js';
import { TenantDb } from '../../../db/tenant-db.js';
import type { AccessScope } from '../../../security/authz/access-scope.js';
import { runGuarded, scopeTenant } from '../repository-support.js';
import type { TerminalListQuery } from './halls.schemas.js';
import type { TerminalRow } from './halls.types.js';

/**
 * Terminals repository (ADR-011 B7, T05). Every query filters tenant + hall,
 * so a terminal reached through another hall's path is the same generic 404
 * as a missing one. The service verifies and LOCKS the parent hall before any
 * write (AT-11).
 */

export interface CreateTerminalRow {
  readonly name: string;
  readonly nameKey: string;
  readonly isActive: boolean;
  readonly displayOrder: number;
}

export interface UpdateTerminalRow {
  readonly name?: string;
  readonly nameKey?: string;
  readonly isActive?: boolean;
  readonly displayOrder?: number;
}

export type TerminalCasResult =
  | { readonly kind: 'updated'; readonly row: TerminalRow }
  | { readonly kind: 'missing' }
  | { readonly kind: 'stale' };

const SORT_COLUMNS = {
  displayOrder: hallTerminals.displayOrder,
  name: hallTerminals.name,
  createdAt: hallTerminals.createdAt,
} as const;

@Injectable()
export class TerminalsRepository {
  constructor(@Inject(TenantDb) private readonly tenantDb: TenantDb) {}

  async create(scope: AccessScope, hallId: string, input: CreateTerminalRow): Promise<TerminalRow> {
    const tenantId = scopeTenant(scope);
    return runGuarded(
      () =>
        this.tenantDb.run(async (tx) => {
          const rows = await tx
            .insert(hallTerminals)
            .values({
              tenantId,
              hallId,
              name: input.name,
              nameKey: input.nameKey,
              isActive: input.isActive,
              displayOrder: input.displayOrder,
            })
            .returning();
          const row = rows[0];
          if (row === undefined) {
            throw DomainError.internal({ reason: 'terminal_insert' });
          }
          return row as TerminalRow;
        }),
      { '23505': () => DomainError.conflict({ field: 'name' }) },
    );
  }

  async list(
    scope: AccessScope,
    hallId: string,
    query: TerminalListQuery,
  ): Promise<{ readonly rows: TerminalRow[]; readonly total: number }> {
    const tenantId = scopeTenant(scope);
    const conditions = [
      eq(hallTerminals.tenantId, tenantId),
      eq(hallTerminals.hallId, hallId),
      isNull(hallTerminals.deletedAt),
    ];
    if (query.isActive !== undefined) {
      conditions.push(eq(hallTerminals.isActive, query.isActive));
    }
    if (query.q !== undefined) {
      conditions.push(
        sql`${hallTerminals.nameKey} like ${likeContains(normalizeNameKey(query.q))} escape '\\'`,
      );
    }
    const where = and(...conditions);
    const orderBy = query.sort.map(({ field, direction }) =>
      direction === 'desc' ? desc(SORT_COLUMNS[field]) : asc(SORT_COLUMNS[field]),
    );
    orderBy.push(asc(hallTerminals.id));

    return runGuarded(() =>
      this.tenantDb.run(async (tx) => {
        const rows = await tx
          .select()
          .from(hallTerminals)
          .where(where)
          .orderBy(...orderBy)
          .limit(query.pageSize)
          .offset(paginationOffset(query));
        const totals = await tx
          .select({ total: sql<number>`count(*)::int` })
          .from(hallTerminals)
          .where(where);
        return { rows: rows as TerminalRow[], total: totals[0]?.total ?? 0 };
      }),
    );
  }

  async findById(scope: AccessScope, hallId: string, id: string): Promise<TerminalRow | null> {
    return this.findByIdWithLock(scope, hallId, id, false);
  }

  /** Locks the terminal row so the audit `before` is exact for the CAS. */
  async findByIdForUpdate(
    scope: AccessScope,
    hallId: string,
    id: string,
  ): Promise<TerminalRow | null> {
    return this.findByIdWithLock(scope, hallId, id, true);
  }

  private async findByIdWithLock(
    scope: AccessScope,
    hallId: string,
    id: string,
    forUpdate: boolean,
  ): Promise<TerminalRow | null> {
    const tenantId = scopeTenant(scope);
    const rows = await runGuarded(() =>
      this.tenantDb.run((tx) => {
        const query = tx
          .select()
          .from(hallTerminals)
          .where(
            and(
              eq(hallTerminals.tenantId, tenantId),
              eq(hallTerminals.hallId, hallId),
              eq(hallTerminals.id, id),
              isNull(hallTerminals.deletedAt),
            ),
          )
          .limit(1);
        return forUpdate ? query.for('update') : query;
      }),
    );
    const row = rows[0];
    return row === undefined ? null : (row as TerminalRow);
  }

  async updateCas(
    scope: AccessScope,
    hallId: string,
    id: string,
    patch: UpdateTerminalRow,
    expectedVersion: number,
  ): Promise<TerminalCasResult> {
    const tenantId = scopeTenant(scope);
    return runGuarded(
      () =>
        this.tenantDb.run(async (tx) => {
          const rows = await tx
            .update(hallTerminals)
            .set({
              ...(patch.name === undefined ? {} : { name: patch.name }),
              ...(patch.nameKey === undefined ? {} : { nameKey: patch.nameKey }),
              ...(patch.isActive === undefined ? {} : { isActive: patch.isActive }),
              ...(patch.displayOrder === undefined ? {} : { displayOrder: patch.displayOrder }),
              version: sql`${hallTerminals.version} + 1`,
              updatedAt: sql`now()`,
            })
            .where(
              and(
                eq(hallTerminals.tenantId, tenantId),
                eq(hallTerminals.hallId, hallId),
                eq(hallTerminals.id, id),
                eq(hallTerminals.version, expectedVersion),
                isNull(hallTerminals.deletedAt),
              ),
            )
            .returning();
          const row = rows[0];
          if (row !== undefined) {
            return { kind: 'updated', row: row as TerminalRow };
          }
          const live = await tx
            .select({ id: hallTerminals.id })
            .from(hallTerminals)
            .where(
              and(
                eq(hallTerminals.tenantId, tenantId),
                eq(hallTerminals.hallId, hallId),
                eq(hallTerminals.id, id),
                isNull(hallTerminals.deletedAt),
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
    hallId: string,
    id: string,
    expectedVersion: number,
  ): Promise<TerminalCasResult> {
    const tenantId = scopeTenant(scope);
    return runGuarded(() =>
      this.tenantDb.run(async (tx) => {
        const rows = await tx
          .update(hallTerminals)
          .set({
            deletedAt: sql`now()`,
            version: sql`${hallTerminals.version} + 1`,
            updatedAt: sql`now()`,
          })
          .where(
            and(
              eq(hallTerminals.tenantId, tenantId),
              eq(hallTerminals.hallId, hallId),
              eq(hallTerminals.id, id),
              eq(hallTerminals.version, expectedVersion),
              isNull(hallTerminals.deletedAt),
            ),
          )
          .returning();
        const row = rows[0];
        if (row !== undefined) {
          return { kind: 'updated', row: row as TerminalRow };
        }
        const live = await tx
          .select({ id: hallTerminals.id })
          .from(hallTerminals)
          .where(
            and(
              eq(hallTerminals.tenantId, tenantId),
              eq(hallTerminals.hallId, hallId),
              eq(hallTerminals.id, id),
              isNull(hallTerminals.deletedAt),
            ),
          )
          .limit(1);
        return live.length > 0 ? { kind: 'stale' } : { kind: 'missing' };
      }),
    );
  }
}

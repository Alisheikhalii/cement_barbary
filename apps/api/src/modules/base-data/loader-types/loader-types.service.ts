import { Inject, Injectable } from '@nestjs/common';

import { DomainError } from '../../../common/errors/domain-error.js';
import { paginationMeta } from '../../../common/pagination/pagination.js';
import { normalizeNameKey } from '../../../common/text/name-key.js';
import { TenantContext } from '../../../db/tenant-context.js';
import { TenantDb, type Tx } from '../../../db/tenant-db.js';
import { AccessScope } from '../../../security/authz/access-scope.js';
import type { BaseDataWriteActor } from '../base-data.actor.js';
import { AuditWriter } from '../../audit/audit-writer.js';
import { assertNotReferenced } from '../reference-guard.js';
import { LoaderTypeGroupReferences } from './loader-type-group-references.js';
import { LoaderTypeGroupsRepository } from './loader-type-groups.repository.js';
import type {
  CreateLoaderTypeGroupInput,
  CreateLoaderTypeInput,
  DeleteQuery,
  LoaderTypeGroupListQuery,
  LoaderTypeGroupListResult,
  LoaderTypeListQuery,
  LoaderTypeListResult,
  UpdateLoaderTypeGroupInput,
  UpdateLoaderTypeInput,
} from './loader-types.schemas.js';
import {
  loaderTypeGroupSnapshot,
  loaderTypeSnapshot,
  toLoaderTypeDto,
  toLoaderTypeGroupDto,
  type LoaderTypeDto,
  type LoaderTypeGroupDto,
} from './loader-types.types.js';
import { LoaderTypesRepository } from './loader-types.repository.js';

/**
 * Loader-type groups and loader types (F1-07 T06, ADR-011 B4–B8).
 *
 * AT-11 locking, both directions:
 *  - a loader-type create and a move between groups lock the TARGET LIVE group
 *    row `FOR UPDATE` before writing;
 *  - a group delete locks itself `FOR UPDATE`, then checks for live types.
 * A composite FK only takes KEY SHARE, which does not conflict with the
 * soft-delete UPDATE, so these explicit locks are what make the pair safe.
 *
 * A move locks only the target group: the source group's delete either sees
 * the type and refuses (409) or runs after the move committed and sees none,
 * so locking it too would only add a two-group lock order that can deadlock.
 *
 * Lock order is the type row first, then the target group. No path takes a
 * group lock and then a type ROW lock (the delete guard reads types without
 * locking), so this inverse order cannot cycle today; keep it that way if a
 * future guard starts locking children.
 *
 * Each write and its audit row share one transaction (fail-closed).
 */
@Injectable()
export class LoaderTypesService {
  constructor(
    @Inject(TenantDb) private readonly tenantDb: TenantDb,
    @Inject(TenantContext) private readonly tenantContext: TenantContext,
    @Inject(LoaderTypeGroupsRepository) private readonly groups: LoaderTypeGroupsRepository,
    @Inject(LoaderTypesRepository) private readonly types: LoaderTypesRepository,
    @Inject(LoaderTypeGroupReferences) private readonly groupRefs: LoaderTypeGroupReferences,
    @Inject(AuditWriter) private readonly audit: AuditWriter,
  ) {}

  // ---------- groups ----------

  async listGroups(
    scope: AccessScope,
    query: LoaderTypeGroupListQuery,
  ): Promise<LoaderTypeGroupListResult> {
    return this.withTenantTx(scope, async () => {
      const { rows, total } = await this.groups.list(scope, query);
      return { data: rows.map(toLoaderTypeGroupDto), meta: paginationMeta(query, total) };
    });
  }

  async getGroup(scope: AccessScope, id: string): Promise<LoaderTypeGroupDto> {
    return this.withTenantTx(scope, async () => {
      const row = await this.groups.findById(scope, id);
      if (row === null) {
        throw DomainError.notFound();
      }
      return toLoaderTypeGroupDto(row);
    });
  }

  async createGroup(
    scope: AccessScope,
    input: CreateLoaderTypeGroupInput,
    actor: BaseDataWriteActor,
  ): Promise<LoaderTypeGroupDto> {
    const nameKey = normalizeNameKey(input.name);
    return this.withTenantTx(scope, async () => {
      const row = await this.groups.create(scope, {
        name: input.name,
        nameKey,
        isActive: input.isActive,
        displayOrder: input.displayOrder,
      });
      await this.audit.append({
        actorType: 'user',
        actorUserId: actor.userId,
        actorSessionId: actor.sessionId,
        action: 'loader_type_group.created',
        resourceType: 'loader_type_group',
        resourceId: row.id,
        outcome: 'success',
        httpStatus: 201,
        after: loaderTypeGroupSnapshot(row),
        ip: actor.ip,
        requestId: actor.requestId,
      });
      return toLoaderTypeGroupDto(row);
    });
  }

  async updateGroup(
    scope: AccessScope,
    id: string,
    input: UpdateLoaderTypeGroupInput,
    actor: BaseDataWriteActor,
  ): Promise<LoaderTypeGroupDto> {
    const nameKey = input.name === undefined ? undefined : normalizeNameKey(input.name);
    return this.withTenantTx(scope, async () => {
      const before = await this.groups.findByIdForUpdate(scope, id);
      if (before === null) {
        throw DomainError.notFound();
      }
      if (before.version !== input.expectedVersion) {
        throw DomainError.staleVersion();
      }
      const result = await this.groups.updateCas(
        scope,
        id,
        {
          ...(input.name === undefined || nameKey === undefined
            ? {}
            : { name: input.name, nameKey }),
          ...(input.isActive === undefined ? {} : { isActive: input.isActive }),
          ...(input.displayOrder === undefined ? {} : { displayOrder: input.displayOrder }),
        },
        input.expectedVersion,
      );
      if (result.kind === 'missing') {
        throw DomainError.notFound();
      }
      if (result.kind === 'stale') {
        throw DomainError.staleVersion();
      }
      await this.audit.append({
        actorType: 'user',
        actorUserId: actor.userId,
        actorSessionId: actor.sessionId,
        action: 'loader_type_group.updated',
        resourceType: 'loader_type_group',
        resourceId: id,
        outcome: 'success',
        httpStatus: 200,
        before: loaderTypeGroupSnapshot(before),
        after: loaderTypeGroupSnapshot(result.row),
        ip: actor.ip,
        requestId: actor.requestId,
      });
      return toLoaderTypeGroupDto(result.row);
    });
  }

  async deleteGroup(
    scope: AccessScope,
    id: string,
    query: DeleteQuery,
    actor: BaseDataWriteActor,
  ): Promise<void> {
    return this.withTenantTx(scope, async (tx) => {
      const before = await this.groups.findByIdForUpdate(scope, id);
      if (before === null) {
        throw DomainError.notFound();
      }
      if (before.version !== query.expectedVersion) {
        throw DomainError.staleVersion();
      }
      // Same transaction and the group row is locked: a concurrent type create
      // or move into this group cannot slip between this check and the soft
      // delete (AT-11).
      await assertNotReferenced(this.groupRefs, tx, scope, id);
      const result = await this.groups.softDeleteCas(scope, id, query.expectedVersion);
      if (result.kind === 'missing') {
        throw DomainError.notFound();
      }
      if (result.kind === 'stale') {
        throw DomainError.staleVersion();
      }
      await this.audit.append({
        actorType: 'user',
        actorUserId: actor.userId,
        actorSessionId: actor.sessionId,
        action: 'loader_type_group.deleted',
        resourceType: 'loader_type_group',
        resourceId: id,
        outcome: 'success',
        httpStatus: 204,
        before: loaderTypeGroupSnapshot(before),
        after: loaderTypeGroupSnapshot(result.row),
        ip: actor.ip,
        requestId: actor.requestId,
      });
    });
  }

  // ---------- types ----------

  async listTypes(scope: AccessScope, query: LoaderTypeListQuery): Promise<LoaderTypeListResult> {
    return this.withTenantTx(scope, async () => {
      if (query.groupId !== undefined) {
        // A missing/deleted/other-tenant group filter is the same 404 as a
        // missing group — never an empty page that reveals the difference.
        await this.requireLiveGroup(scope, query.groupId);
      }
      const { rows, total } = await this.types.list(scope, query);
      return { data: rows.map(toLoaderTypeDto), meta: paginationMeta(query, total) };
    });
  }

  async getType(scope: AccessScope, id: string): Promise<LoaderTypeDto> {
    return this.withTenantTx(scope, async () => {
      const row = await this.types.findById(scope, id);
      if (row === null) {
        throw DomainError.notFound();
      }
      return toLoaderTypeDto(row);
    });
  }

  async createType(
    scope: AccessScope,
    input: CreateLoaderTypeInput,
    actor: BaseDataWriteActor,
  ): Promise<LoaderTypeDto> {
    const nameKey = normalizeNameKey(input.name);
    return this.withTenantTx(scope, async () => {
      // AT-11: lock the live target group BEFORE inserting the child. A
      // missing/deleted/foreign group is the generic 404.
      await this.requireLiveGroupForUpdate(scope, input.groupId);
      const row = await this.types.create(scope, {
        groupId: input.groupId,
        name: input.name,
        nameKey,
        isActive: input.isActive,
        displayOrder: input.displayOrder,
      });
      await this.audit.append({
        actorType: 'user',
        actorUserId: actor.userId,
        actorSessionId: actor.sessionId,
        action: 'loader_type.created',
        resourceType: 'loader_type',
        resourceId: row.id,
        outcome: 'success',
        httpStatus: 201,
        after: loaderTypeSnapshot(row),
        metadata: { groupId: row.groupId },
        ip: actor.ip,
        requestId: actor.requestId,
      });
      return toLoaderTypeDto(row);
    });
  }

  async updateType(
    scope: AccessScope,
    id: string,
    input: UpdateLoaderTypeInput,
    actor: BaseDataWriteActor,
  ): Promise<LoaderTypeDto> {
    const nameKey = input.name === undefined ? undefined : normalizeNameKey(input.name);
    return this.withTenantTx(scope, async () => {
      const before = await this.types.findByIdForUpdate(scope, id);
      if (before === null) {
        throw DomainError.notFound();
      }
      if (before.version !== input.expectedVersion) {
        throw DomainError.staleVersion();
      }
      if (input.groupId !== undefined) {
        // AT-11: a move locks the target live group before the row update. A
        // concurrent delete of that group either commits first (404 here) or
        // waits and then sees the moved type (409 IN_USE).
        await this.requireLiveGroupForUpdate(scope, input.groupId);
      }
      const result = await this.types.updateCas(
        scope,
        id,
        {
          ...(input.groupId === undefined ? {} : { groupId: input.groupId }),
          ...(input.name === undefined || nameKey === undefined
            ? {}
            : { name: input.name, nameKey }),
          ...(input.isActive === undefined ? {} : { isActive: input.isActive }),
          ...(input.displayOrder === undefined ? {} : { displayOrder: input.displayOrder }),
        },
        input.expectedVersion,
      );
      if (result.kind === 'missing') {
        throw DomainError.notFound();
      }
      if (result.kind === 'stale') {
        throw DomainError.staleVersion();
      }
      const moved = input.groupId !== undefined && input.groupId !== before.groupId;
      await this.audit.append({
        actorType: 'user',
        actorUserId: actor.userId,
        actorSessionId: actor.sessionId,
        action: 'loader_type.updated',
        resourceType: 'loader_type',
        resourceId: id,
        outcome: 'success',
        httpStatus: 200,
        before: loaderTypeSnapshot(before),
        after: loaderTypeSnapshot(result.row),
        metadata: moved
          ? { groupId: result.row.groupId, previousGroupId: before.groupId }
          : { groupId: result.row.groupId },
        ip: actor.ip,
        requestId: actor.requestId,
      });
      return toLoaderTypeDto(result.row);
    });
  }

  async deleteType(
    scope: AccessScope,
    id: string,
    query: DeleteQuery,
    actor: BaseDataWriteActor,
  ): Promise<void> {
    return this.withTenantTx(scope, async () => {
      const before = await this.types.findByIdForUpdate(scope, id);
      if (before === null) {
        throw DomainError.notFound();
      }
      if (before.version !== query.expectedVersion) {
        throw DomainError.staleVersion();
      }
      const result = await this.types.softDeleteCas(scope, id, query.expectedVersion);
      if (result.kind === 'missing') {
        throw DomainError.notFound();
      }
      if (result.kind === 'stale') {
        throw DomainError.staleVersion();
      }
      await this.audit.append({
        actorType: 'user',
        actorUserId: actor.userId,
        actorSessionId: actor.sessionId,
        action: 'loader_type.deleted',
        resourceType: 'loader_type',
        resourceId: id,
        outcome: 'success',
        httpStatus: 204,
        before: loaderTypeSnapshot(before),
        after: loaderTypeSnapshot(result.row),
        metadata: { groupId: before.groupId },
        ip: actor.ip,
        requestId: actor.requestId,
      });
    });
  }

  private async requireLiveGroup(scope: AccessScope, groupId: string): Promise<void> {
    if ((await this.groups.findById(scope, groupId)) === null) {
      throw DomainError.notFound();
    }
  }

  private async requireLiveGroupForUpdate(scope: AccessScope, groupId: string): Promise<void> {
    if ((await this.groups.findByIdForUpdate(scope, groupId)) === null) {
      throw DomainError.notFound();
    }
  }

  private async withTenantTx<T>(scope: AccessScope, work: (tx: Tx) => Promise<T>): Promise<T> {
    if (!AccessScope.is(scope)) {
      throw DomainError.forbidden();
    }
    const active = this.tenantContext.current();
    if (active !== undefined && active.tenantId === scope.tenantId) {
      return this.tenantDb.run(work);
    }
    return this.tenantContext.run({ tenantId: scope.tenantId }, () => this.tenantDb.run(work));
  }
}

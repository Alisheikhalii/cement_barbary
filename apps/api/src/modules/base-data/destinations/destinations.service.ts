import { Inject, Injectable } from '@nestjs/common';

import { DomainError } from '../../../common/errors/domain-error.js';
import { paginationMeta } from '../../../common/pagination/pagination.js';
import { normalizeNameKey } from '../../../common/text/name-key.js';
import { TenantContext } from '../../../db/tenant-context.js';
import { TenantDb } from '../../../db/tenant-db.js';
import { AccessScope } from '../../../security/authz/access-scope.js';
import type { BaseDataWriteActor } from '../base-data.actor.js';
import { AuditWriter } from '../../audit/audit-writer.js';
import { DestinationsRepository } from './destinations.repository.js';
import type {
  CreateDestinationInput,
  DestinationListQuery,
  DestinationListResult,
  DeleteDestinationQuery,
  UpdateDestinationInput,
} from './destinations.schemas.js';
import {
  destinationSnapshot,
  toDestinationDto,
  type DestinationDto,
} from './destinations.types.js';

/**
 * Destination use cases (F1-07 T04, ADR-011 B4–B8).
 *
 * Each write and its `audit_logs` row run in ONE transaction: the service
 * opens the tenant context + transaction, the repository reuses it, and the
 * audit append reuses it too. A failed audit therefore rolls the business
 * change back (fail-closed), and an idempotent replay (which never reaches the
 * service) cannot produce a second row.
 *
 * The caller passes an `AccessScope` from the guard; the service never builds
 * one from request data.
 */
@Injectable()
export class DestinationsService {
  constructor(
    @Inject(TenantDb) private readonly tenantDb: TenantDb,
    @Inject(TenantContext) private readonly tenantContext: TenantContext,
    @Inject(DestinationsRepository) private readonly repository: DestinationsRepository,
    @Inject(AuditWriter) private readonly audit: AuditWriter,
  ) {}

  async list(scope: AccessScope, query: DestinationListQuery): Promise<DestinationListResult> {
    return this.withTenant(scope, async () => {
      const { rows, total } = await this.repository.list(scope, query);
      return { data: rows.map(toDestinationDto), meta: paginationMeta(query, total) };
    });
  }

  async get(scope: AccessScope, id: string): Promise<DestinationDto> {
    return this.withTenant(scope, async () => {
      const row = await this.repository.findById(scope, id);
      if (row === null) {
        throw DomainError.notFound();
      }
      return toDestinationDto(row);
    });
  }

  async create(
    scope: AccessScope,
    input: CreateDestinationInput,
    actor: BaseDataWriteActor,
  ): Promise<DestinationDto> {
    const nameKey = normalizeNameKey(input.name);
    return this.withTenant(scope, async () => {
      const row = await this.repository.create(scope, {
        name: input.name,
        nameKey,
        provinceName: input.provinceName ?? null,
        isActive: input.isActive,
        displayOrder: input.displayOrder,
      });
      await this.audit.append({
        actorType: 'user',
        actorUserId: actor.userId,
        actorSessionId: actor.sessionId,
        action: 'destination.created',
        resourceType: 'destination',
        resourceId: row.id,
        outcome: 'success',
        httpStatus: 201,
        after: destinationSnapshot(row),
        ip: actor.ip,
        requestId: actor.requestId,
      });
      return toDestinationDto(row);
    });
  }

  async update(
    scope: AccessScope,
    id: string,
    input: UpdateDestinationInput,
    actor: BaseDataWriteActor,
  ): Promise<DestinationDto> {
    const nameKey = input.name === undefined ? undefined : normalizeNameKey(input.name);
    return this.withTenant(scope, async () => {
      // Lock first: the audit `before` and the version comparison must describe
      // the same row state; a concurrent writer then waits and loses on version.
      const before = await this.repository.findByIdForUpdate(scope, id);
      if (before === null) {
        throw DomainError.notFound();
      }
      if (before.version !== input.expectedVersion) {
        throw DomainError.staleVersion();
      }
      const result = await this.repository.updateCas(
        scope,
        id,
        {
          ...(input.name === undefined || nameKey === undefined
            ? {}
            : { name: input.name, nameKey }),
          ...(input.provinceName === undefined ? {} : { provinceName: input.provinceName }),
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
        action: 'destination.updated',
        resourceType: 'destination',
        resourceId: id,
        outcome: 'success',
        httpStatus: 200,
        before: destinationSnapshot(before),
        after: destinationSnapshot(result.row),
        ip: actor.ip,
        requestId: actor.requestId,
      });
      return toDestinationDto(result.row);
    });
  }

  async delete(
    scope: AccessScope,
    id: string,
    query: DeleteDestinationQuery,
    actor: BaseDataWriteActor,
  ): Promise<void> {
    return this.withTenant(scope, async () => {
      const before = await this.repository.findByIdForUpdate(scope, id);
      if (before === null) {
        throw DomainError.notFound();
      }
      if (before.version !== query.expectedVersion) {
        throw DomainError.staleVersion();
      }
      const result = await this.repository.softDeleteCas(scope, id, query.expectedVersion);
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
        action: 'destination.deleted',
        resourceType: 'destination',
        resourceId: id,
        outcome: 'success',
        httpStatus: 204,
        before: destinationSnapshot(before),
        after: destinationSnapshot(result.row),
        ip: actor.ip,
        requestId: actor.requestId,
      });
    });
  }

  /**
   * Every read and write runs under the request's tenant. Mutating routes are
   * already inside the idempotency interceptor's transaction; the same-scope
   * nested run reuses it, so the audit row commits atomically with the change.
   */
  private async withTenant<T>(scope: AccessScope, work: () => Promise<T>): Promise<T> {
    if (!AccessScope.is(scope)) {
      throw DomainError.forbidden();
    }
    const active = this.tenantContext.current();
    if (active !== undefined && active.tenantId === scope.tenantId) {
      // Mutating routes already run inside the idempotency interceptor's
      // context/transaction; keep it (and its carrier id, if a future
      // principal has one) instead of attempting a scope switch mid-tx.
      return this.tenantDb.run(work);
    }
    return this.tenantContext.run({ tenantId: scope.tenantId }, () => this.tenantDb.run(work));
  }
}

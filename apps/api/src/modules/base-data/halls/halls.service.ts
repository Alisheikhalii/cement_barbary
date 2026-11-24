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
import { HallTerminalReferences } from './hall-terminal-references.js';
import { HallsRepository } from './halls.repository.js';
import type {
  CreateHallInput,
  CreateTerminalInput,
  DeleteQuery,
  HallListQuery,
  HallListResult,
  TerminalListQuery,
  TerminalListResult,
  UpdateHallInput,
  UpdateTerminalInput,
} from './halls.schemas.js';
import {
  hallSnapshot,
  terminalSnapshot,
  toHallDto,
  toTerminalDto,
  type HallDto,
  type TerminalDto,
} from './halls.types.js';
import { TerminalsRepository } from './terminals.repository.js';

/**
 * Halls and nested terminals (F1-07 T05, ADR-011 B4–B8).
 *
 * AT-11 locking, both directions:
 *  - every terminal write locks the LIVE hall row `FOR UPDATE` first;
 *  - a hall delete locks itself `FOR UPDATE`, then checks for live terminals.
 * A composite FK only takes KEY SHARE, which does not conflict with the
 * soft-delete UPDATE, so these explicit locks are what make the pair safe.
 *
 * Each write and its audit row share one transaction (fail-closed).
 */
@Injectable()
export class HallsService {
  constructor(
    @Inject(TenantDb) private readonly tenantDb: TenantDb,
    @Inject(TenantContext) private readonly tenantContext: TenantContext,
    @Inject(HallsRepository) private readonly halls: HallsRepository,
    @Inject(TerminalsRepository) private readonly terminals: TerminalsRepository,
    @Inject(HallTerminalReferences) private readonly terminalRefs: HallTerminalReferences,
    @Inject(AuditWriter) private readonly audit: AuditWriter,
  ) {}

  async list(scope: AccessScope, query: HallListQuery): Promise<HallListResult> {
    return this.withTenantTx(scope, async () => {
      const { rows, total } = await this.halls.list(scope, query);
      return { data: rows.map(toHallDto), meta: paginationMeta(query, total) };
    });
  }

  async get(scope: AccessScope, id: string): Promise<HallDto> {
    return this.withTenantTx(scope, async () => {
      const row = await this.halls.findById(scope, id);
      if (row === null) {
        throw DomainError.notFound();
      }
      return toHallDto(row);
    });
  }

  async create(
    scope: AccessScope,
    input: CreateHallInput,
    actor: BaseDataWriteActor,
  ): Promise<HallDto> {
    const nameKey = normalizeNameKey(input.name);
    return this.withTenantTx(scope, async () => {
      const row = await this.halls.create(scope, {
        name: input.name,
        nameKey,
        isActive: input.isActive,
        displayOrder: input.displayOrder,
      });
      await this.audit.append({
        actorType: 'user',
        actorUserId: actor.userId,
        actorSessionId: actor.sessionId,
        action: 'hall.created',
        resourceType: 'hall',
        resourceId: row.id,
        outcome: 'success',
        httpStatus: 201,
        after: hallSnapshot(row),
        ip: actor.ip,
        requestId: actor.requestId,
      });
      return toHallDto(row);
    });
  }

  async update(
    scope: AccessScope,
    id: string,
    input: UpdateHallInput,
    actor: BaseDataWriteActor,
  ): Promise<HallDto> {
    const nameKey = input.name === undefined ? undefined : normalizeNameKey(input.name);
    return this.withTenantTx(scope, async () => {
      const before = await this.halls.findByIdForUpdate(scope, id);
      if (before === null) {
        throw DomainError.notFound();
      }
      if (before.version !== input.expectedVersion) {
        throw DomainError.staleVersion();
      }
      const result = await this.halls.updateCas(
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
        action: 'hall.updated',
        resourceType: 'hall',
        resourceId: id,
        outcome: 'success',
        httpStatus: 200,
        before: hallSnapshot(before),
        after: hallSnapshot(result.row),
        ip: actor.ip,
        requestId: actor.requestId,
      });
      return toHallDto(result.row);
    });
  }

  async delete(
    scope: AccessScope,
    id: string,
    query: DeleteQuery,
    actor: BaseDataWriteActor,
  ): Promise<void> {
    return this.withTenantTx(scope, async (tx) => {
      const before = await this.halls.findByIdForUpdate(scope, id);
      if (before === null) {
        throw DomainError.notFound();
      }
      if (before.version !== query.expectedVersion) {
        throw DomainError.staleVersion();
      }
      // Same transaction and the hall row is locked: a concurrent terminal
      // create cannot slip between this check and the soft delete (AT-11).
      await assertNotReferenced(this.terminalRefs, tx, scope, id);
      const result = await this.halls.softDeleteCas(scope, id, query.expectedVersion);
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
        action: 'hall.deleted',
        resourceType: 'hall',
        resourceId: id,
        outcome: 'success',
        httpStatus: 204,
        before: hallSnapshot(before),
        after: hallSnapshot(result.row),
        ip: actor.ip,
        requestId: actor.requestId,
      });
    });
  }

  // ---------- terminals (always scoped by the hall in the path) ----------

  async listTerminals(
    scope: AccessScope,
    hallId: string,
    query: TerminalListQuery,
  ): Promise<TerminalListResult> {
    return this.withTenantTx(scope, async () => {
      // A missing/deleted/other-tenant hall is the same 404 as a missing
      // terminal list — never an empty page that reveals the difference.
      await this.requireLiveHall(scope, hallId);
      const { rows, total } = await this.terminals.list(scope, hallId, query);
      return { data: rows.map(toTerminalDto), meta: paginationMeta(query, total) };
    });
  }

  async getTerminal(scope: AccessScope, hallId: string, id: string): Promise<TerminalDto> {
    return this.withTenantTx(scope, async () => {
      const row = await this.terminals.findById(scope, hallId, id);
      if (row === null) {
        throw DomainError.notFound();
      }
      return toTerminalDto(row);
    });
  }

  async createTerminal(
    scope: AccessScope,
    hallId: string,
    input: CreateTerminalInput,
    actor: BaseDataWriteActor,
  ): Promise<TerminalDto> {
    const nameKey = normalizeNameKey(input.name);
    return this.withTenantTx(scope, async () => {
      // AT-11: lock the live parent BEFORE inserting the child.
      await this.requireLiveHallForUpdate(scope, hallId);
      const row = await this.terminals.create(scope, hallId, {
        name: input.name,
        nameKey,
        isActive: input.isActive,
        displayOrder: input.displayOrder,
      });
      await this.audit.append({
        actorType: 'user',
        actorUserId: actor.userId,
        actorSessionId: actor.sessionId,
        action: 'terminal.created',
        resourceType: 'terminal',
        resourceId: row.id,
        outcome: 'success',
        httpStatus: 201,
        after: terminalSnapshot(row),
        metadata: { hallId },
        ip: actor.ip,
        requestId: actor.requestId,
      });
      return toTerminalDto(row);
    });
  }

  async updateTerminal(
    scope: AccessScope,
    hallId: string,
    id: string,
    input: UpdateTerminalInput,
    actor: BaseDataWriteActor,
  ): Promise<TerminalDto> {
    const nameKey = input.name === undefined ? undefined : normalizeNameKey(input.name);
    return this.withTenantTx(scope, async () => {
      await this.requireLiveHallForUpdate(scope, hallId);
      const before = await this.terminals.findByIdForUpdate(scope, hallId, id);
      if (before === null) {
        throw DomainError.notFound();
      }
      if (before.version !== input.expectedVersion) {
        throw DomainError.staleVersion();
      }
      const result = await this.terminals.updateCas(
        scope,
        hallId,
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
        action: 'terminal.updated',
        resourceType: 'terminal',
        resourceId: id,
        outcome: 'success',
        httpStatus: 200,
        before: terminalSnapshot(before),
        after: terminalSnapshot(result.row),
        metadata: { hallId },
        ip: actor.ip,
        requestId: actor.requestId,
      });
      return toTerminalDto(result.row);
    });
  }

  async deleteTerminal(
    scope: AccessScope,
    hallId: string,
    id: string,
    query: DeleteQuery,
    actor: BaseDataWriteActor,
  ): Promise<void> {
    return this.withTenantTx(scope, async () => {
      await this.requireLiveHallForUpdate(scope, hallId);
      const before = await this.terminals.findByIdForUpdate(scope, hallId, id);
      if (before === null) {
        throw DomainError.notFound();
      }
      if (before.version !== query.expectedVersion) {
        throw DomainError.staleVersion();
      }
      const result = await this.terminals.softDeleteCas(scope, hallId, id, query.expectedVersion);
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
        action: 'terminal.deleted',
        resourceType: 'terminal',
        resourceId: id,
        outcome: 'success',
        httpStatus: 204,
        before: terminalSnapshot(before),
        after: terminalSnapshot(result.row),
        metadata: { hallId },
        ip: actor.ip,
        requestId: actor.requestId,
      });
    });
  }

  private async requireLiveHall(scope: AccessScope, hallId: string): Promise<void> {
    if ((await this.halls.findById(scope, hallId)) === null) {
      throw DomainError.notFound();
    }
  }

  private async requireLiveHallForUpdate(scope: AccessScope, hallId: string): Promise<void> {
    if ((await this.halls.findByIdForUpdate(scope, hallId)) === null) {
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

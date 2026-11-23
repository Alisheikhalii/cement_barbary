import { Inject, Injectable } from '@nestjs/common';

import { DomainError } from '../../common/errors/domain-error.js';
import { TenantDb } from '../../db/tenant-db.js';
import { AuditWriter } from '../audit/audit-writer.js';
import { roleCodeSchema, userIdSchema, type AssignableRole } from './users.types.js';
import { UsersRepository } from './users.repository.js';

/**
 * The only caller of the SR-05 role functions (F1-06 T06, ADR-009 L5).
 *
 * Oracle rule (F1-05 debt): a nonexistent user, another tenant's user and a
 * soft-deleted user produce the SAME `DomainError.notFound()` for assign AND
 * revoke — same status, code, message and body — so neither operation reveals
 * whether a user exists. `UsersRepository.findById` is the visibility check
 * (live, same tenant, RLS-enforced).
 *
 * Visibility check, role write and audit row run in ONE transaction
 * (`TenantDb.run`; the repository calls reuse it), so a role change and its
 * `user.role.*` row commit or roll back together.
 */

export type RoleChangeActor =
  | { readonly type: 'user'; readonly userId: string; readonly sessionId: string }
  | { readonly type: 'system'; readonly tool: string };

export interface RoleChangeResult {
  readonly changed: boolean;
  readonly roles: readonly AssignableRole[];
}

function sorted(roles: readonly string[]): string[] {
  return [...roles].sort();
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

@Injectable()
export class UserRoleService {
  constructor(
    @Inject(TenantDb) private readonly tenantDb: TenantDb,
    @Inject(UsersRepository) private readonly users: UsersRepository,
    @Inject(AuditWriter) private readonly audit: AuditWriter,
  ) {}

  /** Assigns a catalog role. `changed` is false when the user already had it. */
  async assign(
    userId: string,
    roleCode: string,
    actor: RoleChangeActor,
  ): Promise<RoleChangeResult> {
    return this.change('assign', userId, roleCode, actor);
  }

  /** Revokes a catalog role. `changed` is false when the user did not have it. */
  async revoke(
    userId: string,
    roleCode: string,
    actor: RoleChangeActor,
  ): Promise<RoleChangeResult> {
    return this.change('revoke', userId, roleCode, actor);
  }

  private async change(
    operation: 'assign' | 'revoke',
    userId: string,
    roleCode: string,
    actor: RoleChangeActor,
  ): Promise<RoleChangeResult> {
    // Input shape is validated BEFORE any visibility check: an invalid id or
    // role code is 400 for every user state, so it cannot become a second
    // existence oracle (T06 review MEDIUM 1).
    if (!userIdSchema.safeParse(userId).success || !roleCodeSchema.safeParse(roleCode).success) {
      throw DomainError.badInput();
    }
    return this.tenantDb.run(async () => {
      // Lock the user row first (T06 review MEDIUM 3): `before` is read under
      // the same lock the SR-05 function takes, so two concurrent assigns
      // serialize instead of the loser reading a stale role set.
      await this.users.lockForRoleChange(userId);
      const user = await this.users.findById(userId);
      if (user === null) {
        // Identical for both operations and every invisible-user cause.
        throw DomainError.notFound();
      }
      const before = sorted(await this.users.listRoles(userId));
      if (operation === 'assign') {
        await this.users.assignRole(userId, roleCode);
      } else {
        await this.users.revokeRole(userId, roleCode);
      }
      const after = sorted(await this.users.listRoles(userId));
      const changed = !sameSet(before, after);
      if (changed) {
        await this.audit.append({
          actorType: actor.type === 'user' ? 'user' : 'system',
          actorUserId: actor.type === 'user' ? actor.userId : null,
          actorSessionId: actor.type === 'user' ? actor.sessionId : null,
          action: operation === 'assign' ? 'user.role.assigned' : 'user.role.revoked',
          resourceType: 'user',
          resourceId: userId,
          outcome: 'success',
          before: { roles: before },
          after: { roles: after },
          metadata: actor.type === 'system' ? { tool: actor.tool, roleCode } : { roleCode },
        });
      }
      return { changed, roles: after as AssignableRole[] };
    });
  }
}

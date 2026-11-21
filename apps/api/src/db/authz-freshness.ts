import { Inject, Injectable } from '@nestjs/common';

import { authSessions } from './schema/auth-sessions.js';
import { tenants } from './schema/tenants.js';
import { userRoles } from './schema/user-roles.js';
import { users } from './schema/users.js';
import { and, eq, gt, isNull } from './sql.js';
import { TenantContext } from './tenant-context.js';
import { TenantDb } from './tenant-db.js';

/**
 * Fresh authorization snapshot for a SENSITIVE action (ADR-008 Z6, CP1 SR-06).
 * One tenant-scoped read transaction returns the user and tenant status, the
 * session's liveness, and the current DB role set. The guard intersects the DB
 * roles with the token roles, so a stale token can never add or keep a grant.
 *
 * This service never returns PII and is only called for permissions whose
 * catalog flag is `sensitive`; normal requests trust the short-lived token.
 */

export interface FreshAuthzState {
  readonly userActive: boolean;
  readonly tenantActive: boolean;
  readonly sessionLive: boolean;
  readonly roles: readonly string[];
}

export interface FreshAuthzInput {
  readonly tenantId: string;
  readonly userId: string;
  readonly sessionId: string;
}

@Injectable()
export class AuthzFreshness {
  constructor(
    @Inject(TenantDb) private readonly tenantDb: TenantDb,
    @Inject(TenantContext) private readonly tenantContext: TenantContext,
  ) {}

  async read(input: FreshAuthzInput): Promise<FreshAuthzState> {
    return this.tenantContext.run({ tenantId: input.tenantId }, () =>
      this.tenantDb.run(
        async (tx) => {
          const now = new Date();
          const userRows = await tx
            .select({ status: users.status, deletedAt: users.deletedAt })
            .from(users)
            .where(and(eq(users.tenantId, input.tenantId), eq(users.id, input.userId)))
            .limit(1);
          const user = userRows[0];

          const tenantRows = await tx
            .select({ status: tenants.status, deletedAt: tenants.deletedAt })
            .from(tenants)
            .where(eq(tenants.id, input.tenantId))
            .limit(1);
          const tenant = tenantRows[0];

          const roleRows = await tx
            .select({ roleCode: userRoles.roleCode })
            .from(userRoles)
            .where(and(eq(userRoles.tenantId, input.tenantId), eq(userRoles.userId, input.userId)));

          const sessionRows = await tx
            .select({ id: authSessions.id })
            .from(authSessions)
            .where(
              and(
                eq(authSessions.tenantId, input.tenantId),
                eq(authSessions.id, input.sessionId),
                eq(authSessions.userId, input.userId),
                isNull(authSessions.revokedAt),
                gt(authSessions.expiresAt, now),
              ),
            )
            .limit(1);

          return {
            userActive: user !== undefined && user.status === 'active' && user.deletedAt === null,
            tenantActive:
              tenant !== undefined && tenant.status === 'active' && tenant.deletedAt === null,
            sessionLive: sessionRows.length > 0,
            roles: roleRows.map((row) => row.roleCode),
          };
        },
        // One consistent snapshot: the four rows cannot mix pre/post states.
        { isolationLevel: 'repeatable read' },
      ),
    );
  }
}

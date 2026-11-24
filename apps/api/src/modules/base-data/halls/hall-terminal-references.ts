import { Injectable } from '@nestjs/common';

import { DomainError } from '../../../common/errors/domain-error.js';
import { hallTerminals } from '../../../db/schema/hall-terminals.js';
import { and, eq, isNull } from '../../../db/sql.js';
import type { Tx } from '../../../db/tenant-db.js';
import { AccessScope } from '../../../security/authz/access-scope.js';
import type { ReferenceGuard } from '../reference-guard.js';

/**
 * R3 in-use guard: a hall with at least one LIVE terminal cannot be soft
 * deleted (B5). It runs inside the delete transaction after the service locks
 * the hall FOR UPDATE. Every terminal write locks that same hall row first
 * (AT-11), so a concurrent create either commits before the delete (the guard
 * then sees it and answers 409 IN_USE) or waits and sees a deleted hall (404).
 */
@Injectable()
export class HallTerminalReferences implements ReferenceGuard {
  async isReferenced(tx: Tx, scope: AccessScope, id: string): Promise<boolean> {
    if (!AccessScope.is(scope)) {
      throw DomainError.forbidden();
    }
    const rows = await tx
      .select({ id: hallTerminals.id })
      .from(hallTerminals)
      .where(
        and(
          eq(hallTerminals.tenantId, scope.tenantId),
          eq(hallTerminals.hallId, id),
          isNull(hallTerminals.deletedAt),
        ),
      )
      .limit(1);
    return rows.length > 0;
  }
}

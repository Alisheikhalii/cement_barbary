import { Injectable } from '@nestjs/common';

import { DomainError } from '../../../common/errors/domain-error.js';
import { loaderTypes } from '../../../db/schema/loader-types.js';
import { and, eq, isNull } from '../../../db/sql.js';
import type { Tx } from '../../../db/tenant-db.js';
import { AccessScope } from '../../../security/authz/access-scope.js';
import type { ReferenceGuard } from '../reference-guard.js';

/**
 * R3 in-use guard: a loader-type group with at least one LIVE loader type
 * cannot be soft deleted (B5). It runs inside the delete transaction after the
 * service locks the group FOR UPDATE. A type create/move locks that same group
 * row first (AT-11), so a concurrent create either commits before the delete
 * (the guard then sees it and answers 409 IN_USE) or waits and sees a deleted
 * group (404).
 */
@Injectable()
export class LoaderTypeGroupReferences implements ReferenceGuard {
  async isReferenced(tx: Tx, scope: AccessScope, id: string): Promise<boolean> {
    if (!AccessScope.is(scope)) {
      throw DomainError.forbidden();
    }
    const rows = await tx
      .select({ id: loaderTypes.id })
      .from(loaderTypes)
      .where(
        and(
          eq(loaderTypes.tenantId, scope.tenantId),
          eq(loaderTypes.groupId, id),
          isNull(loaderTypes.deletedAt),
        ),
      )
      .limit(1);
    return rows.length > 0;
  }
}

import { DomainError } from '../../common/errors/domain-error.js';
import type { Tx } from '../../db/tenant-db.js';
import type { AccessScope } from '../../security/authz/access-scope.js';

/**
 * R3 minimal in-use guard for a soft delete (B5).
 *
 * A service that deletes a parent row calls the guard checks that belong to it
 * inside the delete transaction, after locking the parent `FOR UPDATE`:
 *
 *   - halls: a live terminal still references the hall;
 *   - loader-type groups: a live loader type still references the group.
 *
 * Each check is a small object with one method; there is deliberately no
 * registry or plugin layer. F2/F3 add their own checks by implementing this
 * same interface and calling `assertNotReferenced` from the delete path.
 */
export interface ReferenceGuard {
  /** True when a LIVE row still references `id` inside `tx`. */
  isReferenced(tx: Tx, scope: AccessScope, id: string): Promise<boolean>;
}

/**
 * Runs one guard check in the caller's transaction. A live reference is the
 * generic 409 IN_USE: no child id, count or name ever reaches the client.
 */
export async function assertNotReferenced(
  guard: ReferenceGuard,
  tx: Tx,
  scope: AccessScope,
  id: string,
): Promise<void> {
  if (await guard.isReferenced(tx, scope, id)) {
    throw DomainError.inUse();
  }
}

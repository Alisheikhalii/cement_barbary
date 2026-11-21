import { isPermissionName, PERMISSIONS } from './permissions.js';
import type { PermissionDefinition, PermissionName, PermissionScope } from './permissions.js';
import type { Principal } from './principal.js';
import { roleHasPermission } from './role-permissions.js';

/**
 * A resource the caller wants to act on. `tenantId` is always required; the
 * other ids are present only for carrier/own scope. Passing no resource means
 * "does this principal hold this capability?" (the route guard's check);
 * repositories still filter by `AccessScope` and answer 404 for a row outside
 * it (Z8).
 */
export interface ResourceRef {
  readonly tenantId: string;
  readonly carrierId?: string;
  readonly driverUserId?: string;
}

/**
 * Pure authorization decision (ADR-008 Z5). It never reads the DB, the clock or
 * request state: the guard supplies the principal and, when needed, a resource.
 *
 * Order:
 *  1. unknown permission name → deny;
 *  2. any role grants it? (unknown roles are ignored; duplicate roles are
 *     deduped and cannot inflate the set — CP1 BF-04);
 *  3. scope resolution (tenant always; carrier needs a carrier id; own needs
 *     the principal's user id).
 */
export function can(principal: Principal, permissionName: string, resource?: ResourceRef): boolean {
  if (!isPermissionName(permissionName)) {
    return false;
  }
  return decide(
    principal,
    PERMISSIONS[permissionName],
    holdsPermission(principal.roles, permissionName),
    resource,
  );
}

/**
 * Decision core shared by `can()` and the unit fixtures. `granted` is the
 * role-map result; this function resolves only the scope. It is exported so a
 * test can force-map a carrier-scoped definition before F1-08 exists and prove
 * the same path `can()` uses fails closed without a carrier id.
 */
export function decide(
  principal: Principal,
  definition: PermissionDefinition,
  granted: boolean,
  resource?: ResourceRef,
): boolean {
  return granted && scopeAllows(principal, definition.scope, resource);
}

/**
 * Scope layer, exported so the tests can force-map a fixture permission that
 * the production catalog does not contain yet (for example a carrier-scoped
 * permission before F1-08) and prove it fails closed without a carrier id.
 */
export function scopeAllows(
  principal: Principal,
  scope: PermissionScope,
  resource?: ResourceRef,
): boolean {
  if (principal.tenantId.length === 0) {
    return false;
  }
  if (resource !== undefined && resource.tenantId !== principal.tenantId) {
    return false;
  }
  switch (scope) {
    case 'tenant':
      return true;
    case 'carrier':
      // F1-05: no principal has a carrier id (Z9). Even a mistakenly mapped
      // carrier permission cannot grant until F1-08 supplies one.
      if (principal.carrierId === undefined || principal.carrierId.length === 0) {
        return false;
      }
      return resource === undefined || resource.carrierId === principal.carrierId;
    case 'own':
      return (
        principal.userId.length > 0 &&
        (resource === undefined || resource.driverUserId === principal.userId)
      );
    default:
      return false;
  }
}

function holdsPermission(roles: readonly string[], permissionName: PermissionName): boolean {
  // A Set documents the intent: repeated role codes are one grant, not more.
  for (const role of new Set(roles)) {
    if (roleHasPermission(role, permissionName)) {
      return true;
    }
  }
  return false;
}

import { DomainError } from '../../common/errors/domain-error.js';
import { getPermission, type PermissionName, type PermissionScope } from './permissions.js';
import { isVerifiedPrincipal, type Principal } from './principal.js';

/**
 * The server-side resource scope a request may touch (ADR-008 Z8, F1-05 T05).
 *
 * A scope is BRANDED: the constructor is private, every instance is tracked in
 * a module-private WeakSet, and both factories require a principal produced by
 * `createVerifiedPrincipal()` (the guard's verified-claims path). A plain
 * `createPrincipal()` built from a body or route param, a JSON object or an
 * object literal can therefore never mint a scope. `AccessScope.is()` refuses
 * look-alike objects, so a forged scope can never widen a repository query.
 *
 * Scope kinds:
 *  - tenant: every row inside the caller's tenant;
 *  - carrier: only rows whose carrier id matches the principal's carrier id
 *    (fails closed while F1-05 has no carrier claim; F1-08 supplies it);
 *  - own: only rows owned by the principal's user id.
 *
 * Repositories combine the scope with their tenant/RLS filter and answer the
 * SAME generic 404 for an absent row and a row outside the scope (Z8) — the
 * caller must not be able to tell "exists but not yours" from "does not exist".
 */
export class AccessScope {
  static readonly #issued = new WeakSet<AccessScope>();

  /** Nominal brand: an object literal is never assignable to this class. */
  readonly #brand = true;

  private constructor(
    readonly tenantId: string,
    readonly carrierId: string | null,
    readonly driverUserId: string | null,
  ) {
    AccessScope.#issued.add(this);
    Object.freeze(this);
  }

  /** Builds the scope a permission requires from a verified principal. */
  static forPermission(principal: Principal, permission: PermissionName): AccessScope {
    const definition = getPermission(permission);
    if (definition === undefined) {
      throw DomainError.forbidden();
    }
    return AccessScope.fromPrincipal(principal, definition.scope);
  }

  /** Builds one scope kind. Any missing required id fails closed with a 403. */
  static fromPrincipal(principal: Principal, required: PermissionScope): AccessScope {
    // Provenance gate: only the guard's verified token claims can be scoped.
    if (!isVerifiedPrincipal(principal) || principal.tenantId.length === 0) {
      throw DomainError.forbidden();
    }
    switch (required) {
      case 'tenant':
        return new AccessScope(principal.tenantId, null, null);
      case 'carrier': {
        const carrierId = principal.carrierId;
        // F1-05: no principal carries a carrier id yet. A carrier-scoped
        // permission therefore cannot produce a usable scope until F1-08.
        if (carrierId === undefined || carrierId.length === 0) {
          throw DomainError.forbidden();
        }
        return new AccessScope(principal.tenantId, carrierId, null);
      }
      case 'own':
        if (principal.userId.length === 0) {
          throw DomainError.forbidden();
        }
        return new AccessScope(principal.tenantId, null, principal.userId);
      default:
        throw DomainError.forbidden();
    }
  }

  /** True only for a scope created by this module. */
  static is(value: unknown): value is AccessScope {
    return (
      typeof value === 'object' &&
      value !== null &&
      #brand in value &&
      AccessScope.#issued.has(value as AccessScope)
    );
  }
}

/** The minimal row shape an access-scope check needs. */
export interface ScopedRow {
  readonly tenantId: string;
  readonly carrierId?: string | null;
  readonly ownerUserId?: string | null;
}

/** True when the row is inside the scope. A forged scope matches nothing. */
export function rowInScope(scope: AccessScope, row: ScopedRow): boolean {
  if (!AccessScope.is(scope)) {
    return false;
  }
  if (row.tenantId !== scope.tenantId) {
    return false;
  }
  if (scope.carrierId !== null && row.carrierId !== scope.carrierId) {
    return false;
  }
  if (scope.driverUserId !== null && row.ownerUserId !== scope.driverUserId) {
    return false;
  }
  return true;
}

/**
 * Repository guard: returns the row when it is in scope; otherwise throws the
 * single generic 404. An absent row and an out-of-scope row are indistinguishable
 * to the client (same status, code, message and body).
 */
export function assertInScope<T extends ScopedRow>(
  scope: AccessScope,
  row: T | null | undefined,
): T {
  if (row === null || row === undefined || !rowInScope(scope, row)) {
    throw DomainError.notFound();
  }
  return row;
}

/** The authorization context the guard attaches to an authorized request. */
export interface AuthzContext {
  readonly principal: Principal;
  readonly scope: AccessScope;
}

/**
 * Reads the guard-attached context. A missing/broken context, a forged scope,
 * an unverified principal or a principal/scope tenant mismatch fails closed
 * with the generic 403; controllers never rebuild a scope from request data.
 */
export function readAuthzContext(request: unknown): AuthzContext {
  const context = (request as { authz?: unknown } | null | undefined)?.authz;
  if (typeof context !== 'object' || context === null) {
    throw DomainError.forbidden();
  }
  const principal = (context as { principal?: unknown }).principal;
  const scope = (context as { scope?: unknown }).scope;
  if (
    !AccessScope.is(scope) ||
    !isVerifiedPrincipal(principal) ||
    scope.tenantId !== principal.tenantId
  ) {
    throw DomainError.forbidden();
  }
  return { principal, scope };
}

/**
 * The authenticated principal the authorization layer reasons about (ADR-008
 * Z4/Z5/Z8). It is derived from a verified access token by the guard; nothing
 * here reads HTTP or the database.
 *
 * `roles` stays `readonly string[]` on purpose: a token may carry a role code
 * that is unknown or removed, and `can()` must ignore it rather than fail open.
 * `carrierId` is absent until F1-08 adds `users.carrier_id` / a `cid` claim.
 */

export interface Principal {
  readonly userId: string;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly roles: readonly string[];
  readonly carrierId?: string;
}

export interface PrincipalInput {
  readonly userId: string;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly roles: readonly string[];
  readonly carrierId?: string;
}

/**
 * Copies the role list so a caller cannot mutate a principal after the guard
 * built it. With `exactOptionalPropertyTypes`, `carrierId` is omitted rather
 * than set to undefined when absent.
 */
export function createPrincipal(input: PrincipalInput): Principal {
  return Object.freeze({
    userId: input.userId,
    tenantId: input.tenantId,
    sessionId: input.sessionId,
    roles: Object.freeze([...input.roles]),
    ...(input.carrierId === undefined ? {} : { carrierId: input.carrierId }),
  });
}

/**
 * Principals created from VERIFIED access-token claims. Only the authorization
 * guard uses this factory; `AccessScope` refuses a plain `createPrincipal()`
 * result, so a future controller cannot mint a usable scope from request data.
 * This WeakSet is the runtime half of the nominal `Principal` boundary.
 */
const verifiedPrincipals = new WeakSet<Principal>();

/** Internal to the authz layer: marks a principal as token-verified. */
export function createVerifiedPrincipal(input: PrincipalInput): Principal {
  const principal = createPrincipal(input);
  verifiedPrincipals.add(principal);
  return principal;
}

/** True only for a principal produced by `createVerifiedPrincipal`. */
export function isVerifiedPrincipal(value: unknown): value is Principal {
  return typeof value === 'object' && value !== null && verifiedPrincipals.has(value as Principal);
}

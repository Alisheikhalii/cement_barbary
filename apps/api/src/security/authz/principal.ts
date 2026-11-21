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

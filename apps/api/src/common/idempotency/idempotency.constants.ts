/**
 * Idempotency constants shared by the decorator, the route scan and the
 * interceptor (ADR-010 L9/L10/L11). Kept in a leaf module so the decorator and
 * the interceptor can import them without a cycle.
 */

/** Handler metadata: this route requires an `Idempotency-Key` and stored replay. */
export const IDEMPOTENT_KEY = 'authz:idempotent';

/** Methods whose routes must carry `@Idempotent()` under `@RequirePermission`. */
export const IDEMPOTENT_METHODS = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE'] as const);

/** Client key charset and length (ADR-010 L9): opaque, no separators. */
export const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

/** `METHOD + " " + route template`, e.g. `POST /api/v1/base/destinations`. */
export const IDEMPOTENCY_ROUTE_PATTERN = /^[A-Z]{3,7} \/[A-Za-z0-9_:/{}.@-]{1,150}$/;

/** Plaintext response cap; the encrypted blob adds only the 30-byte PII header. */
export const MAX_STORED_RESPONSE_BYTES = 65_536;

/** The AAD column component; the row id is appended by `buildAad`. */
export const RESPONSE_ENC_COLUMN = 'idempotency_keys.response_enc';

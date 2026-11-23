import { createHash } from 'node:crypto';

/**
 * Request fingerprint for idempotency (ADR-010 L9, owner CP4 change 4).
 *
 * It covers exactly the three request-payload surfaces — route params, query
 * and body. It deliberately does NOT cover:
 *  - the route: `METHOD + route template` is part of the scope key, so the
 *    same key on another route is an independent row;
 *  - the principal: tenant + user are part of the scope key;
 *  - headers (including `Idempotency-Key` itself and `Authorization`), because
 *    headers carry transports/credentials, not request intent, and replaying
 *    with a rotated token must still match.
 *
 * Canonical form: recursively sorted object keys, array order kept, `undefined`
 * object members omitted (JSON.stringify semantics), so two equivalent JSON
 * documents hash identically. SHA-256 → 32 bytes, matching the DB CHECK.
 */

export interface FingerprintInput {
  readonly params: unknown;
  readonly query: unknown;
  readonly body: unknown;
}

export function fingerprintOf(input: FingerprintInput): Buffer {
  const canonical = JSON.stringify(
    canonicalize({
      params: input.params ?? {},
      query: input.query ?? {},
      body: input.body ?? null,
    }),
  );
  if (typeof canonical !== 'string') {
    // Only impossible for a top-level undefined/function/symbol.
    throw new Error('IDEMPOTENCY_FINGERPRINT_FAILED');
  }
  return createHash('sha256').update(canonical, 'utf8').digest();
}

function canonicalize(value: unknown, seen: Set<object> = new Set<object>()): unknown {
  if (value === null) {
    return null;
  }
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return value;
    case 'number':
      // Parsed JSON cannot carry NaN/Infinity; normalise defensively.
      return Number.isFinite(value) ? value : null;
    case 'object':
      break;
    default:
      // Functions/symbols/bigints never come from a JSON body; treat as absent.
      return undefined;
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item, seen) ?? null);
  }
  if (seen.has(value)) {
    // A cycle cannot come from JSON.parse; fail closed as a stable marker.
    return null;
  }
  seen.add(value);
  const source = value as Record<string, unknown>;
  // Null prototype: a JSON body can carry an own `__proto__` key (JSON.parse
  // creates it), and assigning it on a normal object would invoke the
  // prototype setter — the key would vanish from the canonical form and two
  // different bodies would collide (review MEDIUM 5).
  const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of Object.keys(source).sort()) {
    const item = canonicalize(source[key], seen);
    if (item !== undefined) {
      out[key] = item;
    }
  }
  return out;
}

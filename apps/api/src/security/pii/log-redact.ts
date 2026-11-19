/**
 * Log redaction for personal data (ADR-006 U11): pino's path-based redact only
 * covers fixed paths, so PII fields are hidden structurally instead — any
 * object key that mentions a phone / mobile / national id, or carries a
 * `*_enc` / `*_hash` (or camelCase `…Enc` / `…Hash`) suffix, is replaced at
 * any depth. Wired as pino's `formatters.log` hook in app.module.ts.
 *
 * This is key-based redaction: it cannot see PII inside free-text values.
 * Never put a phone or national ID into a URL, an error message or a log
 * message string (see docs/security/pii.md).
 */

export const PII_REDACTED = '[Redacted]';
export const PII_CIRCULAR = '[Circular]';

function isPiiKey(key: string): boolean {
  const k = key.toLowerCase();
  return (
    k.includes('phone') || // phone, phoneNumber, phone_number, driverPhone, …
    k.includes('mobile') ||
    k.includes('msisdn') ||
    k.includes('national') || // nationalId, national_id, nationalCode, …
    k.endsWith('_enc') ||
    k.endsWith('_hash') ||
    k.endsWith('enc') || // camelCase …Enc
    k.endsWith('hash') // camelCase …Hash
  );
}

/**
 * Returns a copy with every PII-keyed value replaced by '[Redacted]', at any
 * depth. Only the current ancestor path is tracked (added on entry, removed on
 * exit): a merely shared reference — `{ a: user, b: user }` — is redacted
 * again at every visit, while a true cycle is cut and rendered '[Circular]'.
 * A global "seen" set would be wrong here: the second visit would return the
 * ORIGINAL object and leak its raw PII.
 */
export function redactPii<T>(value: T, ancestors = new Set<object>()): T {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (value instanceof Date || Buffer.isBuffer(value)) {
    return value;
  }
  if (ancestors.has(value)) {
    return PII_CIRCULAR as T;
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => redactPii(item, ancestors)) as T;
    }
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out[key] = isPiiKey(key) ? PII_REDACTED : redactPii(item, ancestors);
    }
    return out as T;
  } finally {
    ancestors.delete(value);
  }
}

/** pino `formatters.log` hook. */
export function redactPiiLogObject(obj: Record<string, unknown>): Record<string, unknown> {
  return redactPii(obj);
}

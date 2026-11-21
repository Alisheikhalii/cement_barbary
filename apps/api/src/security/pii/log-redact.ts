/**
 * Log redaction for personal data (ADR-006 U11) and auth secrets (ADR-007
 * A14): pino's path-based redact only covers fixed paths, so sensitive fields
 * are hidden structurally instead — any object key that mentions a phone /
 * mobile / national id, carries a `*_enc` / `*_hash` (or camelCase `…Enc` /
 * `…Hash`) suffix, or names a password / PIN / token / secret / OTP code /
 * authorization / cookie / credential is replaced at any depth. Wired as
 * pino's `formatters.log` hook in app.module.ts.
 *
 * This is key-based redaction: it cannot see secrets inside free-text values.
 * Never put a phone, national ID, password, token or OTP into a URL, an error
 * message or a log message string (docs/security/pii.md, docs/security/authn.md).
 *
 * Any `*code` key (exact `code`, `sms_code`, `smsCode`, `verificationCode`, …)
 * is redacted for future OTP flows — which would also hide DomainError.code
 * inside logged `err` objects, so the exception filter logs the error code
 * separately under `errorCode`, and `errorCode`/`statusCode` are allowlisted
 * below to stay observable.
 */

export const PII_REDACTED = '[Redacted]';
export const PII_CIRCULAR = '[Circular]';

/**
 * Operational (non-secret) `*code` keys that must stay visible in logs —
 * `tenantCode` is part of the public login identifier and is needed for
 * spray-detection observability (T06).
 */
const CODE_KEY_ALLOWLIST = new Set([
  'errorcode',
  'statuscode',
  'tenantcode',
  // Guard denials log this stable reason CODE (not the free-text reason).
  'reasoncode',
  'reason_code',
  'reason-code',
  'x-reason-code',
  'x_reason_code',
]);

function isPiiKey(key: string): boolean {
  const k = key.toLowerCase();
  // Operational code keys win over the generic `reason`/`code` rules.
  if (CODE_KEY_ALLOWLIST.has(k)) {
    return false;
  }
  return (
    // PII (ADR-006 U11)
    k.includes('phone') || // phone, phoneNumber, phone_number, driverPhone, …
    k.includes('mobile') ||
    k.includes('msisdn') ||
    k.includes('national') || // nationalId, national_id, nationalCode, …
    k.endsWith('_enc') ||
    k.endsWith('_hash') ||
    k.endsWith('enc') || // camelCase …Enc
    k.endsWith('hash') || // camelCase …Hash
    // Auth secrets (ADR-007 A14)
    k.includes('password') ||
    k.includes('passphrase') ||
    k === 'pin' ||
    k.endsWith('_pin') ||
    k.endsWith('pin') || // driverPin, loginPin, …
    k.startsWith('pin') || // pinCode, pin_code, … (over-redaction is safe)
    k.includes('token') || // accessToken, refreshToken, idToken, …
    k.includes('secret') ||
    k.includes('apikey') || // apiKey, apikey, …
    k.includes('api_key') ||
    k.includes('api-key') || // x-api-key, …
    k.includes('otp') || // otp, otpCode, otp_code, …
    (k.endsWith('code') && !CODE_KEY_ALLOWLIST.has(k)) || // code, smsCode, verification_code, …
    k.includes('authorization') ||
    k.includes('cookie') ||
    k.includes('credential') ||
    // Free-text sensitive-action reason (ADR-008 Z10): never pino-logged.
    // Any key containing `reason` is covered (`denialReason`, `reasonText`,
    // `reason_text`, `x-reason`, `x-reason-text`); operation code variants are
    // allowlisted above. A reason logged as a bare string or under an unrelated
    // key (`detail`, `messages: [reason]`) cannot be detected structurally —
    // the contract forbids logging it that way.
    k.includes('reason')
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

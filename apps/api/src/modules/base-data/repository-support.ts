import { DomainError } from '../../common/errors/domain-error.js';
import { AccessScope } from '../../security/authz/access-scope.js';

/**
 * Shared repository plumbing for every base-data resource (T05 review).
 *
 * `scopeTenant` is the only accepted scope shape: a forged brand, a carrier
 * scope or an own scope can never act on tenant-wide base data. `runGuarded`
 * translates the SQLSTATEs that are client-caused or retryable and turns every
 * other PG failure into a generic 500 — the raw drizzle/PG error embeds SQL
 * text and bound values, which must never reach a client.
 */

/** Client-caused text failures plus transient DB contention. */
const PG_TRANSLATIONS: Readonly<Record<string, () => DomainError>> = Object.freeze({
  // PostgreSQL cannot store NUL/lone surrogates (backstop behind the schemas).
  '22021': () => DomainError.badInput(),
  '22P05': () => DomainError.badInput(),
  // Row/index lock wait or deadlock under concurrent operators: retryable.
  '55P03': () => DomainError.serviceUnavailable(),
  '40P01': () => DomainError.serviceUnavailable(),
});

export function scopeTenant(scope: AccessScope): string {
  if (!AccessScope.is(scope) || scope.carrierId !== null || scope.driverUserId !== null) {
    throw DomainError.forbidden();
  }
  return scope.tenantId;
}

export async function runGuarded<T>(
  work: () => Promise<T>,
  translate: Record<string, () => DomainError> = {},
): Promise<T> {
  try {
    return await work();
  } catch (error) {
    if (error instanceof DomainError) {
      throw error;
    }
    const code = pgCode(error);
    if (code === undefined) {
      throw error;
    }
    const mapped = translate[code] ?? PG_TRANSLATIONS[code];
    if (mapped) {
      throw mapped();
    }
    throw DomainError.internal({ pgCode: code });
  }
}

/** Walks drizzle's "Failed query" wrapper to the original 5-char SQLSTATE. */
export function pgCode(error: unknown): string | undefined {
  let current: unknown = error;
  for (let i = 0; i < 5 && current !== null && current !== undefined; i += 1) {
    const code = (current as { code?: unknown }).code;
    if (typeof code === 'string' && code.length === 5) {
      return code;
    }
    current = (current as { cause?: unknown }).cause;
  }
  return undefined;
}

import { normalizePhone } from '../../security/pii/normalize.js';
import { USERNAME_PATTERN } from '../users/users.types.js';

/**
 * Classifies a login identifier (ADR-007 A4) WITHOUT touching the database:
 * a staff identifier contains `@` (`username@tenant-code`), everything else is
 * a driver phone. The classification is what builds the rate-limit identity,
 * so an unknown or malformed identifier still consumes its own bucket.
 */

/** Same shape as the tenants_code_format CHECK. */
export const TENANT_CODE_PATTERN = /^[a-z0-9-]{2,32}$/;

export type ParsedLoginIdentifier =
  | {
      readonly kind: 'staff';
      readonly username: string;
      readonly tenantCode: string;
      readonly rateLimitIdentity: string;
    }
  | { readonly kind: 'driver'; readonly phone: string; readonly rateLimitIdentity: string }
  | { readonly kind: 'invalid'; readonly rateLimitIdentity: string };

export function parseLoginIdentifier(raw: string): ParsedLoginIdentifier {
  const trimmed = raw.trim();
  if (trimmed.includes('@')) {
    const at = trimmed.lastIndexOf('@');
    const username = trimmed.slice(0, at);
    const tenantCode = trimmed.slice(at + 1);
    if (USERNAME_PATTERN.test(username) && TENANT_CODE_PATTERN.test(tenantCode)) {
      return {
        kind: 'staff',
        username,
        tenantCode,
        rateLimitIdentity: `staff:${tenantCode}:${username}`,
      };
    }
    return { kind: 'invalid', rateLimitIdentity: `invalid:${trimmed}` };
  }
  try {
    return {
      kind: 'driver',
      phone: trimmed,
      rateLimitIdentity: `driver:${normalizePhone(trimmed)}`,
    };
  } catch {
    return { kind: 'invalid', rateLimitIdentity: `invalid:${trimmed}` };
  }
}

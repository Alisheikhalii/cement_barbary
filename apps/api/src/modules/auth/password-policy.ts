import { DomainError } from '../../common/errors/domain-error.js';
import type { AssignableRole } from '../users/users.types.js';

/**
 * Password policy (ADR-007 A20, owner Q5): split by account type.
 *  - staff  → 12–128 characters, any type;
 *  - driver → numeric PIN of 8–20 digits + common-PIN blocklist;
 *  - never equal to the login identifier;
 *  - dual-role accounts follow the staff rule.
 * Nothing here ever echoes the password back — failure reasons are stable
 * codes, and the HTTP message stays generic (A14).
 */

export const STAFF_PASSWORD_MIN = 12;
export const STAFF_PASSWORD_MAX = 128;
export const DRIVER_PIN_MIN = 8;
export const DRIVER_PIN_MAX = 20;

export type PasswordKind = 'staff' | 'driver-pin';

/** A20: an account with any non-DRIVER role follows the staff rule. */
export function passwordKindForRoles(roles: readonly AssignableRole[]): PasswordKind {
  return roles.some((role) => role !== 'DRIVER') ? 'staff' : 'driver-pin';
}

/** All-same-digit PINs, lengths 8–12 (longer ones are caught by isAllSameDigit). */
function repeatedDigitPins(): string[] {
  const pins: string[] = [];
  for (let length = 8; length <= 12; length += 1) {
    for (let digit = 0; digit <= 9; digit += 1) {
      pins.push(String(digit).repeat(length));
    }
  }
  return pins;
}

/** Well-known weak PINs beyond the generated repeats. */
const COMMON_PIN_LITERALS: readonly string[] = [
  // ascending / descending runs, 8–12 digits (11+ wrap around the digit cycle)
  '01234567',
  '12345678',
  '23456789',
  '012345678',
  '123456789',
  '0123456789',
  '01234567890',
  '012345678901',
  '98765432',
  '87654321',
  '76543210',
  '987654321',
  '876543210',
  '9876543210',
  '98765432109',
  '987654321098',
  // repeated pairs and keypad patterns
  '11223344',
  '12121212',
  '12341234',
  '11112222',
  '00001111',
  '12344321',
  '13579246',
  '24681357',
  '10203040',
  '13131313',
  '10101010',
  '12312312',
  '11122233',
  '12131415',
  '01010101',
  '00112233',
  '22334455',
  '66778899',
  '99887766',
  '55443322',
  '01230123',
  '12343210',
  '13571357',
  '14725836',
  // year- and date-flavoured
  '13800101',
  '13900101',
  '14000101',
  '19700101',
  '19800101',
  '19900101',
  '20000101',
  '20100101',
];

/** A20's common-PIN blocklist (~90 entries). Structural rules below back it up. */
export const COMMON_PIN_BLOCKLIST: ReadonlySet<string> = new Set([
  ...repeatedDigitPins(),
  ...COMMON_PIN_LITERALS,
]);

function isAllSameDigit(pin: string): boolean {
  return pin.length > 0 && pin.split('').every((ch) => ch === pin[0]);
}

/**
 * Ascending or descending over the whole PIN, wrapping around the digit cycle
 * (mod 10): catches 0123…, …3210 and cyclic runs like 1234567890 / 8901234.
 */
function isSequentialRun(pin: string): boolean {
  let ascending = true;
  let descending = true;
  for (let i = 1; i < pin.length; i += 1) {
    const prev = pin.charCodeAt(i - 1) - 48;
    const current = pin.charCodeAt(i) - 48;
    if (current !== (prev + 1) % 10) ascending = false;
    if (current !== (prev + 9) % 10) descending = false;
  }
  return pin.length > 1 && (ascending || descending);
}

export type PasswordPolicyFailure =
  'too_short' | 'too_long' | 'pin_not_numeric' | 'pin_blocked' | 'equals_identifier';

/**
 * Returns null when the password satisfies the policy, else a stable failure
 * code. Pure: no I/O, no logging, and the password never leaves this function.
 */
export function checkPasswordPolicy(
  kind: PasswordKind,
  password: string,
  identifier: string,
): PasswordPolicyFailure | null {
  if (kind === 'staff') {
    // "Any type" (A20) still excludes an all-whitespace password.
    if (password.length < STAFF_PASSWORD_MIN || password.trim().length === 0) return 'too_short';
    if (password.length > STAFF_PASSWORD_MAX) return 'too_long';
    if (password.trim().toLowerCase() === identifier.trim().toLowerCase()) {
      return 'equals_identifier';
    }
    return null;
  }
  // driver PIN
  if (!/^\d+$/.test(password)) return 'pin_not_numeric';
  if (password.length < DRIVER_PIN_MIN) return 'too_short';
  if (password.length > DRIVER_PIN_MAX) return 'too_long';
  if (password === identifier.trim()) return 'equals_identifier';
  if (COMMON_PIN_BLOCKLIST.has(password) || isAllSameDigit(password) || isSequentialRun(password)) {
    return 'pin_blocked';
  }
  return null;
}

/**
 * Throws DomainError.badInput on a policy violation. The `reason` code goes to
 * `details` (client-safe, 4xx); the password itself never appears in the
 * message, details or logs (A14).
 */
export function assertPasswordPolicy(
  kind: PasswordKind,
  password: string,
  identifier: string,
): void {
  const failure = checkPasswordPolicy(kind, password, identifier);
  if (failure !== null) {
    throw DomainError.badInput({ reason: failure });
  }
}

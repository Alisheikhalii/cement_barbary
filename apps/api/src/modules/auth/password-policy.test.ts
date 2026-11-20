import { describe, expect, it } from 'vitest';

import { DomainError } from '../../common/errors/domain-error.js';
import {
  assertPasswordPolicy,
  checkPasswordPolicy,
  COMMON_PIN_BLOCKLIST,
  DRIVER_PIN_MAX,
  DRIVER_PIN_MIN,
  passwordKindForRoles,
  STAFF_PASSWORD_MAX,
  STAFF_PASSWORD_MIN,
} from './password-policy.js';

const OPERATOR = 'ali.operator@dev-factory';
const DRIVER_PHONE = '09120000001'; // gitleaks-allowlisted synthetic number

describe('passwordKindForRoles (A20: dual-role follows staff)', () => {
  it('maps DRIVER-only to the PIN rule and anything mixed to staff', () => {
    expect(passwordKindForRoles(['DRIVER'])).toBe('driver-pin');
    expect(passwordKindForRoles(['FACTORY_OPERATOR'])).toBe('staff');
    expect(passwordKindForRoles(['CARRIER_ADMIN'])).toBe('staff');
    expect(passwordKindForRoles(['DRIVER', 'CARRIER_ADMIN'])).toBe('staff');
  });
});

describe('staff password policy (12–128 chars)', () => {
  it('enforces the bounds exactly', () => {
    expect(STAFF_PASSWORD_MIN).toBe(12);
    expect(STAFF_PASSWORD_MAX).toBe(128);
    expect(checkPasswordPolicy('staff', 'a'.repeat(11), OPERATOR)).toBe('too_short');
    expect(checkPasswordPolicy('staff', 'a'.repeat(12), OPERATOR)).toBeNull();
    expect(checkPasswordPolicy('staff', 'a'.repeat(128), OPERATOR)).toBeNull();
    expect(checkPasswordPolicy('staff', 'a'.repeat(129), OPERATOR)).toBe('too_long');
  });

  it('accepts a long passphrase', () => {
    const passphrase = 'correct horse battery staple with some more words 2026';
    expect(checkPasswordPolicy('staff', passphrase, OPERATOR)).toBeNull();
  });

  it('rejects an all-whitespace password even at valid length (review hardening)', () => {
    expect(checkPasswordPolicy('staff', ' '.repeat(12), OPERATOR)).toBe('too_short');
  });

  it('rejects the identifier as the password, case- and whitespace-insensitively', () => {
    expect(checkPasswordPolicy('staff', OPERATOR, OPERATOR)).toBe('equals_identifier');
    expect(checkPasswordPolicy('staff', `  ${OPERATOR.toUpperCase()} `, OPERATOR)).toBe(
      'equals_identifier',
    );
  });
});

describe('driver PIN policy (8–20 digits + blocklist)', () => {
  it('enforces the bounds and numeric-only', () => {
    expect(DRIVER_PIN_MIN).toBe(8);
    expect(DRIVER_PIN_MAX).toBe(20);
    expect(checkPasswordPolicy('driver-pin', '1234567', DRIVER_PHONE)).toBe('too_short');
    expect(checkPasswordPolicy('driver-pin', '9'.repeat(21), DRIVER_PHONE)).toBe('too_long');
    expect(checkPasswordPolicy('driver-pin', '12ab5678', DRIVER_PHONE)).toBe('pin_not_numeric');
    expect(checkPasswordPolicy('driver-pin', '52849173', DRIVER_PHONE)).toBeNull();
  });

  it('rejects blocklisted common PINs', () => {
    expect(checkPasswordPolicy('driver-pin', '12345678', DRIVER_PHONE)).toBe('pin_blocked');
    expect(checkPasswordPolicy('driver-pin', '11223344', DRIVER_PHONE)).toBe('pin_blocked');
    expect(COMMON_PIN_BLOCKLIST.size).toBeGreaterThanOrEqual(90);
  });

  it('rejects structural patterns beyond the blocklist', () => {
    // 15/20 digits — longer than any blocklist entry, caught by the rules.
    expect(checkPasswordPolicy('driver-pin', '7'.repeat(15), DRIVER_PHONE)).toBe('pin_blocked');
    expect(checkPasswordPolicy('driver-pin', '1'.repeat(20), DRIVER_PHONE)).toBe('pin_blocked');
  });

  it('rejects long digit runs via the blocklist (they wrap, so the strict-run rule cannot)', () => {
    expect(checkPasswordPolicy('driver-pin', '012345678901', DRIVER_PHONE)).toBe('pin_blocked');
    expect(checkPasswordPolicy('driver-pin', '987654321098', DRIVER_PHONE)).toBe('pin_blocked');
  });

  it('rejects a PIN equal to the login phone', () => {
    expect(checkPasswordPolicy('driver-pin', DRIVER_PHONE, DRIVER_PHONE)).toBe('equals_identifier');
  });
});

describe('assertPasswordPolicy (A14: never echoes the password)', () => {
  it('throws BAD_INPUT with a stable reason and no password echo', () => {
    const secret = 'a'.repeat(11);
    let error: DomainError | undefined;
    try {
      assertPasswordPolicy('staff', secret, OPERATOR);
    } catch (e) {
      error = e as DomainError;
    }
    expect(error).toBeInstanceOf(DomainError);
    expect(error?.code).toBe('BAD_INPUT');
    expect(error?.statusCode).toBe(400);
    expect(error?.details).toEqual({ reason: 'too_short' });
    expect(JSON.stringify({ message: error?.message, details: error?.details })).not.toContain(
      secret,
    );
  });

  it('passes valid input without throwing', () => {
    expect(() => assertPasswordPolicy('staff', 'a'.repeat(12), OPERATOR)).not.toThrow();
    expect(() => assertPasswordPolicy('driver-pin', '52849173', DRIVER_PHONE)).not.toThrow();
  });
});

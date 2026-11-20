import { describe, expect, it } from 'vitest';

import { DomainError } from '../../src/common/errors/domain-error.js';
import {
  COMMON_PIN_BLOCKLIST,
  assertPasswordPolicy,
  checkPasswordPolicy,
  passwordKindForRoles,
  type PasswordKind,
  type PasswordPolicyFailure,
} from '../../src/modules/auth/password-policy.js';
import type { AssignableRole } from '../../src/modules/users/users.types.js';

/**
 * ATTACK tests for the A20 password policy (F1-04 T02). Focus: off-by-one
 * boundaries, unicode digit lookalikes, identifier-equality tricks, structural
 * PIN patterns, and the no-plaintext guarantee of the thrown DomainError
 * (A14). All functions under test are pure — no I/O.
 */

const PHONE = '09120000002'; // gitleaks-allowlisted synthetic number

describe('staff passwords — length boundaries', () => {
  const identifier = 'someone@t01';

  it.each([
    ['empty', '', 'too_short'],
    ['11 chars (min - 1)', 'a'.repeat(11), 'too_short'],
    ['129 chars (max + 1)', 'a'.repeat(129), 'too_long'],
    ['300 chars', 'a'.repeat(300), 'too_long'],
  ] as const)('rejects %s', (_label, password, expected) => {
    expect(checkPasswordPolicy('staff', password, identifier)).toBe(expected);
  });

  it.each([
    ['12 chars (min)', 'b'.repeat(12)],
    ['128 chars (max)', 'b'.repeat(128)],
  ] as const)('accepts %s', (_label, password) => {
    expect(checkPasswordPolicy('staff', password, identifier)).toBeNull();
  });
});

describe('staff passwords — identifier-equality tricks', () => {
  const identifier = 'AdminUser@Acme1';

  it.each([
    ['exact match', 'AdminUser@Acme1'],
    ['different case', 'adminuser@acme1'],
    ['shouting case', 'ADMINUSER@ACME1'],
    ['padded with whitespace', '  AdminUser@Acme1  '],
    ['case + whitespace combined', ' ADMINUSER@ACME1 '],
  ])('rejects a password equal to the identifier (%s)', (_label, password) => {
    expect(checkPasswordPolicy('staff', password, identifier)).toBe('equals_identifier');
  });

  it('accepts a password that merely contains the identifier', () => {
    expect(checkPasswordPolicy('staff', `xx${identifier}xx`, identifier)).toBeNull();
  });

  it('accepts when only interior whitespace differs (a genuinely different string)', () => {
    expect(checkPasswordPolicy('staff', 'Admin User@Acme1', identifier)).toBeNull();
  });

  it('reports too_short (not equals_identifier) for a short password equal to the identifier', () => {
    // Documents check order: length is judged before identifier equality.
    expect(checkPasswordPolicy('staff', 'Ab!23', 'ab!23')).toBe('too_short');
  });
});

describe('driver PINs — numeric-only (unicode lookalikes must not slip through)', () => {
  it.each([
    ['ASCII letter mixed in', '1234567a'],
    ['fullwidth digits', '１２３４５６７８'],
    ['Persian digits', '۱۲۳۴۵۶۷۸'],
    ['Arabic-Indic digits', '١٢٣٤٥٦٧٨'],
    ['interior space', '1234 5678'],
    ['padded with spaces', ' 12345678 '],
    ['empty string', ''],
    ['decimal point', '123456.8'],
    ['scientific notation', '12e6'],
  ])('rejects %s as pin_not_numeric', (_label, pin) => {
    expect(checkPasswordPolicy('driver-pin', pin, PHONE)).toBe('pin_not_numeric');
  });
});

describe('driver PINs — length boundaries', () => {
  it.each([
    ['7 digits (min - 1)', '5813047', 'too_short'],
    ['21 digits (max + 1)', '582047163928475610394', 'too_long'],
  ] as const)('rejects %s', (_label, pin, expected) => {
    expect(checkPasswordPolicy('driver-pin', pin, PHONE)).toBe(expected);
  });

  it.each([
    ['8 digits (min)', '58130472'],
    ['20 digits (max)', '58204716392847561039'],
  ] as const)('accepts a strong %s', (_label, pin) => {
    expect(checkPasswordPolicy('driver-pin', pin, PHONE)).toBeNull();
  });
});

describe('driver PINs — identifier equality', () => {
  it('rejects a PIN equal to the phone', () => {
    expect(checkPasswordPolicy('driver-pin', PHONE, PHONE)).toBe('equals_identifier');
  });

  it('still rejects when the identifier carries surrounding whitespace', () => {
    expect(checkPasswordPolicy('driver-pin', PHONE, `  ${PHONE} `)).toBe('equals_identifier');
  });

  it('cannot be smuggled past the numeric rule with whitespace in the PIN', () => {
    expect(checkPasswordPolicy('driver-pin', ` ${PHONE}`, PHONE)).toBe('pin_not_numeric');
  });
});

describe('driver PINs — common-PIN blocklist', () => {
  it('rejects every single blocklist entry, and every entry is a well-formed PIN', () => {
    expect(COMMON_PIN_BLOCKLIST.size).toBeGreaterThanOrEqual(80);
    for (const pin of COMMON_PIN_BLOCKLIST) {
      expect(/^\d{8,20}$/.test(pin), `malformed blocklist entry: ${pin}`).toBe(true);
      expect(checkPasswordPolicy('driver-pin', pin, PHONE), `entry not rejected: ${pin}`).toBe(
        'pin_blocked',
      );
    }
  });

  it.each(['12345678', '0123456789', '11223344', '13800101'])(
    'rejects well-known weak PIN %s',
    (pin) => {
      expect(checkPasswordPolicy('driver-pin', pin, PHONE)).toBe('pin_blocked');
    },
  );
});

describe('driver PINs — structural patterns beyond the blocklist', () => {
  it.each([
    ['13-digit all-same (beyond blocklist lengths)', '3'.repeat(13)],
    ['20-digit all-same', '9'.repeat(20)],
  ])('rejects %s', (_label, pin) => {
    expect(checkPasswordPolicy('driver-pin', pin, PHONE)).toBe('pin_blocked');
  });

  // ATTACK PROBE: cyclic extensions of blocked runs (digits wrap at 9→0).
  // The 0- and 9-anchored wraps are blocklisted; '1234567890' is not (FINDING).
  it.each(['01234567890', '012345678901', '1234567890', '98765432109'])(
    'rejects cyclic/extended sequential PIN %s',
    (pin) => {
      expect(checkPasswordPolicy('driver-pin', pin, PHONE)).toBe('pin_blocked');
    },
  );
});

describe('passwordKindForRoles (A20: dual-role accounts follow the staff rule)', () => {
  it.each<[readonly AssignableRole[], PasswordKind]>([
    [['DRIVER'], 'driver-pin'],
    [['DRIVER', 'DRIVER'], 'driver-pin'],
    [['FACTORY_OPERATOR'], 'staff'],
    [['CARRIER_ADMIN'], 'staff'],
    [['DRIVER', 'CARRIER_ADMIN'], 'staff'],
    [['DRIVER', 'FACTORY_OPERATOR', 'CARRIER_ADMIN'], 'staff'],
  ])('roles %j → %s', (roles, expected) => {
    expect(passwordKindForRoles(roles)).toBe(expected);
  });
});

describe('assertPasswordPolicy — DomainError contract (A14: never echoes the password)', () => {
  const cases: {
    label: string;
    kind: PasswordKind;
    password: string;
    identifier: string;
    reason: PasswordPolicyFailure;
  }[] = [
    {
      label: 'staff too_short',
      kind: 'staff',
      password: 'Q7!x',
      identifier: 'someone@t01',
      reason: 'too_short',
    },
    {
      label: 'staff too_long',
      kind: 'staff',
      password: `Marker${'Z'.repeat(140)}`,
      identifier: 'someone@t01',
      reason: 'too_long',
    },
    {
      label: 'staff equals_identifier',
      kind: 'staff',
      password: 'Tr0ub4dor&3x',
      identifier: 'tr0ub4dor&3x',
      reason: 'equals_identifier',
    },
    {
      label: 'driver pin_not_numeric',
      kind: 'driver-pin',
      password: '12a45678',
      identifier: '09120000004',
      reason: 'pin_not_numeric',
    },
    {
      label: 'driver pin_blocked',
      kind: 'driver-pin',
      password: '12345678',
      identifier: '09120000004',
      reason: 'pin_blocked',
    },
  ];

  for (const testCase of cases) {
    it(`throws BAD_INPUT (${testCase.label}) and never leaks the password`, () => {
      let thrown: unknown;
      try {
        assertPasswordPolicy(testCase.kind, testCase.password, testCase.identifier);
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(DomainError);
      const err = thrown as DomainError;
      expect(err.code).toBe('BAD_INPUT');
      expect(err.statusCode).toBe(400);
      expect(err.details).toEqual({ reason: testCase.reason });
      const blob = JSON.stringify({
        name: err.name,
        message: err.message,
        code: err.code,
        details: err.details,
      });
      expect(blob).not.toContain(testCase.password);
    });
  }

  it('does not throw for valid inputs', () => {
    expect(() => assertPasswordPolicy('staff', 'V4lid!Passphrase', 'someone@t01')).not.toThrow();
    expect(() => assertPasswordPolicy('driver-pin', '58130472', '09120000004')).not.toThrow();
  });
});

import { describe, expect, it } from 'vitest';

import { randomNationalId } from '../../../test/setup/national-id.js';
import {
  ASSIGNABLE_ROLES,
  createUserInputSchema,
  ROLE_SCOPE,
  roleCodeSchema,
  toUserDto,
  USERNAME_PATTERN,
} from './users.types.js';

/**
 * Docker-free unit tests for the repository's input whitelist, role catalog
 * and DTO mapping (F1-03 T06). Behavior against a real DB is covered by
 * test/users.int.test.ts.
 */
describe('users.types', () => {
  describe('createUserInputSchema', () => {
    it('accepts phone-only, username-only and both', () => {
      expect(
        createUserInputSchema.safeParse({ displayName: 'A', phone: '09120000001' }).success,
      ).toBe(true);
      expect(
        createUserInputSchema.safeParse({ displayName: 'A', username: 'user.a' }).success,
      ).toBe(true);
      expect(
        createUserInputSchema.safeParse({
          displayName: 'A',
          username: 'user.a',
          phone: '09120000001',
        }).success,
      ).toBe(true);
    });

    it('rejects input with neither username nor phone (users_login_present)', () => {
      expect(createUserInputSchema.safeParse({ displayName: 'A' }).success).toBe(false);
    });

    it('rejects unknown fields — tenantId, status, createdBy and PII columns are not mass-assignable', () => {
      const base = { displayName: 'A', phone: '09120000001' };
      for (const extra of [
        { tenantId: 'b6f6b7b8-0000-4000-8000-000000000000' },
        { status: 'disabled' },
        { createdBy: 'b6f6b7b8-0000-4000-8000-000000000000' },
        { phoneEnc: Buffer.from([1]) },
        { nationalId: randomNationalId() },
        { role: 'DRIVER' },
      ]) {
        expect(
          createUserInputSchema.safeParse({ ...base, ...extra }).success,
          JSON.stringify(extra),
        ).toBe(false);
      }
    });

    it('enforces the username format (same rule as the DB CHECK)', () => {
      for (const bad of ['Ab', 'ab', 'UPPERCASE', 'has space', 'فارسی', 'a'.repeat(33)]) {
        expect(USERNAME_PATTERN.test(bad), bad).toBe(false);
        expect(createUserInputSchema.safeParse({ displayName: 'A', username: bad }).success).toBe(
          false,
        );
      }
      expect(
        createUserInputSchema.safeParse({ displayName: 'A', username: 'ali.sheikh-1' }).success,
      ).toBe(true);
    });

    it('trims displayName and rejects empty/over-long values', () => {
      const trimmed = createUserInputSchema.parse({ displayName: '  علی  ', phone: '09120000001' });
      expect(trimmed.displayName).toBe('علی');
      expect(
        createUserInputSchema.safeParse({ displayName: '   ', phone: '09120000001' }).success,
      ).toBe(false);
      expect(
        createUserInputSchema.safeParse({ displayName: 'x'.repeat(201), phone: '09120000001' })
          .success,
      ).toBe(false);
    });
  });

  describe('roleCodeSchema / ROLE_SCOPE', () => {
    it('accepts exactly the 3-role catalog', () => {
      for (const code of ASSIGNABLE_ROLES) {
        expect(roleCodeSchema.safeParse(code).success).toBe(true);
      }
    });

    it('rejects removed and unknown roles (PLATFORM_ADMIN, AUDITOR, CARRIER_OPERATOR, …)', () => {
      for (const bad of ['PLATFORM_ADMIN', 'AUDITOR', 'CARRIER_OPERATOR', 'NINJA', '']) {
        expect(roleCodeSchema.safeParse(bad).success, bad).toBe(false);
      }
    });

    it('maps each role to its catalog scope (the composite FK re-verifies the pair)', () => {
      expect(ROLE_SCOPE).toEqual({
        FACTORY_OPERATOR: 'tenant',
        CARRIER_ADMIN: 'carrier',
        DRIVER: 'driver',
      });
    });
  });

  describe('toUserDto', () => {
    it('copies only DTO fields — PII ciphertext/hash columns can never leak', () => {
      const row = {
        id: 'b6f6b7b8-0000-4000-8000-000000000001',
        tenantId: 'b6f6b7b8-0000-4000-8000-000000000002',
        username: 'user.a',
        displayName: 'User A',
        status: 'active',
        createdAt: new Date('2026-01-01T00:00:00Z'),
        updatedAt: new Date('2026-01-02T00:00:00Z'),
        // Columns that must NOT survive the mapping:
        phoneEnc: Buffer.from([1, 2, 3]),
        phoneHash: Buffer.from([4, 5, 6]),
        nationalIdEnc: Buffer.from([7]),
        nationalIdHash: Buffer.from([8]),
        deletedAt: null,
        createdBy: null,
      };
      const dto = toUserDto(row);
      expect(dto).toEqual({
        id: row.id,
        tenantId: row.tenantId,
        username: 'user.a',
        displayName: 'User A',
        status: 'active',
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
      });
      expect(Object.keys(dto).sort()).toEqual(
        ['createdAt', 'displayName', 'id', 'status', 'tenantId', 'updatedAt', 'username'].sort(),
      );
    });
  });
});

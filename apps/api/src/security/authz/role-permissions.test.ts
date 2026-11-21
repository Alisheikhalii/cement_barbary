import { describe, expect, it } from 'vitest';

import { ASSIGNABLE_ROLES } from '../../modules/users/users.types.js';
import { PERMISSION_NAMES, PERMISSIONS } from './permissions.js';
import type { PermissionName } from './permissions.js';
import {
  isRoleCode,
  permissionsForRole,
  roleHasPermission,
  ROLE_CODES,
  ROLE_PERMISSIONS,
} from './role-permissions.js';
import type { RoleCode } from './role-permissions.js';

/**
 * Exhaustive role × permission tests (ADR-008 Z1/Z2/Z9, F1-05 T02). The
 * operator holds the full catalog; CARRIER_ADMIN and DRIVER hold no data
 * permission in F1-05.
 */
describe('role-permission map', () => {
  const expected: Record<RoleCode, readonly PermissionName[]> = {
    FACTORY_OPERATOR: [
      'destination.read',
      'destination.write',
      'hall.read',
      'hall.write',
      'loader_type.read',
      'loader_type.write',
      'carrier.read',
      'carrier.write',
      'carrier_membership.write',
      'carrier_quota.write',
    ],
    CARRIER_ADMIN: [],
    DRIVER: [],
  };

  it('uses exactly the role catalog from ADR-006 (drift guard)', () => {
    expect([...ROLE_CODES]).toEqual([...ASSIGNABLE_ROLES]);
    expect(Object.keys(ROLE_PERMISSIONS).sort()).toEqual([...ASSIGNABLE_ROLES].sort());
  });

  it('maps every role to exactly the reviewed list', () => {
    for (const role of ROLE_CODES) {
      expect(permissionsForRole(role)).toEqual(expected[role]);
    }
  });

  it('exhaustive role × permission table: only the operator holds a permission', () => {
    for (const role of ROLE_CODES) {
      for (const permission of PERMISSION_NAMES) {
        expect(roleHasPermission(role, permission)).toBe(role === 'FACTORY_OPERATOR');
      }
    }
  });

  it('gives CARRIER_ADMIN and DRIVER zero data permissions', () => {
    expect(ROLE_PERMISSIONS.CARRIER_ADMIN).toEqual([]);
    expect(ROLE_PERMISSIONS.DRIVER).toEqual([]);
    for (const permission of PERMISSION_NAMES) {
      expect(roleHasPermission('CARRIER_ADMIN', permission)).toBe(false);
      expect(roleHasPermission('DRIVER', permission)).toBe(false);
    }
  });

  it('never maps a permission that is absent from the catalog', () => {
    for (const role of ROLE_CODES) {
      for (const permission of ROLE_PERMISSIONS[role]) {
        expect(PERMISSIONS).toHaveProperty(permission);
      }
    }
  });

  it('never repeats a permission inside one role', () => {
    for (const role of ROLE_CODES) {
      const list = ROLE_PERMISSIONS[role];
      expect(new Set(list).size).toBe(list.length);
    }
  });

  it('unknown or removed role codes grant nothing', () => {
    for (const role of ['', 'SUPERUSER', 'PLATFORM_ADMIN', 'factory_operator']) {
      expect(isRoleCode(role)).toBe(false);
      expect(permissionsForRole(role)).toEqual([]);
      for (const permission of PERMISSION_NAMES) {
        expect(roleHasPermission(role, permission)).toBe(false);
      }
    }
  });

  it('accepts only the three catalog role codes', () => {
    for (const role of ROLE_CODES) {
      expect(isRoleCode(role)).toBe(true);
    }
  });

  it('keeps the map and every role list frozen', () => {
    expect(Object.isFrozen(ROLE_PERMISSIONS)).toBe(true);
    for (const role of ROLE_CODES) {
      expect(Object.isFrozen(ROLE_PERMISSIONS[role])).toBe(true);
    }
  });
});

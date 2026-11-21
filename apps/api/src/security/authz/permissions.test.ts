import { describe, expect, it } from 'vitest';

import {
  getPermission,
  isPermissionName,
  isSensitivePermission,
  PERMISSION_NAME_PATTERN,
  PERMISSION_NAMES,
  PERMISSION_SCOPES,
  PERMISSIONS,
} from './permissions.js';

/**
 * Exhaustive catalog tests (ADR-008 Z1/Z2, F1-05 T02). The catalog is the
 * single source of truth for permission names, scopes and sensitivity; the
 * matrix generator and the BFLA suite iterate it.
 */
describe('permission catalog', () => {
  const expectedCatalog = {
    'destination.read': { scope: 'tenant', sensitive: false },
    'destination.write': { scope: 'tenant', sensitive: false },
    'hall.read': { scope: 'tenant', sensitive: false },
    'hall.write': { scope: 'tenant', sensitive: false },
    'loader_type.read': { scope: 'tenant', sensitive: false },
    'loader_type.write': { scope: 'tenant', sensitive: false },
    'carrier.read': { scope: 'tenant', sensitive: false },
    'carrier.write': { scope: 'tenant', sensitive: false },
    'carrier_membership.write': { scope: 'tenant', sensitive: true },
    'carrier_quota.write': { scope: 'tenant', sensitive: true },
  } as const;

  it('contains exactly the reviewed F1-05/F1-07/F1-08 catalog', () => {
    expect(PERMISSIONS).toEqual(expectedCatalog);
    expect(PERMISSION_NAMES).toEqual(Object.keys(expectedCatalog));
  });

  it('has unique, resource.action-shaped names', () => {
    expect(new Set(PERMISSION_NAMES).size).toBe(PERMISSION_NAMES.length);
    for (const name of PERMISSION_NAMES) {
      expect(name).toMatch(PERMISSION_NAME_PATTERN);
    }
  });

  it('uses only the three declared scopes', () => {
    for (const name of PERMISSION_NAMES) {
      expect(PERMISSION_SCOPES).toContain(PERMISSIONS[name].scope);
    }
  });

  it('marks only the two F1-08 writes as sensitive', () => {
    const sensitive = PERMISSION_NAMES.filter((name) => PERMISSIONS[name].sensitive);
    expect(sensitive).toEqual(['carrier_membership.write', 'carrier_quota.write']);
    for (const name of PERMISSION_NAMES) {
      expect(isSensitivePermission(name)).toBe(PERMISSIONS[name].sensitive);
    }
  });

  it('never resolves an unknown or differently-cased name', () => {
    for (const name of [
      '',
      'destination',
      'destination.delete',
      'DESTINATION.READ',
      'roles.write',
    ]) {
      expect(isPermissionName(name)).toBe(false);
      expect(getPermission(name)).toBeUndefined();
      expect(isSensitivePermission(name)).toBe(false);
    }
  });

  it('keeps the catalog, every definition and the scope list frozen', () => {
    expect(Object.isFrozen(PERMISSIONS)).toBe(true);
    expect(Object.isFrozen(PERMISSION_NAMES)).toBe(true);
    expect(Object.isFrozen(PERMISSION_SCOPES)).toBe(true);
    for (const name of PERMISSION_NAMES) {
      expect(Object.isFrozen(PERMISSIONS[name])).toBe(true);
    }
  });
});

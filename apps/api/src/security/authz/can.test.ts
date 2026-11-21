import { describe, expect, it } from 'vitest';

import { can, decide, scopeAllows } from './can.js';
import type { ResourceRef } from './can.js';
import { isSensitivePermission, PERMISSION_NAMES } from './permissions.js';
import { createPrincipal } from './principal.js';
import type { Principal, PrincipalInput } from './principal.js';
import { ROLE_CODES } from './role-permissions.js';

/**
 * Exhaustive `can()` and scope tests (ADR-008 Z5/Z6/Z8/Z9, F1-05 T02).
 * The function is pure: every case below supplies a principal and, where the
 * scope needs one, a resource.
 */
const TENANT = 'tenant-a';
const OTHER_TENANT = 'tenant-b';
const USER = 'user-a';
const OTHER_USER = 'user-b';
const SESSION = 'session-a';
const CARRIER = 'carrier-a';
const OTHER_CARRIER = 'carrier-b';

function principal(overrides: Partial<PrincipalInput> = {}): Principal {
  return createPrincipal({
    userId: USER,
    tenantId: TENANT,
    sessionId: SESSION,
    roles: ['FACTORY_OPERATOR'],
    ...overrides,
  });
}

describe('can()', () => {
  it('exhaustive role × permission table without a resource', () => {
    for (const role of ROLE_CODES) {
      const p = principal({ roles: [role] });
      for (const permission of PERMISSION_NAMES) {
        expect(can(p, permission)).toBe(role === 'FACTORY_OPERATOR');
      }
    }
  });

  it('denies every permission to an unknown role', () => {
    const p = principal({ roles: ['SUPERUSER', 'PLATFORM_ADMIN'] });
    for (const permission of PERMISSION_NAMES) {
      expect(can(p, permission)).toBe(false);
    }
  });

  it('denies every permission to a role-less principal', () => {
    const p = principal({ roles: [] });
    for (const permission of PERMISSION_NAMES) {
      expect(can(p, permission)).toBe(false);
    }
  });

  it('duplicate roles are behaviorally identical to one role (CP1 BF-04)', () => {
    const single = principal({ roles: ['FACTORY_OPERATOR'] });
    const duplicated = principal({ roles: Array<string>(8).fill('FACTORY_OPERATOR') });
    for (const permission of PERMISSION_NAMES) {
      expect(can(duplicated, permission)).toBe(can(single, permission));
      expect(can(duplicated, permission)).toBe(true);
    }

    // An unknown role repeated many times still grants nothing; one real role
    // next to it grants exactly what that role grants.
    const onlyUnknown = principal({ roles: Array<string>(8).fill('SUPERUSER') });
    const mixed = principal({ roles: ['SUPERUSER', 'FACTORY_OPERATOR', 'FACTORY_OPERATOR'] });
    for (const permission of PERMISSION_NAMES) {
      expect(can(onlyUnknown, permission)).toBe(false);
      expect(can(mixed, permission)).toBe(can(single, permission));
    }
  });

  it('unknown and differently-cased permission names deny', () => {
    const p = principal();
    for (const name of [
      '',
      'destination',
      'destination.delete',
      'DESTINATION.READ',
      'roles.write',
    ]) {
      expect(can(p, name)).toBe(false);
    }
  });

  it('treats sensitive permissions exactly like normal ones (freshness is the guard)', () => {
    const operator = principal();
    const driver = principal({ roles: ['DRIVER'] });
    for (const permission of PERMISSION_NAMES) {
      if (!isSensitivePermission(permission)) {
        continue;
      }
      expect(can(operator, permission)).toBe(true);
      expect(can(driver, permission)).toBe(false);
    }
  });

  it('tenant scope requires a matching tenant when a resource is supplied', () => {
    const p = principal();
    expect(can(p, 'destination.read', { tenantId: TENANT })).toBe(true);
    expect(can(p, 'destination.read', { tenantId: OTHER_TENANT })).toBe(false);
    expect(can(p, 'destination.read', { tenantId: '' })).toBe(false);
  });

  it('tenant scope ignores carrier/owner fields (a tenant permission is tenant-wide)', () => {
    const p = principal({ carrierId: CARRIER });
    expect(
      can(p, 'destination.read', {
        tenantId: TENANT,
        carrierId: OTHER_CARRIER,
        driverUserId: OTHER_USER,
      }),
    ).toBe(true);
  });

  it('fails closed for an empty principal tenant id', () => {
    const p = principal({ tenantId: '' });
    expect(can(p, 'destination.read')).toBe(false);
    expect(scopeAllows(p, 'tenant')).toBe(false);
  });
});

describe('scopeAllows()', () => {
  it('forces a carrier-scoped fixture through the same decision core as can()', () => {
    // The production catalog has no carrier-scoped permission until F1-08.
    // This fixture is force-mapped as "granted" and goes through decide(),
    // which can() also calls, so the carrier branch is not dead code in tests.
    const carrierDefinition = { scope: 'carrier', sensitive: false } as const;
    const noCarrier = principal();
    const emptyCarrier = principal({ carrierId: '' });
    const withCarrier = principal({ carrierId: CARRIER });

    expect(decide(noCarrier, carrierDefinition, true)).toBe(false);
    expect(decide(emptyCarrier, carrierDefinition, true)).toBe(false);
    expect(decide(withCarrier, carrierDefinition, true)).toBe(true);
    expect(
      decide(noCarrier, carrierDefinition, true, { tenantId: TENANT, carrierId: CARRIER }),
    ).toBe(false);
    expect(
      decide(withCarrier, carrierDefinition, true, { tenantId: TENANT, carrierId: CARRIER }),
    ).toBe(true);
    expect(decide(withCarrier, carrierDefinition, false)).toBe(false);
  });

  it('carrier scope requires tenant + matching carrier when a resource is supplied', () => {
    const p = principal({ carrierId: CARRIER });
    expect(scopeAllows(p, 'carrier')).toBe(true);
    expect(scopeAllows(p, 'carrier', { tenantId: TENANT, carrierId: CARRIER })).toBe(true);
    expect(scopeAllows(p, 'carrier', { tenantId: TENANT, carrierId: OTHER_CARRIER })).toBe(false);
    expect(scopeAllows(p, 'carrier', { tenantId: OTHER_TENANT, carrierId: CARRIER })).toBe(false);
    expect(scopeAllows(p, 'carrier', { tenantId: TENANT })).toBe(false);
  });

  it('own scope resolves to the principal user id', () => {
    const p = principal();
    expect(scopeAllows(p, 'own')).toBe(true);
    expect(scopeAllows(p, 'own', { tenantId: TENANT, driverUserId: USER })).toBe(true);
    expect(scopeAllows(p, 'own', { tenantId: TENANT, driverUserId: OTHER_USER })).toBe(false);
    expect(scopeAllows(p, 'own', { tenantId: OTHER_TENANT, driverUserId: USER })).toBe(false);
    expect(scopeAllows(p, 'own', { tenantId: TENANT })).toBe(false);
    expect(scopeAllows(principal({ userId: '' }), 'own')).toBe(false);
  });

  it('an unknown scope string fails closed', () => {
    const p = principal();
    // TypeScript prevents this in production; the runtime guard must too.
    expect(scopeAllows(p, 'platform' as never)).toBe(false);
  });
});

describe('createPrincipal()', () => {
  it('copies the role list so later mutation cannot change the principal', () => {
    const roles = ['FACTORY_OPERATOR'];
    const p = createPrincipal({
      userId: USER,
      tenantId: TENANT,
      sessionId: SESSION,
      roles,
    });
    roles.push('DRIVER');
    expect(p.roles).toEqual(['FACTORY_OPERATOR']);
  });

  it('omits carrierId when absent and keeps it when supplied', () => {
    const withoutCarrier = principal();
    expect('carrierId' in withoutCarrier).toBe(false);
    expect(principal({ carrierId: CARRIER }).carrierId).toBe(CARRIER);
  });

  it('returns a frozen principal and a frozen role list', () => {
    const p = principal();
    expect(Object.isFrozen(p)).toBe(true);
    expect(Object.isFrozen(p.roles)).toBe(true);

    // Runtime mutation must not change a decision: TS readonly is compile-time.
    expect(Reflect.set(p, 'tenantId', OTHER_TENANT)).toBe(false);
    expect(Reflect.set(p.roles as unknown as object, '0', 'DRIVER')).toBe(false);
    expect(p.tenantId).toBe(TENANT);
    expect(p.roles).toEqual(['FACTORY_OPERATOR']);
    expect(can(p, 'destination.read')).toBe(true);
  });
});

describe('resource reference shape', () => {
  it('is readonly at the type level and accepted by can()', () => {
    const resource: ResourceRef = { tenantId: TENANT };
    expect(can(principal(), 'destination.read', resource)).toBe(true);
  });
});

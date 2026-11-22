import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  canonicalRoutePath,
  isAllowlistedPublicRoute,
  markerCount,
  normalizeRoutePath,
  normalizeRoutePaths,
  PUBLIC_ROUTE_ALLOWLIST,
  reasonSchemaIsValid,
  scanControllers,
  scanRoutes,
  type ScannedRoute,
} from './route-scan.js';
import { sensitiveReasonSchema } from './sensitive-reason.js';

/**
 * Exhaustive route-scan rules (ADR-008 Z3/Z10; owner C5/C6; CP1 GB-03/GB-04,
 * RD-03, SA-05). These are the same pure functions the boot assertion uses.
 */
const TENANT_PERMISSION = 'destination.read';
const SENSITIVE_PERMISSION = 'carrier_membership.write';

function route(overrides: Partial<ScannedRoute> = {}): ScannedRoute {
  return {
    moduleName: 'ProbeModule',
    controllerName: 'ProbeController',
    handlerName: 'handler',
    method: 'GET',
    path: '/api/v1/probe',
    isPublic: false,
    isSelfService: false,
    isPermission: true,
    classLevelMarker: false,
    permission: TENANT_PERMISSION,
    bodySchema: null,
    querySchema: null,
    paramsSchema: null,
    ...overrides,
  };
}

function codes(
  routes: readonly ScannedRoute[],
  env: 'development' | 'test' | 'production' = 'test',
): string[] {
  return scanRoutes(routes, env).map((issue) => issue.code);
}

describe('route scan — markers', () => {
  it('accepts a permission route with exactly one marker', () => {
    expect(scanRoutes([route()], 'test')).toEqual([]);
  });

  it('accepts a self-service route for every module', () => {
    const self = route({ isPermission: false, isSelfService: true, permission: null });
    expect(scanRoutes([self], 'test')).toEqual([]);
  });

  it('rejects a route with no marker', () => {
    expect(
      codes([
        route({ isPermission: false, isSelfService: false, isPublic: false, permission: null }),
      ]),
    ).toContain('AUTHZ_MARKER_COUNT');
  });

  it('rejects a route with two markers', () => {
    expect(codes([route({ isPublic: true, isSelfService: true })])).toContain('AUTHZ_MARKER_COUNT');
    expect(codes([route({ isPublic: true, isPermission: true })])).toContain('AUTHZ_MARKER_COUNT');
  });

  it('rejects a class-level marker even when the handler is valid', () => {
    expect(codes([route({ classLevelMarker: true })])).toContain('AUTHZ_CLASS_LEVEL_MARKER');
  });

  it('counts markers exactly', () => {
    expect(markerCount(route())).toBe(1);
    expect(
      markerCount(
        route({ isPublic: true, isSelfService: true, isPermission: false, permission: null }),
      ),
    ).toBe(2);
    expect(
      markerCount(
        route({ isPermission: false, isSelfService: false, isPublic: false, permission: null }),
      ),
    ).toBe(0);
  });
});

describe('route scan — public allowlist (GB-03)', () => {
  it('contains exactly the reviewed §D public routes', () => {
    expect([...PUBLIC_ROUTE_ALLOWLIST]).toEqual([
      { method: 'GET', path: '/health/live' },
      { method: 'GET', path: '/health/ready' },
      { method: 'POST', path: '/api/v1/auth/login' },
      { method: 'POST', path: '/api/v1/auth/refresh' },
      { method: 'POST', path: '/api/v1/auth/logout' },
      { method: 'POST', path: '/api/v1/auth/password/change' },
    ]);
  });

  it('accepts each allowlisted public route', () => {
    for (const entry of PUBLIC_ROUTE_ALLOWLIST) {
      const publicRoute = route({
        method: entry.method,
        path: entry.path,
        isPermission: false,
        isPublic: true,
        permission: null,
      });
      expect(scanRoutes([publicRoute], 'test'), entry.path).toEqual([]);
    }
  });

  it('rejects a public route that is not on the allowlist', () => {
    expect(
      codes([
        route({ isPublic: true, isPermission: false, permission: null, path: '/api/v1/probe' }),
      ]),
    ).toContain('AUTHZ_PUBLIC_NOT_ALLOWLISTED');
  });

  it('matches prefixed, unprefixed and trailing-slash request paths, and the method', () => {
    expect(isAllowlistedPublicRoute('POST', '/api/v1/auth/login', 'production')).toBe(true);
    expect(isAllowlistedPublicRoute('POST', '/auth/login', 'production')).toBe(false);
    expect(isAllowlistedPublicRoute('POST', '/auth/login', 'test')).toBe(true);
    expect(isAllowlistedPublicRoute('POST', '/api/v1/auth/login', 'test')).toBe(true);
    expect(isAllowlistedPublicRoute('POST', '/api/v1/auth/login/', 'test')).toBe(true);
    expect(isAllowlistedPublicRoute('post', '/api/v1/auth/login?x=1', 'test')).toBe(true);
    expect(isAllowlistedPublicRoute('GET', '/health/live', 'production')).toBe(true);
    expect(isAllowlistedPublicRoute('GET', '/auth/login', 'test')).toBe(false);
    expect(isAllowlistedPublicRoute('DELETE', '/health/live', 'test')).toBe(false);
    expect(isAllowlistedPublicRoute('POST', '/auth/login/extra', 'test')).toBe(false);
    expect(isAllowlistedPublicRoute('GET', '/api/v1/auth/me', 'test')).toBe(false);
    // Production is canonical-only and case-sensitive.
    expect(isAllowlistedPublicRoute('POST', '/API/V1/AUTH/LOGIN', 'production')).toBe(false);
    expect(isAllowlistedPublicRoute('POST', '/auth/login', 'development')).toBe(true);
    // Path confusion: malformed forms are never allowlisted.
    for (const environment of ['test', 'production'] as const) {
      for (const path of [
        '/api/v1/auth/login/../me',
        '/api/v1/auth/login/%2e%2e/me',
        '/api/v1/auth/login%2F..%2Fme',
        '/api/v1/auth/login;foo=bar',
        '//api/v1/auth/login',
        '/api/v1/auth/login.',
        '/api/v1/auth/login/..',
      ]) {
        expect(isAllowlistedPublicRoute('POST', path, environment), path).toBe(false);
      }
    }
  });
});

describe('route scan — permissions and sensitive bodies (SA-05)', () => {
  it('rejects an unknown permission name', () => {
    expect(codes([route({ permission: 'destination.delete' })])).toContain(
      'AUTHZ_UNKNOWN_PERMISSION',
    );
  });

  it('does not require a body schema for a non-sensitive permission', () => {
    expect(scanRoutes([route()], 'test')).toEqual([]);
  });

  it('requires @ZodBody metadata for a sensitive permission', () => {
    expect(codes([route({ permission: SENSITIVE_PERMISSION })])).toContain(
      'AUTHZ_SENSITIVE_BODY_SCHEMA',
    );
  });

  it('accepts a sensitive schema that carries non-reason fields', () => {
    const schema = z.strictObject({
      reason: sensitiveReasonSchema,
      note: z.string().max(200),
    });
    expect(
      scanRoutes([route({ permission: SENSITIVE_PERMISSION, bodySchema: schema })], 'test'),
    ).toEqual([]);
  });

  it.each([
    ['missing reason', z.strictObject({ other: z.string() })],
    ['plain string', z.strictObject({ reason: z.string() })],
    ['no trim', z.strictObject({ reason: z.string().min(10).max(500) })],
    ['trim after the bounds', z.strictObject({ reason: z.string().min(10).max(500).trim() })],
    ['minimum below ten', z.strictObject({ reason: z.string().min(6).max(500) })],
    ['nullable reason', z.strictObject({ reason: sensitiveReasonSchema.nullable() })],
    [
      'a non-string union branch',
      z.strictObject({ reason: z.union([sensitiveReasonSchema, z.number()]) }),
    ],
    ['too short', z.strictObject({ reason: z.string().trim().min(5).max(500) })],
    ['too long', z.strictObject({ reason: z.string().trim().min(10).max(1000) })],
    ['control characters allowed', z.strictObject({ reason: z.string().trim().min(10).max(500) })],
  ])('rejects a sensitive schema with %s', (_label, schema) => {
    expect(codes([route({ permission: SENSITIVE_PERMISSION, bodySchema: schema })])).toContain(
      'AUTHZ_SENSITIVE_REASON',
    );
  });

  it('reasonSchemaIsValid proves required, trim, bounds and control characters', () => {
    expect(reasonSchemaIsValid(z.strictObject({ reason: sensitiveReasonSchema }))).toBe(true);
    expect(
      reasonSchemaIsValid(z.strictObject({ reason: z.string().trim().min(10).max(500) })),
    ).toBe(false);
    expect(reasonSchemaIsValid(null)).toBe(false);
    expect(reasonSchemaIsValid({ shape: {} })).toBe(false);

    // A hand-rolled schema that rejects only C0 is NOT enough: C1, zero-width,
    // bidi and lone surrogates must also fail the boot gate.
    const c0Only = z.strictObject({
      reason: z
        .string()
        .trim()
        .min(10)
        .max(500)
        .refine((value) =>
          [...value].every((character) => {
            const codePoint = character.codePointAt(0) ?? 0;
            return codePoint > 0x1f;
          }),
        ),
    });
    expect(reasonSchemaIsValid(c0Only)).toBe(false);
  });
});

describe('route scan — mass assignment (T07)', () => {
  it('rejects forbidden identity keys in body, query and params schemas', () => {
    expect(
      codes([route({ bodySchema: z.strictObject({ roles: z.array(z.string()) }) })]),
    ).toContain('AUTHZ_MASS_ASSIGNMENT');
    expect(codes([route({ querySchema: z.strictObject({ tenant_id: z.string() }) })])).toContain(
      'AUTHZ_MASS_ASSIGNMENT',
    );
    expect(codes([route({ paramsSchema: z.strictObject({ userId: z.string() }) })])).toContain(
      'AUTHZ_MASS_ASSIGNMENT',
    );
  });

  it('rejects a non-strict object in any input surface', () => {
    expect(codes([route({ bodySchema: z.object({ name: z.string() }) })])).toContain(
      'AUTHZ_NON_STRICT_INPUT',
    );
    expect(codes([route({ querySchema: z.object({ page: z.string() }) })])).toContain(
      'AUTHZ_NON_STRICT_INPUT',
    );
    expect(codes([route({ paramsSchema: z.object({ id: z.string() }) })])).toContain(
      'AUTHZ_NON_STRICT_INPUT',
    );
  });

  it('accepts strict body, query and params schemas', () => {
    expect(
      scanRoutes(
        [
          route({
            bodySchema: z.strictObject({ displayName: z.string() }),
            querySchema: z.strictObject({ page: z.coerce.number().int().min(1) }),
            paramsSchema: z.strictObject({ id: z.uuid() }),
          }),
        ],
        'test',
      ),
    ).toEqual([]);
  });
});

describe('route scan — production surface (RD-03)', () => {
  it('accepts the production controllers and modules', () => {
    const health = route({
      moduleName: 'HealthModule',
      controllerName: 'HealthController',
      path: '/health/live',
      isPermission: false,
      isPublic: true,
      permission: null,
    });
    const me = route({
      moduleName: 'AuthModule',
      controllerName: 'AuthController',
      path: '/api/v1/auth/me',
      isPermission: false,
      isSelfService: true,
      permission: null,
    });
    expect(scanRoutes([health, me], 'production')).toEqual([]);
  });

  it('rejects a controller outside the production allowlist', () => {
    expect(
      codes(
        [route({ controllerName: 'ProbeController', moduleName: 'UsersModule' })],
        'production',
      ),
    ).toContain('AUTHZ_PRODUCTION_CONTROLLER');
  });

  it('rejects a probe/fixture/test module in production', () => {
    for (const moduleName of ['ProbeFixtureModule', 'TestModule', 'E2eModule', 'AuthTestModule']) {
      expect(
        codes([route({ moduleName, controllerName: 'AuthController' })], 'production'),
      ).toContain('AUTHZ_PRODUCTION_MODULE');
    }
    // Word-start anchoring: an ordinary name containing "test" is not a hit.
    expect(
      codes(
        [route({ moduleName: 'ContestModule', controllerName: 'AuthController' })],
        'production',
      ),
    ).toEqual([]);
    // The same module is fine outside production.
    expect(
      codes([route({ moduleName: 'ProbeFixtureModule', controllerName: 'AuthController' })]),
    ).toEqual([]);
  });
});

describe('route scan — production controllers without routes (RD-03)', () => {
  it('rejects a probe controller that has no route handlers', () => {
    const issues = scanControllers(
      [{ moduleName: 'ProbeEmptyModule', controllerName: 'ProbeEmptyController' }],
      [],
      'production',
    );
    expect(issues.map((issue) => issue.code)).toEqual([
      'AUTHZ_PRODUCTION_CONTROLLER',
      'AUTHZ_PRODUCTION_MODULE',
    ]);
  });

  it('does not duplicate an issue for a controller already scanned as a route', () => {
    const routes = [route({ moduleName: 'UsersModule', controllerName: 'ProbeController' })];
    expect(
      scanControllers(
        [{ moduleName: 'UsersModule', controllerName: 'ProbeController' }],
        routes,
        'production',
      ),
    ).toEqual([]);
  });

  it('ignores controllers outside production', () => {
    expect(
      scanControllers(
        [{ moduleName: 'ProbeEmptyModule', controllerName: 'ProbeEmptyController' }],
        [],
        'test',
      ),
    ).toEqual([]);
  });
});

describe('route path helpers', () => {
  it('normalizes Nest path metadata', () => {
    expect(normalizeRoutePath(undefined)).toBe('');
    expect(normalizeRoutePath('/health/')).toBe('health');
    expect(normalizeRoutePaths(['auth', 'password/change'])).toEqual(['auth', 'password/change']);
    expect(normalizeRoutePaths(['live', ''])).toEqual(['live', '']);
  });

  it('prefixes every controller except health', () => {
    expect(canonicalRoutePath('health', 'live', true)).toBe('/health/live');
    expect(canonicalRoutePath('auth', 'login')).toBe('/api/v1/auth/login');
    expect(canonicalRoutePath('auth', 'password/change')).toBe('/api/v1/auth/password/change');
  });
});

import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import { Controller, HttpCode, Module, Post, type INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { API_PREFIX } from '@bitabar/shared';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { AppModule } from '../../src/app.module.js';
import { AuthzFreshness } from '../../src/db/authz-freshness.js';
import { DbHealth } from '../../src/db/db-health.js';
import { TenantDb } from '../../src/db/tenant-db.js';
import { AUDIT_HOOK } from '../../src/security/authz/audit-hook.js';
import { TokenService } from '../../src/modules/auth/token.service.js';
import { RequirePermission, ZodBody } from '../../src/security/authz/decorators.js';
import {
  isPermissionName,
  PERMISSIONS,
  PERMISSION_NAMES,
  type PermissionName,
} from '../../src/security/authz/permissions.js';
import { AuthzRouteDiscovery } from '../../src/security/authz/route-discovery.js';
import { PRODUCTION_CONTROLLERS, type ScannedRoute } from '../../src/security/authz/route-scan.js';
import {
  ROLE_CODES,
  roleHasPermission,
  type RoleCode,
} from '../../src/security/authz/role-permissions.js';
import { sensitiveReasonSchema } from '../../src/security/authz/sensitive-reason.js';

/**
 * BFLA proof (ADR-008 Z1/Z2/Z3/Z9, F1-05 T07). Every catalog permission gets
 * one probe route in a test-only module. The real guards, the real token
 * service and the real route catalog decide; only the sensitive freshness read
 * and the DB health check are replaced. The production surface is enumerated
 * with the same discovery the boot scan uses.
 *
 * A broken function-level authorization shows up as a route whose status
 * disagrees with `roleHasPermission()`, so the expected matrix is code, not a
 * hand-maintained expectation table.
 */

const TENANT_ID = '00000000-0000-4000-8000-0000000000a1';
const SESSION_ID = '00000000-0000-4000-8000-0000000000a2';
const REASON = 'دلیل تست بفلا شماره یک';

const ROLE_USER_IDS: Readonly<Record<RoleCode, string>> = Object.freeze({
  FACTORY_OPERATOR: '00000000-0000-4000-8000-000000000001',
  CARRIER_ADMIN: '00000000-0000-4000-8000-000000000002',
  DRIVER: '00000000-0000-4000-8000-000000000003',
});
const ROLELESS_USER_ID = '00000000-0000-4000-8000-000000000004';
const UNKNOWN_ROLE_USER_ID = '00000000-0000-4000-8000-000000000005';
const INTERSECTION_USER_ID = '00000000-0000-4000-8000-000000000006';
const UNKNOWN_ROLE = 'SUPERUSER';

/** DB roles per user: the token∩DB intersection must keep exactly these. */
const DB_ROLES: Readonly<Record<string, readonly string[]>> = Object.freeze({
  [ROLE_USER_IDS.FACTORY_OPERATOR]: ['FACTORY_OPERATOR'],
  [ROLE_USER_IDS.CARRIER_ADMIN]: ['CARRIER_ADMIN'],
  [ROLE_USER_IDS.DRIVER]: ['DRIVER'],
  [ROLELESS_USER_ID]: [],
  [UNKNOWN_ROLE_USER_ID]: [UNKNOWN_ROLE],
  // Token says FACTORY_OPERATOR, DB says CARRIER_ADMIN: the sensitive path must
  // use the intersection, not the token's role.
  [INTERSECTION_USER_ID]: ['CARRIER_ADMIN'],
});

const freshness = {
  read: vi.fn(async (input: { userId: string }) => ({
    userActive: true,
    tenantActive: true,
    sessionLive: true,
    roles: DB_ROLES[input.userId] ?? [],
  })),
};

const EMPTY_BODY = z.strictObject({});
const SENSITIVE_BODY = z.strictObject({ reason: sensitiveReasonSchema });

/** One probe route per catalog permission, in catalog order. */
@Controller('bfla-probe')
class BflaProbeController {
  @HttpCode(200)
  @RequirePermission('destination.read')
  @Post('destination-read')
  destinationRead(@ZodBody(EMPTY_BODY) body: Record<string, never>): { ok: true } {
    void body;
    return { ok: true };
  }

  @HttpCode(200)
  @RequirePermission('destination.write')
  @Post('destination-write')
  destinationWrite(@ZodBody(EMPTY_BODY) body: Record<string, never>): { ok: true } {
    void body;
    return { ok: true };
  }

  @HttpCode(200)
  @RequirePermission('hall.read')
  @Post('hall-read')
  hallRead(@ZodBody(EMPTY_BODY) body: Record<string, never>): { ok: true } {
    void body;
    return { ok: true };
  }

  @HttpCode(200)
  @RequirePermission('hall.write')
  @Post('hall-write')
  hallWrite(@ZodBody(EMPTY_BODY) body: Record<string, never>): { ok: true } {
    void body;
    return { ok: true };
  }

  @HttpCode(200)
  @RequirePermission('loader_type.read')
  @Post('loader_type-read')
  loaderTypeRead(@ZodBody(EMPTY_BODY) body: Record<string, never>): { ok: true } {
    void body;
    return { ok: true };
  }

  @HttpCode(200)
  @RequirePermission('loader_type.write')
  @Post('loader_type-write')
  loaderTypeWrite(@ZodBody(EMPTY_BODY) body: Record<string, never>): { ok: true } {
    void body;
    return { ok: true };
  }

  @HttpCode(200)
  @RequirePermission('carrier.read')
  @Post('carrier-read')
  carrierRead(@ZodBody(EMPTY_BODY) body: Record<string, never>): { ok: true } {
    void body;
    return { ok: true };
  }

  @HttpCode(200)
  @RequirePermission('carrier.write')
  @Post('carrier-write')
  carrierWrite(@ZodBody(EMPTY_BODY) body: Record<string, never>): { ok: true } {
    void body;
    return { ok: true };
  }

  @HttpCode(200)
  @RequirePermission('carrier_membership.write')
  @Post('carrier_membership-write')
  carrierMembershipWrite(@ZodBody(SENSITIVE_BODY) body: { reason: string }): { ok: true } {
    void body;
    return { ok: true };
  }

  @HttpCode(200)
  @RequirePermission('carrier_quota.write')
  @Post('carrier_quota-write')
  carrierQuotaWrite(@ZodBody(SENSITIVE_BODY) body: { reason: string }): { ok: true } {
    void body;
    return { ok: true };
  }
}

@Module({ controllers: [BflaProbeController] })
class BflaProbeModule {}

const PROBE_ROUTES = [
  { permission: 'destination.read', segment: 'destination-read' },
  { permission: 'destination.write', segment: 'destination-write' },
  { permission: 'hall.read', segment: 'hall-read' },
  { permission: 'hall.write', segment: 'hall-write' },
  { permission: 'loader_type.read', segment: 'loader_type-read' },
  { permission: 'loader_type.write', segment: 'loader_type-write' },
  { permission: 'carrier.read', segment: 'carrier-read' },
  { permission: 'carrier.write', segment: 'carrier-write' },
  { permission: 'carrier_membership.write', segment: 'carrier_membership-write' },
  { permission: 'carrier_quota.write', segment: 'carrier_quota-write' },
] as const satisfies readonly { readonly permission: PermissionName; readonly segment: string }[];

const FORBIDDEN_BODY = Object.freeze({
  error: { code: 'FORBIDDEN', message: 'دسترسی مجاز نیست' },
});

const dbHealthStub = { ping: async (): Promise<void> => undefined };

let app: INestApplication;
let roleTokens: Readonly<Record<RoleCode, string>>;
let rolelessToken: string;
let unknownRoleToken: string;
let intersectionToken: string;
let productionRoutes: readonly ScannedRoute[];

function bearer(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

/** Test app mounts controllers without the main.ts global prefix. */
function actualPath(canonical: string): string {
  if (!canonical.startsWith(API_PREFIX)) {
    return canonical;
  }
  const stripped = canonical.slice(API_PREFIX.length);
  return stripped.length === 0 ? '/' : stripped;
}

interface ProbeRoute {
  readonly permission: PermissionName;
  readonly segment: string;
  readonly sensitive: boolean;
}

function probeOf(route: (typeof PROBE_ROUTES)[number]): ProbeRoute {
  return { ...route, sensitive: PERMISSIONS[route.permission].sensitive };
}

async function postProbe(
  probe: ProbeRoute,
  token?: string,
): Promise<{ readonly status: number; readonly body: unknown }> {
  let call = request(app.getHttpServer()).post(`/bfla-probe/${probe.segment}`);
  if (token !== undefined) {
    call = call.set(bearer(token));
  }
  const response = await call.send(probe.sensitive ? { reason: REASON } : {});
  return { status: response.status, body: response.body };
}

/** One enumerated production route, or a clear failure if it is missing. */
function productionRoute(method: string, path: string): ScannedRoute {
  const found = productionRoutes.find(
    (candidate) => candidate.method === method && candidate.path === path,
  );
  if (found === undefined) {
    throw new Error(`production route ${method} ${path} was not enumerated`);
  }
  return found;
}

/** Drives a real production route by its canonical scanned path. */
async function sendProduction(
  route: ScannedRoute,
  token?: string,
): Promise<{ readonly status: number; readonly body: unknown }> {
  const path = actualPath(route.path);
  const server = app.getHttpServer();
  let call = request(server).get(path);
  switch (route.method) {
    case 'GET':
      break;
    case 'PUT':
      call = request(server).put(path).set('x-bitabar-csrf', '1');
      break;
    case 'PATCH':
      call = request(server).patch(path).set('x-bitabar-csrf', '1');
      break;
    case 'DELETE':
      call = request(server).delete(path).set('x-bitabar-csrf', '1');
      break;
    default:
      // Cookie endpoints (refresh/logout) and login need no auth; the CSRF
      // header lets the cookie guard pass so their own 400/401 logic answers.
      call = request(server).post(path).set('x-bitabar-csrf', '1');
      break;
  }
  if (token !== undefined) {
    call = call.set(bearer(token));
  }
  const response = await call;
  return { status: response.status, body: response.body };
}

beforeAll(async () => {
  process.env.DATABASE_URL ??= 'postgresql://bitabar_app:dummy@localhost:5432/bitabar';
  process.env.PII_ENC_KEY ??= randomBytes(32).toString('base64');
  process.env.PII_HMAC_KEY ??= randomBytes(32).toString('base64');
  process.env.AUTH_TOKEN_SECRET ??= randomBytes(32).toString('base64');

  const moduleRef = await Test.createTestingModule({ imports: [AppModule, BflaProbeModule] })
    .overrideProvider(DbHealth)
    .useValue(dbHealthStub)
    .overrideProvider(AuthzFreshness)
    .useValue(freshness)
    // Unit test without a database (F1-06 T05): the sensitive audit path is
    // exercised by test/authz-audit.test.ts and the int suites.
    .overrideProvider(AUDIT_HOOK)
    .useValue({ record: async (): Promise<void> => undefined })
    .overrideProvider(TenantDb)
    .useValue({ run: async (fn: (tx: unknown) => Promise<unknown>) => fn(undefined) })
    .compile();
  app = moduleRef.createNestApplication();
  await app.init();

  const tokens = app.get(TokenService);
  roleTokens = {
    FACTORY_OPERATOR: await tokens.signAccessToken({
      userId: ROLE_USER_IDS.FACTORY_OPERATOR,
      tenantId: TENANT_ID,
      sessionId: SESSION_ID,
      roles: ['FACTORY_OPERATOR'],
    }),
    CARRIER_ADMIN: await tokens.signAccessToken({
      userId: ROLE_USER_IDS.CARRIER_ADMIN,
      tenantId: TENANT_ID,
      sessionId: SESSION_ID,
      roles: ['CARRIER_ADMIN'],
    }),
    DRIVER: await tokens.signAccessToken({
      userId: ROLE_USER_IDS.DRIVER,
      tenantId: TENANT_ID,
      sessionId: SESSION_ID,
      roles: ['DRIVER'],
    }),
  };
  rolelessToken = await tokens.signAccessToken({
    userId: ROLELESS_USER_ID,
    tenantId: TENANT_ID,
    sessionId: SESSION_ID,
    roles: [],
  });
  unknownRoleToken = await tokens.signAccessToken({
    userId: UNKNOWN_ROLE_USER_ID,
    tenantId: TENANT_ID,
    sessionId: SESSION_ID,
    roles: [UNKNOWN_ROLE],
  });
  intersectionToken = await tokens.signAccessToken({
    userId: INTERSECTION_USER_ID,
    tenantId: TENANT_ID,
    sessionId: SESSION_ID,
    roles: ['FACTORY_OPERATOR'],
  });

  productionRoutes = app
    .get(AuthzRouteDiscovery)
    .collect()
    .filter((route) =>
      (PRODUCTION_CONTROLLERS as readonly string[]).includes(route.controllerName),
    );
}, 60000);

afterAll(async () => {
  await app?.close();
});

describe('catalog probe surface', { timeout: 30000 }, () => {
  it('defines exactly one probe route per catalog permission, in catalog order', () => {
    expect(PROBE_ROUTES.map((route) => route.permission)).toEqual([...PERMISSION_NAMES]);
    expect(new Set(PROBE_ROUTES.map((route) => route.segment)).size).toBe(PERMISSION_NAMES.length);
    expect(Object.keys(roleTokens).sort()).toEqual([...ROLE_CODES].sort());
  });

  it('answers 401 to every anonymous permission probe', async () => {
    for (const route of PROBE_ROUTES) {
      const response = await postProbe(probeOf(route));
      expect(response.status, `anonymous ${route.permission}`).toBe(401);
    }
  });

  it('matches roleHasPermission for every role and every permission', async () => {
    for (const role of ROLE_CODES) {
      for (const route of PROBE_ROUTES) {
        const probe = probeOf(route);
        const response = await postProbe(probe, roleTokens[role]);
        const allowed = roleHasPermission(role, probe.permission);
        expect(response.status, `${role} ${probe.permission}`).toBe(allowed ? 200 : 403);
      }
    }
  });

  it('uses the token∩DB intersection on sensitive routes, not token roles alone', async () => {
    const sensitive = PROBE_ROUTES.filter((route) => PERMISSIONS[route.permission].sensitive);
    expect(sensitive.length).toBeGreaterThan(0);
    for (const route of sensitive) {
      const response = await postProbe(probeOf(route), intersectionToken);
      expect(response.status, `intersection ${route.permission}`).toBe(403);
    }
    // The same token is allowed on a non-sensitive route: that path trusts the
    // token role, while the sensitive path must intersect it with the DB.
    const nonSensitive = PROBE_ROUTES.find((route) => !PERMISSIONS[route.permission].sensitive);
    if (nonSensitive === undefined) {
      throw new Error('catalog has no non-sensitive permission');
    }
    expect((await postProbe(probeOf(nonSensitive), intersectionToken)).status).toBe(200);
  });

  it('denies a role-less and an unknown-role token on every permission route', async () => {
    const cases: readonly (readonly [string, string])[] = [
      ['role-less', rolelessToken],
      ['unknown-role', unknownRoleToken],
    ];
    for (const [label, token] of cases) {
      for (const route of PROBE_ROUTES) {
        const response = await postProbe(probeOf(route), token);
        expect(response.status, `${label} ${route.permission}`).toBe(403);
      }
    }
  });

  it('returns byte-identical denials that leak no permission, role or reason', async () => {
    const bodies: unknown[] = [];
    for (const role of ROLE_CODES) {
      for (const route of PROBE_ROUTES) {
        const probe = probeOf(route);
        if (roleHasPermission(role, probe.permission)) {
          continue;
        }
        bodies.push((await postProbe(probe, roleTokens[role])).body);
      }
    }
    for (const token of [rolelessToken, unknownRoleToken]) {
      for (const route of PROBE_ROUTES) {
        bodies.push((await postProbe(probeOf(route), token)).body);
      }
    }

    expect(bodies.length).toBeGreaterThan(0);
    const canonical = JSON.stringify(FORBIDDEN_BODY);
    for (const body of bodies) {
      expect(JSON.stringify(body)).toBe(canonical);
    }

    const serialized = JSON.stringify(bodies);
    for (const permission of PERMISSION_NAMES) {
      expect(serialized).not.toContain(permission);
    }
    for (const role of ROLE_CODES) {
      expect(serialized).not.toContain(role);
    }
    expect(serialized).not.toContain(UNKNOWN_ROLE);
    expect(serialized).not.toContain(REASON);
  });
});

describe('real production surface', { timeout: 30000 }, () => {
  it('enumerates a non-empty production route set with every marker kind', () => {
    expect(productionRoutes.length).toBeGreaterThan(0);
    expect(productionRoutes.filter((route) => route.isPublic).length).toBeGreaterThan(0);
    expect(productionRoutes.filter((route) => !route.isPublic).length).toBeGreaterThan(0);
    expect(productionRoutes.filter((route) => route.isSelfService).length).toBeGreaterThan(0);
    // Every production route is one of the enumerated entries; the loops below
    // iterate this exact set, so none can be skipped.
    expect(productionRoutes).toHaveLength(
      new Set(productionRoutes.map((route) => `${route.method} ${route.path}`)).size,
    );
  });

  it('answers 401 to an anonymous request on every non-public route', async () => {
    const nonPublic = productionRoutes.filter((route) => !route.isPublic);
    expect(nonPublic.length).toBeGreaterThan(0);
    for (const route of nonPublic) {
      const response = await sendProduction(route);
      expect(response.status, `${route.method} ${route.path}`).toBe(401);
    }
  });

  it('classifies the public routes with @Public in the scan', () => {
    for (const [method, path] of [
      ['GET', '/health/live'],
      ['GET', '/health/ready'],
      ['POST', '/api/v1/auth/login'],
      ['POST', '/api/v1/auth/refresh'],
      ['POST', '/api/v1/auth/logout'],
      ['POST', '/api/v1/auth/password/change'],
    ] as const) {
      expect(productionRoute(method, path).isPublic, `${method} ${path}`).toBe(true);
    }
  });

  it('answers health probes 200 and login without a body 400, anonymously', async () => {
    // The two health probes and login are the routes whose own logic has a
    // deterministic anonymous answer. Refresh/logout are @Public to the
    // authorization guard but CsrfGuard may legitimately answer 403 for a
    // missing CSRF header, so they are intentionally NOT status-asserted here.
    expect((await sendProduction(productionRoute('GET', '/health/live'))).status).toBe(200);
    expect((await sendProduction(productionRoute('GET', '/health/ready'))).status).toBe(200);
    // Login validates its own JSON content type/body; an empty body is a 400.
    expect((await sendProduction(productionRoute('POST', '/api/v1/auth/login'))).status).toBe(400);
  });

  it('role-checks every real production permission route that exists', async () => {
    // There are no production permission routes in F1-05, so this loop is empty
    // today. It is intentionally written against discovery data: the first
    // F1-07/F1-08 @RequirePermission route is role-tested without editing this
    // suite. A denied role must be 403 before any handler/pipe; an allowed role
    // may still fail its own validation (never 403/401).
    const permissionRoutes = productionRoutes.filter((route) => route.isPermission);
    for (const route of permissionRoutes) {
      const permission = route.permission;
      if (permission === null || !isPermissionName(permission)) {
        throw new Error(`permission route ${route.path} has no catalog permission`);
      }
      expect((await sendProduction(route)).status, `${route.method} ${route.path}`).toBe(401);
      for (const role of ROLE_CODES) {
        const response = await sendProduction(route, roleTokens[role]);
        const allowed = roleHasPermission(role, permission);
        if (allowed) {
          expect(response.status, `${role} ${route.method} ${route.path}`).not.toBe(403);
        } else {
          expect(response.status, `${role} ${route.method} ${route.path}`).toBe(403);
        }
      }
    }
  });

  it('allows every ROLE_CODES role on the @SelfService production route', async () => {
    const selfService = productionRoutes.filter((route) => route.isSelfService);
    expect(selfService.length).toBeGreaterThan(0);
    for (const route of selfService) {
      for (const role of ROLE_CODES) {
        const response = await sendProduction(route, roleTokens[role]);
        expect(response.status, `${role} ${route.method} ${route.path}`).toBe(200);
        expect((response.body as { data?: { id?: string } }).data?.id).toBe(ROLE_USER_IDS[role]);
      }
    }
  });
});

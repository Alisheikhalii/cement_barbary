import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import {
  Controller,
  Get,
  HttpCode,
  Module,
  Post,
  type INestApplication,
  type Type,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { AppModule } from '../../src/app.module.js';
import { DbHealth } from '../../src/db/db-health.js';
import { TokenService } from '../../src/modules/auth/token.service.js';
import {
  RequirePermission,
  ZodBody,
  ZodParams,
  ZodQuery,
} from '../../src/security/authz/decorators.js';
import {
  FORBIDDEN_INPUT_KEYS,
  scanInputSchema,
  type InputSurface,
} from '../../src/security/authz/input-scan.js';
import { AuthzRouteDiscovery } from '../../src/security/authz/route-discovery.js';
import {
  PRODUCTION_CONTROLLERS,
  scanRoutes,
  type ScannedRoute,
} from '../../src/security/authz/route-scan.js';

/** Non-sensitive permission used only to keep probe routes marker-valid. */
const TENANT_PERMISSION = 'destination.read';

/**
 * Mass-assignment proof (ADR-008 Z3/Z8, F1-05 T07). Three independent layers:
 *  1. pure scan — the walker rejects forbidden identity/status keys at every
 *     nesting depth and any non-strict object, on body, query and params;
 *  2. boot proof — a test-only probe module with such a schema prevents the
 *     app from starting;
 *  3. HTTP proof — the strict pipe rejects a request that adds `tenantId`/`role`.
 * The real production route set is also scanned clean. Docker-free throughout.
 */

const TENANT_ID = '00000000-0000-4000-8000-0000000000b1';
const SESSION_ID = '00000000-0000-4000-8000-0000000000b2';
const USER_ID = '00000000-0000-4000-8000-0000000000b3';

const SURFACES = ['body', 'query', 'params'] as const satisfies readonly InputSurface[];

const REVIEWED_FORBIDDEN_KEYS = [
  'role',
  'roles',
  'tenantId',
  'tenant_id',
  'carrierId',
  'carrier_id',
  'status',
  'userId',
  'createdBy',
] as const;

function codes(schema: unknown, surface: InputSurface = 'body'): readonly string[] {
  return scanInputSchema(schema, surface).map((issue) => issue.code);
}

function paths(schema: unknown, surface: InputSurface = 'body'): readonly string[] {
  return scanInputSchema(schema, surface).map((issue) => issue.path);
}

function route(overrides: Partial<ScannedRoute> = {}): ScannedRoute {
  return {
    moduleName: 'MassAssignmentProbeModule',
    controllerName: 'MassAssignmentProbeController',
    handlerName: 'handler',
    method: 'POST',
    path: '/api/v1/mass-assignment-probe',
    isPublic: false,
    isSelfService: false,
    isPermission: true,
    isIdempotent: true,
    classLevelMarker: false,
    permission: TENANT_PERMISSION,
    bodySchema: null,
    querySchema: null,
    paramsSchema: null,
    ...overrides,
  };
}

describe('mass-assignment scan — forbidden keys at every depth', () => {
  it('covers the reviewed forbidden key set', () => {
    for (const key of REVIEWED_FORBIDDEN_KEYS) {
      expect(FORBIDDEN_INPUT_KEYS as readonly string[]).toContain(key);
    }
  });

  it.each(FORBIDDEN_INPUT_KEYS)('rejects %s on body, query and params', (key) => {
    for (const surface of SURFACES) {
      const issues = scanInputSchema(z.strictObject({ [key]: z.string() }), surface);
      expect(
        issues.map((issue) => issue.code),
        `${surface} ${key}`,
      ).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
      expect(issues[0]?.path, `${surface} ${key}`).toBe(`${surface}.${key}`);
    }
  });

  it('rejects forbidden keys at nested object paths on every surface', () => {
    for (const surface of SURFACES) {
      const schema = z.strictObject({ nested: z.strictObject({ role: z.string() }) });
      expect(codes(schema, surface), surface).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
      expect(paths(schema, surface), surface).toEqual([`${surface}.nested.role`]);
    }
  });

  it('rejects forbidden keys inside arrays, records, unions and intersections', () => {
    const inArray = z.strictObject({ items: z.array(z.strictObject({ tenantId: z.string() })) });
    expect(codes(inArray)).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
    expect(paths(inArray)).toEqual(['body.items[].tenantId']);

    const inRecord = z.strictObject({
      byId: z.record(z.string(), z.strictObject({ carrierId: z.string() })),
    });
    expect(codes(inRecord)).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
    expect(paths(inRecord)).toEqual(['body.byId{*}.carrierId']);

    const inUnion = z.strictObject({
      variant: z.union([
        z.strictObject({ status: z.string() }),
        z.strictObject({ ok: z.string() }),
      ]),
    });
    expect(codes(inUnion)).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
    expect(paths(inUnion)).toEqual(['body.variant|0.status']);

    expect(
      codes(z.union([z.strictObject({ userId: z.string() }), z.strictObject({ ok: z.string() })])),
    ).toEqual(['AUTHZ_MASS_ASSIGNMENT']);

    expect(
      codes(
        z.intersection(
          z.strictObject({ name: z.string() }),
          z.strictObject({ createdBy: z.string() }),
        ),
      ),
    ).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
  });
});

describe('mass-assignment scan — strictness', () => {
  it('rejects non-strict objects at the top level and nested, on every surface', () => {
    for (const surface of SURFACES) {
      expect(codes(z.object({ name: z.string() }), surface), surface).toContain(
        'AUTHZ_NON_STRICT_INPUT',
      );
      expect(
        codes(z.strictObject({ nested: z.object({ name: z.string() }) }), surface),
        surface,
      ).toContain('AUTHZ_NON_STRICT_INPUT');
    }
  });

  it('accepts strict schemas on every surface', () => {
    for (const surface of SURFACES) {
      expect(
        scanInputSchema(z.strictObject({ displayName: z.string().min(1) }), surface),
        surface,
      ).toEqual([]);
      expect(
        scanInputSchema(
          z.strictObject({ page: z.coerce.number().int().min(1), sort: z.enum(['asc', 'desc']) }),
          surface,
        ),
        surface,
      ).toEqual([]);
    }
  });
});

describe('mass-assignment scan — scanRoutes wiring', () => {
  it('rejects forbidden keys in body, query and params schemas', () => {
    const codeOf = (overrides: Partial<ScannedRoute>): readonly string[] =>
      scanRoutes([route(overrides)], 'test').map((issue) => issue.code);
    expect(codeOf({ bodySchema: z.strictObject({ roles: z.array(z.string()) }) })).toContain(
      'AUTHZ_MASS_ASSIGNMENT',
    );
    expect(codeOf({ querySchema: z.strictObject({ tenant_id: z.string() }) })).toContain(
      'AUTHZ_MASS_ASSIGNMENT',
    );
    expect(codeOf({ paramsSchema: z.strictObject({ userId: z.string() }) })).toContain(
      'AUTHZ_MASS_ASSIGNMENT',
    );
    expect(codeOf({ bodySchema: z.object({ name: z.string() }) })).toContain(
      'AUTHZ_NON_STRICT_INPUT',
    );
    expect(codeOf({ querySchema: z.object({ page: z.string() }) })).toContain(
      'AUTHZ_NON_STRICT_INPUT',
    );
    expect(codeOf({ paramsSchema: z.object({ id: z.string() }) })).toContain(
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

/* ------------------------------------------------------------------ *
 * Boot proof: each forbidden surface is its own module so the startup
 * failure is attributable to the input scan, not to a marker/catalog issue.
 * ------------------------------------------------------------------ */

@Controller('mass-assignment-body-probe')
class MassAssignmentBodyProbeController {
  @RequirePermission('destination.read')
  @Post()
  handler(@ZodBody(z.strictObject({ roles: z.array(z.string()) })) body: { roles: string[] }): {
    ok: true;
  } {
    void body;
    return { ok: true };
  }
}

@Controller('mass-assignment-query-probe')
class MassAssignmentQueryProbeController {
  @RequirePermission('destination.read')
  @Get()
  handler(@ZodQuery(z.strictObject({ tenant_id: z.string() })) query: { tenant_id: string }): {
    ok: true;
  } {
    void query;
    return { ok: true };
  }
}

@Controller('mass-assignment-params-probe')
class MassAssignmentParamsProbeController {
  @RequirePermission('destination.read')
  @Get(':id')
  handler(@ZodParams(z.strictObject({ userId: z.string() })) params: { userId: string }): {
    ok: true;
  } {
    void params;
    return { ok: true };
  }
}

@Controller('mass-assignment-nonstrict-probe')
class MassAssignmentNonStrictProbeController {
  @RequirePermission('destination.read')
  @Get()
  handler(@ZodQuery(z.object({ page: z.string() })) query: { page: string }): { ok: true } {
    void query;
    return { ok: true };
  }
}

@Module({ controllers: [MassAssignmentBodyProbeController] })
class MassAssignmentBodyProbeModule {}

@Module({ controllers: [MassAssignmentQueryProbeController] })
class MassAssignmentQueryProbeModule {}

@Module({ controllers: [MassAssignmentParamsProbeController] })
class MassAssignmentParamsProbeModule {}

@Module({ controllers: [MassAssignmentNonStrictProbeController] })
class MassAssignmentNonStrictProbeModule {}

@Controller('mass-assignment-good-probe')
class MassAssignmentGoodProbeController {
  @HttpCode(200)
  @RequirePermission('destination.read')
  @Get('echo')
  echo(
    @ZodBody(z.strictObject({ displayName: z.string().min(1) })) body: { displayName: string },
  ): { displayName: string } {
    return { displayName: body.displayName };
  }
}

@Module({ controllers: [MassAssignmentGoodProbeController] })
class MassAssignmentGoodProbeModule {}

const dbHealthStub = { ping: async (): Promise<void> => undefined };

async function expectBootRejected(
  extraModules: readonly Type[],
  expectedCode: string,
): Promise<void> {
  const moduleRef = await Test.createTestingModule({ imports: [AppModule, ...extraModules] })
    .overrideProvider(DbHealth)
    .useValue(dbHealthStub)
    .compile();
  const app = moduleRef.createNestApplication();
  const issues = scanRoutes(app.get(AuthzRouteDiscovery).collect(), 'test');
  const found = issues.map((issue) => issue.code);
  expect(found).toContain(expectedCode);
  // The permission marker is valid, so the failure is the input scan alone.
  expect(found).not.toContain('AUTHZ_MARKER_COUNT');
  await expect(app.init()).rejects.toThrow(expectedCode);
  await app.close().catch(() => undefined);
}

describe('mass-assignment scan — boot refusal', { timeout: 30000 }, () => {
  it('refuses a forbidden key in a body schema', async () => {
    await expectBootRejected([MassAssignmentBodyProbeModule], 'AUTHZ_MASS_ASSIGNMENT');
  });

  it('refuses a forbidden key in a query schema', async () => {
    await expectBootRejected([MassAssignmentQueryProbeModule], 'AUTHZ_MASS_ASSIGNMENT');
  });

  it('refuses a forbidden key in a params schema', async () => {
    await expectBootRejected([MassAssignmentParamsProbeModule], 'AUTHZ_MASS_ASSIGNMENT');
  });

  it('refuses a non-strict input object', async () => {
    await expectBootRejected([MassAssignmentNonStrictProbeModule], 'AUTHZ_NON_STRICT_INPUT');
  });
});

/* ------------------------------------------------------------------ *
 * HTTP proof: the strict pipe strips nothing and rejects extra identity
 * fields in a request body.
 * ------------------------------------------------------------------ */

let app: INestApplication;
let accessToken: string;

beforeAll(async () => {
  process.env.DATABASE_URL ??= 'postgresql://bitabar_app:dummy@localhost:5432/bitabar';
  process.env.PII_ENC_KEY ??= randomBytes(32).toString('base64');
  process.env.PII_HMAC_KEY ??= randomBytes(32).toString('base64');
  process.env.AUTH_TOKEN_SECRET ??= randomBytes(32).toString('base64');

  const moduleRef = await Test.createTestingModule({
    imports: [AppModule, MassAssignmentGoodProbeModule],
  })
    .overrideProvider(DbHealth)
    .useValue(dbHealthStub)
    .compile();
  app = moduleRef.createNestApplication();
  await app.init();
  accessToken = await app.get(TokenService).signAccessToken({
    userId: USER_ID,
    tenantId: TENANT_ID,
    sessionId: SESSION_ID,
    roles: ['FACTORY_OPERATOR'],
  });
}, 60000);

afterAll(async () => {
  await app?.close();
});

describe('mass-assignment — HTTP strict-body rejection', { timeout: 30000 }, () => {
  it('accepts a body with only the reviewed fields', async () => {
    const response = await request(app.getHttpServer())
      .get('/mass-assignment-good-probe/echo')
      .set({ authorization: `Bearer ${accessToken}` })
      .send({ displayName: 'Barbary' })
      .expect(200);
    expect(response.body.data).toEqual({ displayName: 'Barbary' });
  });

  it('rejects a body that adds tenantId or role (strict pipe)', async () => {
    for (const extra of [{ tenantId: TENANT_ID }, { role: 'FACTORY_OPERATOR' }]) {
      const response = await request(app.getHttpServer())
        .get('/mass-assignment-good-probe/echo')
        .set({ authorization: `Bearer ${accessToken}` })
        .send({ displayName: 'Barbary', ...extra });
      expect(response.status, JSON.stringify(extra)).toBe(400);
    }
  });

  it('scans the real production route set clean', () => {
    const routes = app
      .get(AuthzRouteDiscovery)
      .collect()
      .filter((candidate) =>
        (PRODUCTION_CONTROLLERS as readonly string[]).includes(candidate.controllerName),
      );
    expect(routes.length).toBeGreaterThan(0);
    expect(scanRoutes(routes, 'test')).toEqual([]);
    expect(scanRoutes(routes, 'production')).toEqual([]);
  });
});

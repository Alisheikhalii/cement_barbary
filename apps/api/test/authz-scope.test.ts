import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import { Controller, Get, Module, Param, Req, type INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { Request } from 'express';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { AppModule } from '../src/app.module.js';
import { DomainError } from '../src/common/errors/domain-error.js';
import { APP_CONFIG } from '../src/config/config.module.js';
import { parseEnv, type AppConfig } from '../src/config/env.js';
import { DbHealth } from '../src/db/db-health.js';
import { TokenService } from '../src/modules/auth/token.service.js';
import {
  AccessScope,
  assertInScope,
  readAuthzContext,
  rowInScope,
  type ScopedRow,
} from '../src/security/authz/access-scope.js';
import { RequirePermission } from '../src/security/authz/decorators.js';
import { createPrincipal, createVerifiedPrincipal } from '../src/security/authz/principal.js';

/**
 * AccessScope scaffold (ADR-008 Z8, F1-05 T05). Proves:
 *  - a scope cannot be built from request data (branded, guard-attached);
 *  - carrier scope fails closed without a carrier id;
 *  - an absent row and an out-of-scope row produce the SAME generic 404;
 *  - the test-only probe module is refused by the production boot scan.
 *
 * The probe controller lives only in this test file; AppModule never imports
 * it, and the production-surface scan refuses it if it ever were imported.
 */

const TENANT_A = '00000000-0000-4000-8000-00000000000a';
const TENANT_B = '00000000-0000-4000-8000-00000000000b';
const USER_ID = '00000000-0000-4000-8000-000000000001';
const OTHER_USER = '00000000-0000-4000-8000-000000000002';
const SESSION_ID = '00000000-0000-4000-8000-000000000003';
const CARRIER_A = '00000000-0000-4000-8000-0000000000c1';
const CARRIER_B = '00000000-0000-4000-8000-0000000000c2';

interface ProbeRow extends ScopedRow {
  readonly id: string;
}

const ROWS: readonly ProbeRow[] = Object.freeze([
  { id: 'own-row', tenantId: TENANT_A, carrierId: null, ownerUserId: USER_ID },
  { id: 'other-tenant-row', tenantId: TENANT_B, carrierId: null, ownerUserId: USER_ID },
  {
    id: 'other-carrier-row',
    tenantId: TENANT_A,
    carrierId: CARRIER_B,
    ownerUserId: OTHER_USER,
  },
]);

@Controller('authz-scope-probe')
class AuthzScopeProbeController {
  @RequirePermission('destination.read')
  @Get('resources/:id')
  read(@Req() req: Request, @Param('id') id: string): ProbeRow {
    const { scope } = readAuthzContext(req);
    const row = ROWS.find((candidate) => candidate.id === id) ?? null;
    return assertInScope(scope, row);
  }
}

@Module({ controllers: [AuthzScopeProbeController] })
class AuthzScopeProbeModule {}

const dbHealthStub = { ping: async (): Promise<void> => undefined };

let app: INestApplication;
let productionApp: INestApplication | undefined;
let tenantAToken: string;
let tenantBToken: string;
let carrierToken: string;

function bearer(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

beforeAll(async () => {
  process.env.DATABASE_URL ??= 'postgresql://bitabar_app:dummy@localhost:5432/bitabar';
  process.env.PII_ENC_KEY ??= randomBytes(32).toString('base64');
  process.env.PII_HMAC_KEY ??= randomBytes(32).toString('base64');
  process.env.AUTH_TOKEN_SECRET ??= randomBytes(32).toString('base64');

  const moduleRef = await Test.createTestingModule({ imports: [AppModule, AuthzScopeProbeModule] })
    .overrideProvider(DbHealth)
    .useValue(dbHealthStub)
    .compile();
  app = moduleRef.createNestApplication();
  await app.init();

  const tokens = app.get(TokenService);
  tenantAToken = await tokens.signAccessToken({
    userId: USER_ID,
    tenantId: TENANT_A,
    sessionId: SESSION_ID,
    roles: ['FACTORY_OPERATOR'],
  });
  tenantBToken = await tokens.signAccessToken({
    userId: USER_ID,
    tenantId: TENANT_B,
    sessionId: SESSION_ID,
    roles: ['FACTORY_OPERATOR'],
  });
  carrierToken = await tokens.signAccessToken({
    userId: USER_ID,
    tenantId: TENANT_A,
    sessionId: SESSION_ID,
    roles: ['CARRIER_ADMIN'],
  });
}, 60000);

afterAll(async () => {
  await productionApp?.close().catch(() => undefined);
  await app?.close();
});

function principal(carrierId?: string) {
  return createVerifiedPrincipal({
    userId: USER_ID,
    tenantId: TENANT_A,
    sessionId: SESSION_ID,
    roles: ['FACTORY_OPERATOR'],
    ...(carrierId === undefined ? {} : { carrierId }),
  });
}

describe('AccessScope construction', () => {
  it('builds a tenant scope only from a verified principal', () => {
    const scope = AccessScope.forPermission(principal(), 'destination.read');
    expect(scope).toMatchObject({
      tenantId: TENANT_A,
      carrierId: null,
      driverUserId: null,
    });
  });

  it('fails closed for a carrier scope without a carrier id', () => {
    expect(() => AccessScope.fromPrincipal(principal(), 'carrier')).toThrow(DomainError);
    try {
      AccessScope.fromPrincipal(principal(), 'carrier');
    } catch (error) {
      expect(error).toMatchObject({ code: 'FORBIDDEN', statusCode: 403 });
    }
  });

  it('accepts a carrier scope only with a principal carrier id', () => {
    const scope = AccessScope.fromPrincipal(principal(CARRIER_A), 'carrier');
    expect(scope.carrierId).toBe(CARRIER_A);
    expect(scope.driverUserId).toBeNull();
  });

  it('builds an own scope from the principal user id', () => {
    const scope = AccessScope.fromPrincipal(principal(), 'own');
    expect(scope.driverUserId).toBe(USER_ID);
    expect(scope.carrierId).toBeNull();
  });

  it('rejects an object literal that merely looks like a scope', () => {
    const forged = { tenantId: TENANT_A, carrierId: null, driverUserId: null };
    expect(AccessScope.is(forged)).toBe(false);
    expect(rowInScope(forged as unknown as AccessScope, ROWS[0] as ProbeRow)).toBe(false);
    expect(() => assertInScope(forged as unknown as AccessScope, ROWS[0])).toThrow(DomainError);
  });

  it('rejects an unknown permission', () => {
    expect(() => AccessScope.forPermission(principal(), 'unknown.read' as never)).toThrow(
      DomainError,
    );
  });

  it('refuses to mint a scope from a plain, unverified principal', () => {
    const unverified = createPrincipal({
      userId: USER_ID,
      tenantId: TENANT_A,
      sessionId: SESSION_ID,
      roles: ['FACTORY_OPERATOR'],
    });
    expect(() => AccessScope.forPermission(unverified, 'destination.read')).toThrow(DomainError);
    expect(() => AccessScope.fromPrincipal(unverified, 'tenant')).toThrow(DomainError);
  });

  it('rejects a forged guard context instead of trusting request data', () => {
    const forgedScope = { tenantId: TENANT_A, carrierId: null, driverUserId: null };
    expect(() =>
      readAuthzContext({ authz: { principal: principal(), scope: forgedScope } }),
    ).toThrow(DomainError);
  });

  it('rejects a context whose principal did not come from the token path', () => {
    const scope = AccessScope.forPermission(principal(), 'destination.read');
    const unverified = createPrincipal({
      userId: USER_ID,
      tenantId: TENANT_A,
      sessionId: SESSION_ID,
      roles: ['FACTORY_OPERATOR'],
    });
    expect(() => readAuthzContext({ authz: { principal: unverified, scope } })).toThrow(
      DomainError,
    );
  });

  it('rejects a context whose scope belongs to another tenant', () => {
    const scope = AccessScope.forPermission(principal(), 'destination.read');
    const otherTenant = createVerifiedPrincipal({
      userId: USER_ID,
      tenantId: TENANT_B,
      sessionId: SESSION_ID,
      roles: ['FACTORY_OPERATOR'],
    });
    expect(() => readAuthzContext({ authz: { principal: otherTenant, scope } })).toThrow(
      DomainError,
    );
  });
});

describe('scope matching', () => {
  it('tenant scope matches only its tenant', () => {
    const scope = AccessScope.fromPrincipal(principal(), 'tenant');
    expect(rowInScope(scope, ROWS[0] as ProbeRow)).toBe(true);
    expect(rowInScope(scope, ROWS[1] as ProbeRow)).toBe(false);
  });

  it('carrier scope requires the exact carrier id', () => {
    const scope = AccessScope.fromPrincipal(principal(CARRIER_A), 'carrier');
    expect(rowInScope(scope, { tenantId: TENANT_A, carrierId: CARRIER_A })).toBe(true);
    expect(rowInScope(scope, { tenantId: TENANT_A, carrierId: CARRIER_B })).toBe(false);
    expect(rowInScope(scope, { tenantId: TENANT_A, carrierId: null })).toBe(false);
  });

  it('own scope requires the exact owner', () => {
    const scope = AccessScope.fromPrincipal(principal(), 'own');
    expect(rowInScope(scope, { tenantId: TENANT_A, ownerUserId: USER_ID })).toBe(true);
    expect(rowInScope(scope, { tenantId: TENANT_A, ownerUserId: OTHER_USER })).toBe(false);
  });

  it('returns the generic 404 for both an absent row and an out-of-scope row', () => {
    const scope = AccessScope.fromPrincipal(principal(), 'tenant');
    const missing = (): unknown => assertInScope(scope, null);
    const outside = (): unknown => assertInScope(scope, ROWS[1]);
    for (const call of [missing, outside]) {
      try {
        call();
        expect.unreachable('expected a DomainError');
      } catch (error) {
        expect(error).toBeInstanceOf(DomainError);
        expect(error).toMatchObject({
          code: 'NOT_FOUND',
          statusCode: 404,
          message: 'مسیر مورد نظر یافت نشد',
        });
      }
    }
  });
});

describe('guard-attached scope over HTTP', () => {
  it('returns an in-scope row and hides an out-of-scope row', async () => {
    const own = await request(app.getHttpServer())
      .get('/authz-scope-probe/resources/own-row')
      .set(bearer(tenantAToken))
      .expect(200);
    expect(own.body.data.id).toBe('own-row');

    const other = await request(app.getHttpServer())
      .get('/authz-scope-probe/resources/other-tenant-row')
      .set(bearer(tenantAToken))
      .expect(404);
    const missing = await request(app.getHttpServer())
      .get('/authz-scope-probe/resources/no-such-row')
      .set(bearer(tenantAToken))
      .expect(404);

    expect(other.body).toEqual(missing.body);
    expect(JSON.stringify(other.body)).toBe(
      JSON.stringify({ error: { code: 'NOT_FOUND', message: 'مسیر مورد نظر یافت نشد' } }),
    );
    expect(JSON.stringify(other.body)).not.toContain('other-tenant-row');
    expect(JSON.stringify(other.body)).not.toContain(TENANT_B);
  });

  it('hides tenant A rows from a tenant B principal and vice versa', async () => {
    const fromB = await request(app.getHttpServer())
      .get('/authz-scope-probe/resources/own-row')
      .set(bearer(tenantBToken))
      .expect(404);
    const fromA = await request(app.getHttpServer())
      .get('/authz-scope-probe/resources/other-tenant-row')
      .set(bearer(tenantAToken))
      .expect(404);
    expect(fromB.body).toEqual(fromA.body);
  });

  it('answers 401 before scope resolution and 403 before the handler', async () => {
    await request(app.getHttpServer()).get('/authz-scope-probe/resources/own-row').expect(401);

    const denied = await request(app.getHttpServer())
      .get('/authz-scope-probe/resources/own-row')
      .set(bearer(carrierToken))
      .expect(403);
    expect(denied.body).toEqual({
      error: { code: 'FORBIDDEN', message: 'دسترسی مجاز نیست' },
    });
  });

  it('never attaches a scope when the permission check fails', async () => {
    // A carrier token reaches the guard but has no destination.read permission.
    // The handler must never run, so its body cannot leak the in-memory rows.
    const denied = await request(app.getHttpServer())
      .get('/authz-scope-probe/resources/own-row')
      .set(bearer(carrierToken))
      .expect(403);
    expect(JSON.stringify(denied.body)).not.toContain('own-row');
  });
});

describe('production surface', () => {
  it('refuses to load the test-only probe module in production', async () => {
    const productionConfig: AppConfig = parseEnv({
      NODE_ENV: 'production',
      DATABASE_URL: 'postgresql://bitabar_app:dummy@localhost:5432/bitabar',
      PII_ENC_KEY: randomBytes(32).toString('base64'),
      PII_HMAC_KEY: randomBytes(32).toString('base64'),
      AUTH_TOKEN_SECRET: randomBytes(32).toString('base64'),
    });
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule, AuthzScopeProbeModule],
    })
      .overrideProvider(DbHealth)
      .useValue(dbHealthStub)
      .overrideProvider(APP_CONFIG)
      .useValue(productionConfig)
      .compile();
    productionApp = moduleRef.createNestApplication();
    await expect(productionApp.init()).rejects.toThrow(/AUTHZ_PRODUCTION_(CONTROLLER|MODULE)/);
  });
});

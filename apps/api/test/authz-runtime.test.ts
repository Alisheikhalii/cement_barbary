import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import { Controller, Get, Module, type INestApplication } from '@nestjs/common';
import { APP_GUARD, ApplicationConfig } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { AppModule } from '../src/app.module.js';
import { DbHealth } from '../src/db/db-health.js';
import { AuthGuard } from '../src/modules/auth/auth.guard.js';
import { AuthModule } from '../src/modules/auth/auth.module.js';
import { TokenService } from '../src/modules/auth/token.service.js';
import { AuthorizationGuard } from '../src/security/authz/authorization.guard.js';
import { AuthzBootCheck } from '../src/security/authz/authz-boot.check.js';
import { AuthzModule } from '../src/security/authz/authz.module.js';
import {
  IS_PUBLIC_KEY,
  Public,
  RequirePermission,
  SelfService,
} from '../src/security/authz/decorators.js';

/**
 * Runtime authorization (ADR-008 Z3/Z4; owner C2/C5/C6; CP1 BF-04). Boots the
 * real AppModule (Docker-free) and a fixture module whose intentionally broken
 * routes bypass the boot check, proving the guard still fails closed.
 */
const USER_ID = '00000000-0000-4000-8000-000000000001';
const TENANT_ID = '00000000-0000-4000-8000-000000000002';
const SESSION_ID = '00000000-0000-4000-8000-000000000003';
const CHANGE_FINGERPRINT = 'a'.repeat(43);

let app: INestApplication;
let fixtureApp: INestApplication;
let tokens: TokenService;

let operatorToken: string;
let carrierToken: string;
let driverToken: string;
let rolelessToken: string;
let unknownRoleToken: string;
let duplicateRoleToken: string;
let duplicateDriverToken: string;
let changeToken: string;

const dbHealthStub = { ping: vi.fn<() => Promise<void>>() };

@Controller('authz-probe')
class AuthzProbeController {
  @RequirePermission('destination.read')
  @Get('permission')
  permission(): { ok: true } {
    return { ok: true };
  }

  @Get('unmarked')
  unmarked(): { ok: true } {
    return { ok: true };
  }

  @Public()
  @RequirePermission('destination.read')
  @Get('duplicate')
  duplicate(): { ok: true } {
    return { ok: true };
  }

  @Public()
  @Get('public-not-allowed')
  publicNotAllowed(): { ok: true } {
    return { ok: true };
  }
}

@Module({ controllers: [AuthzProbeController] })
class AuthzProbeModule {}

@Controller('authz-class-marker')
class ClassMarkedProbeController {
  @SelfService()
  @Get()
  read(): { ok: true } {
    return { ok: true };
  }
}
Reflect.defineMetadata(IS_PUBLIC_KEY, true, ClassMarkedProbeController);

@Module({ controllers: [ClassMarkedProbeController] })
class ClassMarkedProbeModule {}

function bearer(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

async function sign(service: TokenService, roles: readonly string[]): Promise<string> {
  return service.signAccessToken({
    userId: USER_ID,
    tenantId: TENANT_ID,
    sessionId: SESSION_ID,
    roles,
  });
}

beforeAll(async () => {
  process.env.DATABASE_URL ??= 'postgresql://bitabar_app:dummy@localhost:5432/bitabar';
  process.env.PII_ENC_KEY ??= randomBytes(32).toString('base64');
  process.env.PII_HMAC_KEY ??= randomBytes(32).toString('base64');
  process.env.AUTH_TOKEN_SECRET ??= randomBytes(32).toString('base64');

  const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(DbHealth)
    .useValue(dbHealthStub)
    .compile();
  app = moduleRef.createNestApplication();
  await app.init();
  tokens = app.get(TokenService);

  operatorToken = await sign(tokens, ['FACTORY_OPERATOR']);
  carrierToken = await sign(tokens, ['CARRIER_ADMIN']);
  driverToken = await sign(tokens, ['DRIVER']);
  rolelessToken = await sign(tokens, []);
  unknownRoleToken = await sign(tokens, ['SUPERUSER']);
  duplicateRoleToken = await sign(tokens, ['FACTORY_OPERATOR', 'FACTORY_OPERATOR']);
  duplicateDriverToken = await sign(tokens, ['DRIVER', 'DRIVER']);
  changeToken = await tokens.signPasswordChangeToken({
    userId: USER_ID,
    tenantId: TENANT_ID,
    fingerprint: CHANGE_FINGERPRINT,
  });

  // The fixture module intentionally violates the surface contract; override
  // the boot assertion so the runtime guard itself is exercised (C5/C6).
  const fixtureRef = await Test.createTestingModule({
    imports: [AppModule, AuthzProbeModule, ClassMarkedProbeModule],
  })
    .overrideProvider(DbHealth)
    .useValue(dbHealthStub)
    .overrideProvider(AuthzBootCheck)
    .useValue({ onModuleInit: () => undefined })
    .compile();
  fixtureApp = fixtureRef.createNestApplication();
  await fixtureApp.init();
}, 60000);

afterAll(async () => {
  await fixtureApp?.close();
  await app?.close();
});

describe('guard registration order', () => {
  it('registers and executes AuthGuard before AuthorizationGuard', () => {
    const imports = Reflect.getMetadata('imports', AppModule) as unknown[];
    expect(imports.indexOf(AuthModule)).toBeGreaterThanOrEqual(0);
    expect(imports.indexOf(AuthzModule)).toBeGreaterThanOrEqual(0);
    expect(imports.indexOf(AuthModule)).toBeLessThan(imports.indexOf(AuthzModule));

    const authzGuardProvider = (
      Reflect.getMetadata('providers', AuthModule) as {
        provide?: unknown;
        useClass?: unknown;
      }[]
    ).find((provider) => provider.provide === APP_GUARD);
    expect(authzGuardProvider?.useClass).toBe(AuthGuard);

    const authorizationGuardProvider = (
      Reflect.getMetadata('providers', AuthzModule) as {
        provide?: unknown;
        useClass?: unknown;
      }[]
    ).find((provider) => provider.provide === APP_GUARD);
    expect(authorizationGuardProvider?.useClass).toBe(AuthorizationGuard);

    const executableOrder = app
      .get(ApplicationConfig)
      .getGlobalGuards()
      .map((guard) => guard.constructor.name);
    expect(executableOrder).toEqual(['AuthGuard', 'AuthorizationGuard']);
  });
});

describe('existing routes', () => {
  it('keeps health public', async () => {
    await request(app.getHttpServer()).get('/health/live').expect(200);
  });

  it('answers 401 before 403 for an anonymous protected route', async () => {
    const res = await request(app.getHttpServer()).get('/auth/me').expect(401);
    expect(res.body).toEqual({
      error: { code: 'UNAUTHORIZED', message: 'احراز هویت نامعتبر است' },
    });
  });

  it('lets every authenticated role use @SelfService', async () => {
    for (const token of [operatorToken, carrierToken, driverToken, rolelessToken]) {
      const res = await request(app.getHttpServer()).get('/auth/me').set(bearer(token)).expect(200);
      expect(res.body.data.id).toBe(USER_ID);
    }
  });

  it('rejects the forced-change token on a protected route', async () => {
    const res = await request(app.getHttpServer())
      .get('/auth/me')
      .set(bearer(changeToken))
      .expect(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });
});

describe('permission decisions', () => {
  it('allows the operator and denies carrier/driver with an identical 403', async () => {
    await request(fixtureApp.getHttpServer())
      .get('/authz-probe/permission')
      .set(bearer(operatorToken))
      .expect(200);

    const carrier = await request(fixtureApp.getHttpServer())
      .get('/authz-probe/permission')
      .set(bearer(carrierToken))
      .expect(403);
    const driver = await request(fixtureApp.getHttpServer())
      .get('/authz-probe/permission')
      .set(bearer(driverToken))
      .expect(403);
    expect(carrier.body).toEqual(driver.body);
  });

  it('denies a role-less principal and an unknown role', async () => {
    for (const token of [rolelessToken, unknownRoleToken]) {
      await request(fixtureApp.getHttpServer())
        .get('/authz-probe/permission')
        .set(bearer(token))
        .expect(403);
    }
  });

  it('duplicate role codes in the token cannot inflate the role set (BF-04)', async () => {
    await request(fixtureApp.getHttpServer())
      .get('/authz-probe/permission')
      .set(bearer(duplicateRoleToken))
      .expect(200);
    // Repeating a role that does NOT grant the permission still grants nothing.
    await request(fixtureApp.getHttpServer())
      .get('/authz-probe/permission')
      .set(bearer(duplicateDriverToken))
      .expect(403);
  });

  it('rejects the forced-change token before any permission check', async () => {
    await request(fixtureApp.getHttpServer())
      .get('/authz-probe/permission')
      .set(bearer(changeToken))
      .expect(401);
  });
});

describe('invalid markers at runtime (C5/C6)', () => {
  it('answers 401 without a token and 403 with one on an unmarked route', async () => {
    await request(fixtureApp.getHttpServer()).get('/authz-probe/unmarked').expect(401);
    await request(fixtureApp.getHttpServer())
      .get('/authz-probe/unmarked')
      .set(bearer(operatorToken))
      .expect(403);
  });

  it('answers 403 for a route with two markers', async () => {
    await request(fixtureApp.getHttpServer())
      .get('/authz-probe/duplicate')
      .set(bearer(operatorToken))
      .expect(403);
  });

  it('answers 403 when the marker is on the controller class', async () => {
    await request(fixtureApp.getHttpServer())
      .get('/authz-class-marker')
      .set(bearer(operatorToken))
      .expect(403);
  });

  it('answers 403 for a public route outside the §D allowlist', async () => {
    await request(fixtureApp.getHttpServer()).get('/authz-probe/public-not-allowed').expect(403);
  });

  it('returns byte-identical generic bodies for every denial', async () => {
    const bodies = await Promise.all([
      request(fixtureApp.getHttpServer()).get('/authz-probe/permission').set(bearer(carrierToken)),
      request(fixtureApp.getHttpServer()).get('/authz-probe/unmarked').set(bearer(operatorToken)),
      request(fixtureApp.getHttpServer()).get('/authz-probe/duplicate').set(bearer(operatorToken)),
      request(fixtureApp.getHttpServer()).get('/authz-probe/public-not-allowed'),
    ]);
    for (const body of bodies) {
      expect(body.status).toBe(403);
      expect(JSON.stringify(body.body)).toBe(
        JSON.stringify({ error: { code: 'FORBIDDEN', message: 'دسترسی مجاز نیست' } }),
      );
    }
  });
});

import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import { Controller, Get, Module, type INestApplication, type Type } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { AppModule } from '../src/app.module.js';
import { APP_CONFIG } from '../src/config/config.module.js';
import { parseEnv, type AppConfig } from '../src/config/env.js';
import { DbHealth } from '../src/db/db-health.js';
import { AuthzRouteDiscovery } from '../src/security/authz/route-discovery.js';
import { scanControllers, scanRoutes } from '../src/security/authz/route-scan.js';
import {
  IS_PUBLIC_KEY,
  Public,
  RequirePermission,
  SelfService,
  ZodBody,
} from '../src/security/authz/decorators.js';

/**
 * Boot assertion over the real DiscoveryService (ADR-008 Z3; owner C5/C6;
 * CP1 GB-03/GB-04, RD-03, SA-05). Every broken fixture below must make
 * `app.init()` reject; the real module must boot cleanly in test and
 * production configurations.
 */

const SENSITIVE_PERMISSION = 'carrier_membership.write';

@Controller('boot-unmarked')
class UnmarkedController {
  @Get()
  list(): { ok: true } {
    return { ok: true };
  }
}

@Controller('boot-duplicate')
class DuplicateMarkerController {
  @Public()
  @SelfService()
  @Get()
  read(): { ok: true } {
    return { ok: true };
  }
}

@Controller('boot-class-marker')
class ClassMarkedController {
  @SelfService()
  @Get()
  read(): { ok: true } {
    return { ok: true };
  }
}
Reflect.defineMetadata(IS_PUBLIC_KEY, true, ClassMarkedController);

@Controller('boot-extra-public')
class ExtraPublicController {
  @Public()
  @Get()
  read(): { ok: true } {
    return { ok: true };
  }
}

@Controller('boot-extra-self-service')
class ExtraSelfServiceController {
  @SelfService()
  @Get()
  read(): { ok: true } {
    return { ok: true };
  }
}

@Controller('boot-sensitive')
class BadSensitiveController {
  @RequirePermission(SENSITIVE_PERMISSION)
  @Get()
  write(@ZodBody(z.strictObject({ reason: z.string() })) body: { reason: string }): {
    reason: string;
  } {
    return body;
  }
}

@Controller('probe-fixture')
class ProbeFixtureController {
  @SelfService()
  @Get()
  read(): { ok: true } {
    return { ok: true };
  }
}

/** A probe controller with no route handlers: only the controller scan sees it. */
@Controller('probe-empty')
class ProbeEmptyController {}

@Module({ controllers: [UnmarkedController] })
class UnmarkedModule {}

@Module({ controllers: [DuplicateMarkerController] })
class DuplicateMarkerModule {}

@Module({ controllers: [ClassMarkedController] })
class ClassMarkedModule {}

@Module({ controllers: [ExtraPublicController] })
class ExtraPublicModule {}

@Module({ controllers: [ExtraSelfServiceController] })
class ExtraSelfServiceModule {}

@Module({ controllers: [BadSensitiveController] })
class BadSensitiveModule {}

@Module({ controllers: [ProbeFixtureController] })
class ProbeFixtureModule {}

@Module({ controllers: [ProbeEmptyController] })
class ProbeEmptyModule {}

const dbHealthStub = { ping: async (): Promise<void> => undefined };

const openApps: INestApplication[] = [];

beforeAll(() => {
  process.env.DATABASE_URL ??= 'postgresql://bitabar_app:dummy@localhost:5432/bitabar';
  process.env.PII_ENC_KEY ??= randomBytes(32).toString('base64');
  process.env.PII_HMAC_KEY ??= randomBytes(32).toString('base64');
  process.env.AUTH_TOKEN_SECRET ??= randomBytes(32).toString('base64');
});

afterEach(async () => {
  while (openApps.length > 0) {
    const app = openApps.pop();
    await app?.close().catch(() => undefined);
  }
});

function productionConfig(): AppConfig {
  return parseEnv({
    NODE_ENV: 'production',
    DATABASE_URL: 'postgresql://bitabar_app:dummy@localhost:5432/bitabar',
    PII_ENC_KEY: randomBytes(32).toString('base64'),
    PII_HMAC_KEY: randomBytes(32).toString('base64'),
    AUTH_TOKEN_SECRET: randomBytes(32).toString('base64'),
  });
}

async function buildApp(
  extraModules: readonly Type[] = [],
  config?: AppConfig,
): Promise<INestApplication> {
  const builder = Test.createTestingModule({ imports: [AppModule, ...extraModules] })
    .overrideProvider(DbHealth)
    .useValue(dbHealthStub);
  if (config !== undefined) {
    builder.overrideProvider(APP_CONFIG).useValue(config);
  }
  const moduleRef = await builder.compile();
  const app = moduleRef.createNestApplication();
  openApps.push(app);
  return app;
}

async function expectBootFailure(
  extraModules: readonly Type[],
  code: string,
  config?: AppConfig,
): Promise<void> {
  const app = await buildApp(extraModules, config);
  // (a) the route scan over the real DiscoveryService reports the throwaway
  // controller, and (b) the boot assertion refuses to start (C5/C6).
  const environment = config?.nodeEnv ?? 'test';
  const issues = scanRoutes(app.get(AuthzRouteDiscovery).collect(), environment);
  expect(issues.map((issue) => issue.code)).toContain(code);
  await expect(app.init()).rejects.toThrow(code);
}

describe('route surface', { timeout: 30000 }, () => {
  it('boots the real module and locks the §D route classification', async () => {
    const app = await buildApp();
    await app.init();
    const routes = app.get(AuthzRouteDiscovery).collect();
    expect(routes.map((route) => `${route.method} ${route.path}`).sort()).toEqual([
      'GET /api/v1/auth/me',
      'GET /health/live',
      'GET /health/ready',
      'POST /api/v1/auth/login',
      'POST /api/v1/auth/logout',
      'POST /api/v1/auth/password/change',
      'POST /api/v1/auth/refresh',
    ]);
    for (const route of routes) {
      if (route.path === '/api/v1/auth/me') {
        expect(route.isSelfService, route.path).toBe(true);
        expect(route.isPublic, route.path).toBe(false);
      } else {
        expect(route.isPublic, route.path).toBe(true);
        expect(route.isSelfService, route.path).toBe(false);
      }
      expect(route.classLevelMarker, route.path).toBe(false);
    }
  });

  it('boots the real module with production config', async () => {
    const app = await buildApp([], productionConfig());
    await expect(app.init()).resolves.toBeDefined();
  });
});

describe('boot refusal — negative controls (C5/C6)', () => {
  it('refuses an unlabeled controller', async () => {
    await expectBootFailure([UnmarkedModule], 'AUTHZ_MARKER_COUNT');
  });

  it('refuses a handler with two markers', async () => {
    await expectBootFailure([DuplicateMarkerModule], 'AUTHZ_MARKER_COUNT');
  });

  it('refuses a class-level marker', async () => {
    await expectBootFailure([ClassMarkedModule], 'AUTHZ_CLASS_LEVEL_MARKER');
  });

  it('refuses a public route outside the §D allowlist (GB-03)', async () => {
    await expectBootFailure([ExtraPublicModule], 'AUTHZ_PUBLIC_NOT_ALLOWLISTED');
  });

  it('refuses a self-service route outside the reviewed allowlist (F1-06 T03)', async () => {
    await expectBootFailure([ExtraSelfServiceModule], 'AUTHZ_SELF_SERVICE_NOT_ALLOWLISTED');
  });

  it('refuses a sensitive route whose body does not validate reason (SA-05)', async () => {
    await expectBootFailure([BadSensitiveModule], 'AUTHZ_SENSITIVE_REASON');
  });

  it('refuses a probe module/controller in production (RD-03)', async () => {
    const app = await buildApp([ProbeFixtureModule], productionConfig());
    await expect(app.init()).rejects.toThrow(/AUTHZ_PRODUCTION_(CONTROLLER|MODULE)/);
  });

  it('refuses a probe controller with no routes in production (RD-03)', async () => {
    const app = await buildApp([ProbeEmptyModule], productionConfig());
    const discovery = app.get(AuthzRouteDiscovery);
    const routes = discovery.collect();
    const controllers = discovery.collectControllers();
    expect(scanControllers(controllers, routes, 'production').map((issue) => issue.code)).toContain(
      'AUTHZ_PRODUCTION_CONTROLLER',
    );
    await expect(app.init()).rejects.toThrow(/AUTHZ_PRODUCTION/);
  });
});

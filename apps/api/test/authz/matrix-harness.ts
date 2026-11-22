import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';

import { AppModule } from '../../src/app.module.js';
import { DbHealth } from '../../src/db/db-health.js';
import { PRODUCTION_CONTROLLERS, type ScannedRoute } from '../../src/security/authz/route-scan.js';
import { AuthzRouteDiscovery } from '../../src/security/authz/route-discovery.js';

/**
 * Shared harness for the permission-matrix script and sync test (F1-05 T07).
 * Docker-free: the app boots with a stubbed health check, exactly like the
 * route-scan tests. No HTTP listener is opened.
 */
export async function buildMatrixApp(): Promise<INestApplication> {
  process.env.DATABASE_URL ??= 'postgresql://bitabar_app:dummy@localhost:5432/bitabar';
  process.env.PII_ENC_KEY ??= randomBytes(32).toString('base64');
  process.env.PII_HMAC_KEY ??= randomBytes(32).toString('base64');
  process.env.AUTH_TOKEN_SECRET ??= randomBytes(32).toString('base64');

  const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(DbHealth)
    .useValue({ ping: async (): Promise<void> => undefined })
    .compile();
  const app = moduleRef.createNestApplication();
  await app.init();
  return app;
}

/** The same production route set the boot scan checks (RD-03). */
export function collectProductionRoutes(app: INestApplication): readonly ScannedRoute[] {
  return app
    .get(AuthzRouteDiscovery)
    .collect()
    .filter((route) =>
      (PRODUCTION_CONTROLLERS as readonly string[]).includes(route.controllerName),
    );
}

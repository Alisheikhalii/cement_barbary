import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import { RequestMethod, type INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { API_PREFIX } from '@bitabar/shared';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { AppModule } from '../src/app.module.js';
import { APP_CONFIG } from '../src/config/config.module.js';
import { parseEnv, type AppConfig } from '../src/config/env.js';
import { DbHealth } from '../src/db/db-health.js';
import { isAllowlistedPublicRoute } from '../src/security/authz/route-scan.js';

/**
 * Public-route path confusion (owner CP2 fix 2). Each row must either reach a
 * public handler only after BOTH Express routing and the guard allow it, or be
 * rejected. No row may be public in the guard while routed to a protected
 * handler. 400 = the public login handler's JSON/body check ran; 403 = the
 * guard rejected the path; 404 = Express did not route it.
 */
interface PathCase {
  readonly method: 'GET' | 'POST';
  readonly path: string;
  readonly testStatus: number;
  readonly productionStatus: number;
  readonly allowlisted: boolean;
  readonly note: string;
}

const CASES: readonly PathCase[] = [
  {
    method: 'POST',
    path: '/api/v1/auth/login',
    testStatus: 400,
    productionStatus: 400,
    allowlisted: true,
    note: 'canonical path: guard allows in both modes',
  },
  {
    method: 'POST',
    path: '/api/v1/auth/login/',
    testStatus: 400,
    productionStatus: 400,
    allowlisted: true,
    note: 'one trailing slash: Express and guard normalize identically',
  },
  {
    method: 'POST',
    path: '/API/V1/AUTH/LOGIN',
    testStatus: 403,
    productionStatus: 403,
    allowlisted: false,
    note: 'uppercase: Express matches case-insensitively, guard rejects',
  },
  {
    method: 'POST',
    path: '/api/v1/auth/login/../me',
    testStatus: 404,
    productionStatus: 404,
    allowlisted: false,
    note: 'dot segment: Express does not route it',
  },
  {
    method: 'GET',
    path: '/api/v1/auth/login/../me',
    testStatus: 404,
    productionStatus: 404,
    allowlisted: false,
    note: 'dot segment to the protected /me',
  },
  {
    method: 'POST',
    path: '/api/v1/auth/login/%2e%2e/me',
    testStatus: 404,
    productionStatus: 404,
    allowlisted: false,
    note: 'percent-encoded dot segments',
  },
  {
    method: 'POST',
    path: '/api/v1/auth/login%2F..%2Fme',
    testStatus: 404,
    productionStatus: 404,
    allowlisted: false,
    note: 'encoded slash',
  },
  {
    method: 'POST',
    path: '/api/v1/auth/login;foo=bar',
    testStatus: 404,
    productionStatus: 404,
    allowlisted: false,
    note: 'matrix/param suffix',
  },
  {
    method: 'POST',
    path: '//api/v1/auth/login',
    testStatus: 404,
    productionStatus: 404,
    allowlisted: false,
    note: 'double slash: guard no longer collapses it',
  },
  {
    method: 'POST',
    path: '/api/v1/auth/login.',
    testStatus: 404,
    productionStatus: 404,
    allowlisted: false,
    note: 'trailing dot',
  },
  {
    method: 'POST',
    path: '/api/v1/auth/login/..',
    testStatus: 404,
    productionStatus: 404,
    allowlisted: false,
    note: 'trailing dot segment',
  },
];

function productionConfig(): AppConfig {
  return parseEnv({
    NODE_ENV: 'production',
    DATABASE_URL: 'postgresql://bitabar_app:dummy@localhost:5432/bitabar',
    PII_ENC_KEY: randomBytes(32).toString('base64'),
    PII_HMAC_KEY: randomBytes(32).toString('base64'),
    AUTH_TOKEN_SECRET: randomBytes(32).toString('base64'),
  });
}

async function build(config?: AppConfig): Promise<INestApplication> {
  process.env.DATABASE_URL ??= 'postgresql://bitabar_app:dummy@localhost:5432/bitabar';
  process.env.PII_ENC_KEY ??= randomBytes(32).toString('base64');
  process.env.PII_HMAC_KEY ??= randomBytes(32).toString('base64');
  process.env.AUTH_TOKEN_SECRET ??= randomBytes(32).toString('base64');
  const builder = Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(DbHealth)
    .useValue({ ping: async () => undefined });
  if (config !== undefined) {
    builder.overrideProvider(APP_CONFIG).useValue(config);
  }
  const moduleRef = await builder.compile();
  const app = moduleRef.createNestApplication();
  app.setGlobalPrefix(API_PREFIX, {
    exclude: [
      { path: 'health', method: RequestMethod.ALL },
      { path: 'health/{*splat}', method: RequestMethod.ALL },
    ],
  });
  await app.init();
  return app;
}

function call(app: INestApplication, pathCase: PathCase): request.Test {
  const server = app.getHttpServer();
  return pathCase.method === 'GET'
    ? request(server).get(pathCase.path)
    : request(server).post(pathCase.path);
}

let testApp: INestApplication;
let productionApp: INestApplication;

beforeAll(async () => {
  testApp = await build();
  productionApp = await build(productionConfig());
}, 60000);

afterAll(async () => {
  await productionApp?.close();
  await testApp?.close();
});

describe('public-route path confusion', () => {
  it.each(CASES)('$method $path — $note', async (pathCase) => {
    const testResponse = await call(testApp, pathCase);
    const productionResponse = await call(productionApp, pathCase);
    expect(testResponse.status, `test ${pathCase.path}`).toBe(pathCase.testStatus);
    expect(productionResponse.status, `production ${pathCase.path}`).toBe(
      pathCase.productionStatus,
    );
    // The helper must agree with the status class; 400 means the public handler ran.
    expect(isAllowlistedPublicRoute(pathCase.method, pathCase.path, 'test')).toBe(
      pathCase.allowlisted,
    );
    expect(isAllowlistedPublicRoute(pathCase.method, pathCase.path, 'production')).toBe(
      pathCase.allowlisted,
    );
    expect([200, 201, 204]).not.toContain(testResponse.status);
    expect([200, 201, 204]).not.toContain(productionResponse.status);
  });

  it('rejects the unprefixed form in production but allows it in test', async () => {
    // This app is mounted without the global prefix for this pair only.
    const unprefixedTest = await buildUnprefixed();
    const unprefixedProduction = await buildUnprefixed(productionConfig());
    try {
      await request(unprefixedTest.getHttpServer()).post('/auth/login').expect(400);
      await request(unprefixedProduction.getHttpServer()).post('/auth/login').expect(403);
    } finally {
      await unprefixedTest.close();
      await unprefixedProduction.close();
    }
  }, 60000);
});

async function buildUnprefixed(config?: AppConfig): Promise<INestApplication> {
  const builder = Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(DbHealth)
    .useValue({ ping: async () => undefined });
  if (config !== undefined) {
    builder.overrideProvider(APP_CONFIG).useValue(config);
  }
  const moduleRef = await builder.compile();
  const app = moduleRef.createNestApplication();
  await app.init();
  return app;
}

import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import { AppModule } from '../src/app.module.js';
import { APP_CONFIG } from '../src/config/config.module.js';
import { parseEnv, type AppConfig } from '../src/config/env.js';
import { DbHealth } from '../src/db/db-health.js';
import { setupSwagger } from '../src/swagger.js';

/**
 * Swagger gating (ADR-008 Z13, owner C1): the real module + the real helper.
 * Production config must expose neither `/api/docs` nor `/api/docs-json`;
 * development/test keep both.
 */
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

async function build(config?: AppConfig): Promise<{ app: INestApplication; config: AppConfig }> {
  const builder = Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(DbHealth)
    .useValue(dbHealthStub);
  if (config !== undefined) {
    builder.overrideProvider(APP_CONFIG).useValue(config);
  }
  const moduleRef = await builder.compile();
  const app = moduleRef.createNestApplication();
  openApps.push(app);
  const effective = app.get<AppConfig>(APP_CONFIG);
  // Register Swagger before Nest finalizes routes (same ordering as Nest docs;
  // main.ts calls it after NestFactory.create, which is already initialized).
  setupSwagger(app, effective);
  await app.init();
  return { app, config: effective };
}

describe('Swagger gating', () => {
  it('serves neither docs route in production', async () => {
    const { app } = await build(productionConfig());
    for (const path of ['/api/docs', '/api/docs-json']) {
      const res = await request(app.getHttpServer()).get(path).expect(404);
      expect(res.body).toEqual({
        error: { code: 'NOT_FOUND', message: 'مسیر مورد نظر یافت نشد' },
      });
    }
  });

  it('keeps both docs routes in test/development', async () => {
    const { app, config } = await build();
    expect(config.nodeEnv).not.toBe('production');
    const document = await request(app.getHttpServer()).get('/api/docs-json').expect(200);
    expect(document.body).toMatchObject({ openapi: expect.any(String) });
    await request(app.getHttpServer()).get('/api/docs').expect(200);
  });
});

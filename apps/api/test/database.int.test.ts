import 'reflect-metadata';

import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, inject, it } from 'vitest';

import { AppModule } from '../src/app.module.js';

/**
 * /health/ready against a real PostgreSQL 17 (Testcontainers global setup):
 * 200 when reachable, fast 503 when not. The app must boot either way — the
 * pool is lazy and readiness reports the outage (T07 acceptance).
 */
async function boot(databaseUrl: string): Promise<INestApplication> {
  process.env.NODE_ENV = 'test';
  process.env.DATABASE_URL = databaseUrl;
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  const app = moduleRef.createNestApplication();
  await app.init();
  return app;
}

describe('database readiness (integration)', () => {
  let app: INestApplication | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('boots with DATABASE_URL of the runtime role; /health/ready returns 200', async () => {
    app = await boot(inject('appUrl'));
    const res = await request(app.getHttpServer()).get('/health/ready').expect(200);
    expect(res.body).toEqual({ data: { status: 'ok' } });
  });

  it('/health/ready returns 503 within 3 seconds when the database is unreachable', async () => {
    const down = new URL(inject('appUrl'));
    down.port = '59999'; // nothing listens here
    app = await boot(down.toString());

    const started = Date.now();
    const res = await request(app.getHttpServer()).get('/health/ready').expect(503);
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(3000);
    // Standard envelope, no database internals (the filter has no 503 entry → HTTP_503).
    expect(res.body).toEqual({ error: { code: 'HTTP_503', message: 'درخواست نامعتبر است' } });
  });
});

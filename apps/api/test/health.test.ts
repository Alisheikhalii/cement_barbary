import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import helmet from 'helmet';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { AppModule } from '../src/app.module.js';
import { DbHealth } from '../src/db/db-health.js';

/**
 * Boots the real AppModule (in-memory) and verifies the HTTP contract:
 * envelope, error format, request id and security headers. DbHealth is
 * stubbed so the readiness behavior is tested without a database (the real
 * DB path is covered by test/database.int.test.ts).
 */
describe('API skeleton (integration)', () => {
  let app: INestApplication;
  const dbHealthStub = { ping: vi.fn<() => Promise<void>>() };

  beforeAll(async () => {
    // DATABASE_URL and the PII keys are required by env validation; DbHealth is
    // stubbed, so nothing connects to the DB. Keys are random per run (U17).
    process.env.DATABASE_URL ??= 'postgresql://bitabar_app:dummy@localhost:5432/bitabar';
    process.env.PII_ENC_KEY ??= randomBytes(32).toString('base64');
    process.env.PII_HMAC_KEY ??= randomBytes(32).toString('base64');
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(DbHealth)
      .useValue(dbHealthStub)
      .compile();
    app = moduleRef.createNestApplication();
    app.use(helmet());
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /health/live returns 200 with the standard envelope', async () => {
    const res = await request(app.getHttpServer()).get('/health/live').expect(200);
    expect(res.body).toEqual({ data: { status: 'ok' } });
  });

  it('GET /health/ready returns 200 when the database is healthy', async () => {
    dbHealthStub.ping.mockResolvedValue(undefined);
    const res = await request(app.getHttpServer()).get('/health/ready').expect(200);
    expect(res.body).toEqual({ data: { status: 'ok' } });
  });

  it('GET /health/ready returns 503 with the standard envelope when the database is down', async () => {
    dbHealthStub.ping.mockRejectedValue(new Error('connection refused'));
    const res = await request(app.getHttpServer()).get('/health/ready').expect(503);
    // The global filter has no specific 503 entry, so it emits HTTP_503 with a
    // generic Persian message — no database details reach the client.
    expect(res.body).toEqual({ error: { code: 'HTTP_503', message: 'درخواست نامعتبر است' } });
  });

  it('GET /health/live stays 200 while the database is down', async () => {
    dbHealthStub.ping.mockRejectedValue(new Error('connection refused'));
    const res = await request(app.getHttpServer()).get('/health/live').expect(200);
    expect(res.body).toEqual({ data: { status: 'ok' } });
  });

  it('echoes a request id and sets security headers', async () => {
    const res = await request(app.getHttpServer()).get('/health/live');
    expect(res.headers['x-request-id']).toBeTruthy();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  it('returns the standard error envelope for unknown routes', async () => {
    const res = await request(app.getHttpServer()).get('/no-such-route').expect(404);
    expect(res.body).toEqual({
      error: { code: 'NOT_FOUND', message: 'مسیر مورد نظر یافت نشد' },
    });
  });
});

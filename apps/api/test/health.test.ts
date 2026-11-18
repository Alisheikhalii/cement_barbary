import 'reflect-metadata';

import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import helmet from 'helmet';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { AppModule } from '../src/app.module.js';

/**
 * Boots the real AppModule (in-memory, no database needed yet) and verifies
 * the HTTP contract: envelope, error format, request id and security headers.
 * Mirrors the helmet wiring of `main.ts`.
 */
describe('API skeleton (integration)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
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

  it('GET /health/ready returns 200', async () => {
    const res = await request(app.getHttpServer()).get('/health/ready').expect(200);
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

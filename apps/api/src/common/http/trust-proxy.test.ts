import { Controller, Get, Req } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import type { Request } from 'express';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';

/**
 * Express `trust proxy` is OFF unless the deployment turns it on. Rate limits
 * key on `request.ip` (auth.service.ts → enforceLimits), so trusting a
 * client-supplied `X-Forwarded-For` would let any caller pick its own bucket.
 * The F8 deployment turns it on explicitly, only for the internal Nginx hop —
 * see docs/security/authn.md and AGENT.md §7.
 */

@Controller('probe')
class ProbeController {
  @Get()
  ip(@Req() req: Request): { ip: string | undefined } {
    return { ip: req.ip };
  }
}

async function buildProbe(trustProxy?: number): Promise<NestExpressApplication> {
  const moduleRef = await Test.createTestingModule({ controllers: [ProbeController] }).compile();
  const app = moduleRef.createNestApplication<NestExpressApplication>();
  if (trustProxy !== undefined) {
    app.set('trust proxy', trustProxy);
  }
  await app.init();
  return app;
}

describe('trust proxy', () => {
  let app: NestExpressApplication | undefined;

  afterEach(async () => {
    if (app !== undefined) {
      await app.close();
      app = undefined;
    }
  });

  it('ignores X-Forwarded-For by default', async () => {
    app = await buildProbe();
    expect(app.getHttpAdapter().getInstance().get('trust proxy')).toBeFalsy();

    const response = await request(app.getHttpServer())
      .get('/probe')
      .set('X-Forwarded-For', '203.0.113.7');

    expect(response.status).toBe(200);
    const body = response.body as { ip: string };
    expect(body.ip).not.toBe('203.0.113.7');
    expect(body.ip.length).toBeGreaterThan(0);
  });

  it('uses X-Forwarded-For only when trust proxy is enabled (F8 hand-off)', async () => {
    app = await buildProbe(1);

    const response = await request(app.getHttpServer())
      .get('/probe')
      .set('X-Forwarded-For', '203.0.113.7');

    expect(response.status).toBe(200);
    expect((response.body as { ip: string }).ip).toBe('203.0.113.7');
  });
});

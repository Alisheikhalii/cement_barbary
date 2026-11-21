import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import { Controller, Module, Post, type INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { AppModule } from '../src/app.module.js';
import { DomainError } from '../src/common/errors/domain-error.js';
import { APP_CONFIG } from '../src/config/config.module.js';
import { parseEnv, type AppConfig } from '../src/config/env.js';
import { AuthzFreshness } from '../src/db/authz-freshness.js';
import { DbHealth } from '../src/db/db-health.js';
import { TokenService } from '../src/modules/auth/token.service.js';
import { AUDIT_HOOK, type AuditHook, type AuditRecord } from '../src/security/authz/audit-hook.js';
import { RequirePermission, ZodBody } from '../src/security/authz/decorators.js';
import { sensitiveReasonSchema } from '../src/security/authz/sensitive-reason.js';

/**
 * Sensitive-action audit (ADR-008 Z10, F1-05 T06). The probe module exists only
 * in this test and is refused by the production boot scan. The real guard runs;
 * only the freshness read and the hook are replaced.
 */

const USER_ID = '00000000-0000-4000-8000-000000000001';
const TENANT_ID = '00000000-0000-4000-8000-000000000002';
const SESSION_ID = '00000000-0000-4000-8000-000000000003';
const ACTION = 'carrier_membership.write';
const REASON = 'دلیل تست شماره یک';
const SECRET_REASON = 'دلیل محرمانه تست شماره دو';

const order: string[] = [];
const records: AuditRecord[] = [];

const auditHook: AuditHook = {
  record(entry: AuditRecord): void {
    order.push('audit');
    records.push(entry);
  },
};

const freshness = {
  read: vi.fn(async () => ({
    userActive: true,
    tenantActive: true,
    sessionLive: true,
    roles: ['FACTORY_OPERATOR'],
  })),
};

@Controller('authz-audit-probe')
class AuthzAuditProbeController {
  @RequirePermission(ACTION)
  @Post('success')
  success(@ZodBody(z.strictObject({ reason: sensitiveReasonSchema })) body: { reason: string }): {
    length: number;
  } {
    order.push('handler');
    return { length: body.reason.length };
  }

  @RequirePermission(ACTION)
  @Post('failure')
  failure(
    @ZodBody(z.strictObject({ reason: sensitiveReasonSchema })) body: { reason: string },
  ): never {
    void body;
    order.push('handler');
    throw DomainError.internal();
  }

  @RequirePermission('destination.read')
  @Post('non-sensitive')
  nonSensitive(): { ok: true } {
    order.push('handler');
    return { ok: true };
  }
}

@Module({ controllers: [AuthzAuditProbeController] })
class AuthzAuditProbeModule {}

const dbHealthStub = { ping: async (): Promise<void> => undefined };

let app: INestApplication;
let productionApp: INestApplication | undefined;
let operatorToken: string;
let carrierToken: string;

function bearer(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

async function buildAuditApp(
  env: Record<string, string> = {},
  config?: AppConfig,
): Promise<INestApplication> {
  // Never overwrite another test file's secret: a shared worker may reuse the
  // process env. Only fill what is missing, like the other authz tests.
  process.env.DATABASE_URL ??= 'postgresql://bitabar_app:dummy@localhost:5432/bitabar';
  process.env.PII_ENC_KEY ??= randomBytes(32).toString('base64');
  process.env.PII_HMAC_KEY ??= randomBytes(32).toString('base64');
  process.env.AUTH_TOKEN_SECRET ??= randomBytes(32).toString('base64');
  Object.assign(process.env, env);
  const builder = Test.createTestingModule({ imports: [AppModule, AuthzAuditProbeModule] })
    .overrideProvider(DbHealth)
    .useValue(dbHealthStub)
    .overrideProvider(AuthzFreshness)
    .useValue(freshness)
    .overrideProvider(AUDIT_HOOK)
    .useValue(auditHook);
  if (config !== undefined) {
    builder.overrideProvider(APP_CONFIG).useValue(config);
  }
  const moduleRef = await builder.compile();
  const built = moduleRef.createNestApplication();
  await built.init();
  return built;
}

beforeAll(async () => {
  app = await buildAuditApp();
  const tokens = app.get(TokenService);
  operatorToken = await tokens.signAccessToken({
    userId: USER_ID,
    tenantId: TENANT_ID,
    sessionId: SESSION_ID,
    roles: ['FACTORY_OPERATOR'],
  });
  carrierToken = await tokens.signAccessToken({
    userId: USER_ID,
    tenantId: TENANT_ID,
    sessionId: SESSION_ID,
    roles: ['CARRIER_ADMIN'],
  });
}, 60000);

beforeEach(() => {
  order.length = 0;
  records.length = 0;
  freshness.read.mockClear();
});

afterAll(async () => {
  await productionApp?.close().catch(() => undefined);
  await app?.close();
});

describe('sensitive audit hook', () => {
  it('records success after the handler with the validated, trimmed reason', async () => {
    const response = await request(app.getHttpServer())
      .post('/authz-audit-probe/success')
      .set(bearer(operatorToken))
      .send({ reason: `  ${REASON}  ` })
      .expect(201);

    expect(response.body.data).toEqual({ length: REASON.length });
    expect(order).toEqual(['handler', 'audit']);
    expect(records).toEqual([
      {
        actor: { userId: USER_ID, tenantId: TENANT_ID, sessionId: SESSION_ID },
        action: ACTION,
        resource: {
          type: 'handler',
          id: 'AuthzAuditProbeController.success',
        },
        reason: REASON,
        outcome: 'success',
      },
    ]);
  });

  it('records failure after the handler and rethrows the original error', async () => {
    const response = await request(app.getHttpServer())
      .post('/authz-audit-probe/failure')
      .set(bearer(operatorToken))
      .send({ reason: REASON })
      .expect(500);

    expect(response.body).toEqual({
      error: { code: 'INTERNAL', message: 'خطای داخلی سرور رخ داد' },
    });
    expect(order).toEqual(['handler', 'audit']);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      action: ACTION,
      reason: REASON,
      outcome: 'failure',
    });
  });

  it('records failure with a null reason when the body never validated', async () => {
    await request(app.getHttpServer())
      .post('/authz-audit-probe/success')
      .set(bearer(operatorToken))
      .send({ reason: 'too-short' })
      .expect(400);

    // The pipe rejects before the handler, so only the audit step ran.
    expect(order).toEqual(['audit']);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ action: ACTION, reason: null, outcome: 'failure' });
  });

  it('does not record anything when a guard denies before the interceptor', async () => {
    const response = await request(app.getHttpServer())
      .post('/authz-audit-probe/success')
      .set(bearer(carrierToken))
      .send({ reason: SECRET_REASON })
      .expect(403);

    expect(records).toHaveLength(0);
    expect(order).toEqual([]);

    const serialized = JSON.stringify(response.body);
    expect(serialized).not.toContain(ACTION);
    expect(serialized).not.toContain('CARRIER_ADMIN');
    expect(serialized).not.toContain(SECRET_REASON);
    expect(serialized).toBe(
      JSON.stringify({ error: { code: 'FORBIDDEN', message: 'دسترسی مجاز نیست' } }),
    );
  });

  it('does not record anything for an anonymous request', async () => {
    await request(app.getHttpServer())
      .post('/authz-audit-probe/success')
      .send({ reason: REASON })
      .expect(401);
    expect(records).toHaveLength(0);
    expect(order).toEqual([]);
  });

  it('never invokes the hook for a non-sensitive permission route', async () => {
    await request(app.getHttpServer())
      .post('/authz-audit-probe/non-sensitive')
      .set(bearer(operatorToken))
      .expect(201);
    expect(records).toHaveLength(0);
    expect(order).toEqual(['handler']);
  });
});

describe('production surface', () => {
  it('refuses to load the audit probe module in production', async () => {
    const productionConfig: AppConfig = parseEnv({
      NODE_ENV: 'production',
      DATABASE_URL: 'postgresql://bitabar_app:dummy@localhost:5432/bitabar',
      PII_ENC_KEY: randomBytes(32).toString('base64'),
      PII_HMAC_KEY: randomBytes(32).toString('base64'),
      AUTH_TOKEN_SECRET: randomBytes(32).toString('base64'),
    });
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule, AuthzAuditProbeModule],
    })
      .overrideProvider(DbHealth)
      .useValue(dbHealthStub)
      .overrideProvider(AuthzFreshness)
      .useValue(freshness)
      .overrideProvider(AUDIT_HOOK)
      .useValue(auditHook)
      .overrideProvider(APP_CONFIG)
      .useValue(productionConfig)
      .compile();
    productionApp = moduleRef.createNestApplication();
    await expect(productionApp.init()).rejects.toThrow(/AUTHZ_PRODUCTION_(CONTROLLER|MODULE)/);
  });
});

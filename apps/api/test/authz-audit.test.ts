import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import { Controller, Module, Post, type INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { PinoLogger } from 'nestjs-pino';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { AppModule } from '../src/app.module.js';
import { DomainError } from '../src/common/errors/domain-error.js';
import { APP_CONFIG } from '../src/config/config.module.js';
import { parseEnv, type AppConfig } from '../src/config/env.js';
import { AuthzFreshness } from '../src/db/authz-freshness.js';
import { DbHealth } from '../src/db/db-health.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb } from '../src/db/tenant-db.js';
import type { AuditWriter } from '../src/modules/audit/audit-writer.js';
import { TokenService } from '../src/modules/auth/token.service.js';
import { PersistentAuditHook } from '../src/modules/audit/persistent-audit-hook.js';
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

let failSuccessWrite = false;

const auditHook: AuditHook = {
  record(entry: AuditRecord): void {
    order.push('audit');
    if (failSuccessWrite && entry.outcome === 'success') {
      throw new Error('AUDIT_DOWN');
    }
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
  hookOverride?: AuditHook,
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
    .useValue(hookOverride ?? auditHook)
    // Unit test: no database. The interceptor's outer transaction is stubbed;
    // the real transaction is exercised by test/audit-interceptor.int.test.ts.
    .overrideProvider(TenantDb)
    .useValue({
      run: async (fn: (tx: unknown) => Promise<unknown>) => fn(undefined),
    });
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
  failSuccessWrite = false;
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
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      actor: { userId: USER_ID, tenantId: TENANT_ID, sessionId: SESSION_ID },
      action: ACTION,
      resource: {
        type: 'handler',
        id: 'AuthzAuditProbeController.success',
      },
      reason: REASON,
      outcome: 'success',
      // POST default, derived before Nest applies it (F1-06 L6).
      httpStatus: 201,
    });
    expect(records[0]?.requestId).toEqual(expect.any(String));
    expect(records[0]?.ip).toMatch(/127\.0\.0\.1|::1/);
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
      httpStatus: 500,
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
    expect(records[0]).toMatchObject({
      action: ACTION,
      reason: null,
      outcome: 'failure',
      httpStatus: 400,
    });
  });

  it('records a denied row when a guard denies a sensitive permission (L6)', async () => {
    const response = await request(app.getHttpServer())
      .post('/authz-audit-probe/success')
      .set(bearer(carrierToken))
      .send({ reason: SECRET_REASON })
      .expect(403);

    // F1-06 T05: the guard audits a sensitive 403; the reason is never read
    // there and the response is unchanged.
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      action: ACTION,
      outcome: 'denied',
      httpStatus: 403,
      reason: null,
    });
    expect(JSON.stringify(records[0])).not.toContain(SECRET_REASON);
    // Only the guard's audit step ran; the handler never executed.
    expect(order).toEqual(['audit']);

    const serialized = JSON.stringify(response.body);
    expect(serialized).not.toContain(ACTION);
    expect(serialized).not.toContain('CARRIER_ADMIN');
    expect(serialized).not.toContain(SECRET_REASON);
    expect(serialized).toBe(
      JSON.stringify({ error: { code: 'FORBIDDEN', message: 'دسترسی مجاز نیست' } }),
    );
  });

  it('fails the request when the success audit write fails (fail-closed, ADR-009 L1)', async () => {
    failSuccessWrite = true;
    const response = await request(app.getHttpServer())
      .post('/authz-audit-probe/success')
      .set(bearer(operatorToken))
      .send({ reason: REASON })
      .expect(500);

    // A non-domain error maps to the generic 500 body.
    expect(response.body).toEqual({
      error: { code: 'INTERNAL_ERROR', message: 'خطای داخلی سرور رخ داد' },
    });
    // The success attempt threw, then the failure row was attempted.
    expect(order).toEqual(['handler', 'audit', 'audit']);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ outcome: 'failure', httpStatus: 500 });
  });

  it('keeps the 403 and logs only a code when the denied-row write fails (L6)', async () => {
    const warn = vi.fn();
    const failingHook = new PersistentAuditHook(
      new TenantContext(),
      {
        append: async (): Promise<string> => {
          throw new Error('AUDIT_DOWN');
        },
      } as unknown as AuditWriter,
      { setContext: vi.fn(), warn } as unknown as PinoLogger,
    );
    const failingApp = await buildAuditApp({}, undefined, failingHook);
    try {
      const response = await request(failingApp.getHttpServer())
        .post('/authz-audit-probe/success')
        .set(bearer(carrierToken))
        .send({ reason: SECRET_REASON })
        .expect(403);

      // Raw body, byte-for-byte the normal denial.
      expect(response.text).toBe(
        JSON.stringify({ error: { code: 'FORBIDDEN', message: 'دسترسی مجاز نیست' } }),
      );
      expect(warn).toHaveBeenCalledTimes(1);
      const payload = warn.mock.calls[0]?.[0] as Record<string, unknown>;
      expect(payload).toMatchObject({ outcome: 'denied', code: 'AUDIT_WRITE_FAILED' });
      const serialized = JSON.stringify(payload);
      expect(serialized).not.toContain(SECRET_REASON);
      expect(serialized).not.toContain('127.0.0.1');
      expect(serialized).not.toContain('::1');
      expect(serialized).not.toContain(ACTION);
    } finally {
      await failingApp.close();
    }
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
  it('binds the persistent hook, not the no-op implementation (F1-06 T05)', async () => {
    // No AUDIT_HOOK override: the real provider graph. No query runs during
    // instantiation (the pg pool is lazy).
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(DbHealth)
      .useValue(dbHealthStub)
      .overrideProvider(AuthzFreshness)
      .useValue(freshness)
      .compile();
    const bound = moduleRef.createNestApplication();
    await bound.init();
    try {
      expect(bound.get(AUDIT_HOOK)).toBeInstanceOf(PersistentAuditHook);
    } finally {
      await bound.close();
    }
  });

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

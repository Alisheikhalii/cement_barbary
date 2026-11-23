import { randomBytes } from 'node:crypto';

import type { NestExpressApplication } from '@nestjs/platform-express';
import type { Pool } from 'pg';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { PasswordService } from '../src/modules/auth/password.service.js';
import { parseEnv } from '../src/config/env.js';
import { createTenant, createUser, ownerPool } from './setup/db.js';
import { buildAuthApp } from './setup/auth-app.js';

/**
 * F1-07 T01: a rate-limiter failure (the resolved 57014 case) is fail-closed
 * with a generic 503 + Retry-After, never a raw 500 and never a response that
 * differs between an existing and an unknown account. The injected limiter
 * throws before any credential lookup, which is exactly the production order.
 */

const STAFF_PW = 'Correct-Horse!Battery9';
/** Auth routes are public/self-authenticating, not `@Idempotent()`. */
const IDEMPOTENCY_KEY = 'f1-07-limiter-failure-0001';

let owner: Pool;
let app: NestExpressApplication;
let tenantId: string;
let userId: string;
let code: string;
const username = 'limit.user';

function login(identifier: string) {
  return request(app.getHttpServer())
    .post('/api/v1/auth/login')
    .set('Idempotency-Key', IDEMPOTENCY_KEY)
    .send({ identifier, password: STAFF_PW });
}

async function idempotencyRows(): Promise<number> {
  const res = await owner.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM idempotency_keys WHERE tenant_id = $1',
    [tenantId],
  );
  return res.rows[0]?.n ?? 0;
}

describe('rate-limiter failure (F1-07 T01)', () => {
  beforeAll(async () => {
    owner = ownerPool();
    code = `limfail-${randomBytes(4).toString('hex')}`;
    tenantId = await createTenant(owner, code);
    userId = await createUser(owner, tenantId, { username });

    // buildAuthApp sets DATABASE_URL from the provided container URL, so it
    // must run before parseEnv reads the environment.
    app = await buildAuthApp({}, [], {
      rateLimiter: {
        hit: async () => {
          throw Object.assign(new Error('canceling statement due to statement timeout'), {
            code: '57014',
          });
        },
      },
    });
    const passwords = new PasswordService(parseEnv(process.env));
    await owner.query(
      `INSERT INTO user_credentials (id, tenant_id, user_id, password_hash)
       VALUES ($1,$2,$3,$4)`,
      [uuidv7(), tenantId, userId, await passwords.hash(STAFF_PW)],
    );
  });

  afterAll(async () => {
    if (app !== undefined) {
      await app.close();
    }
  });

  it('answers the same generic 503 + Retry-After for a known and an unknown identifier', async () => {
    const known = await login(`${username}@${code}`);
    const unknown = await login(`ghost.user@${code}`);

    expect(known.status).toBe(503);
    expect(unknown.status).toBe(503);
    expect(known.status).not.toBe(500);
    expect(known.body).toEqual(unknown.body);
    expect(known.body).toMatchObject({ error: { code: 'SERVICE_UNAVAILABLE' } });
    expect(known.body).not.toHaveProperty('error.details');
    expect(known.headers['retry-after']).toBe('1');
    expect(unknown.headers['retry-after']).toBe('1');

    // Fail-closed before any credential work: no session and no audit row.
    const sessions = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM auth_sessions WHERE tenant_id = $1 AND user_id = $2',
      [tenantId, userId],
    );
    expect(sessions.rows[0]?.n).toBe(0);
    const audits = await owner.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action = 'auth.login.success'",
      [tenantId],
    );
    expect(audits.rows[0]?.n).toBe(0);

    // F1-07 T02 check: a 503 is never stored as an idempotent answer. The route
    // carries no `@Idempotent()` marker, so the header is ignored entirely and
    // a retry with the same key re-executes instead of replaying a 503.
    expect(known.headers['idempotent-replayed']).toBeUndefined();
    await expect(idempotencyRows()).resolves.toBe(0);
    const retry = await login(`${username}@${code}`);
    expect(retry.status).toBe(503);
    expect(retry.headers['idempotent-replayed']).toBeUndefined();
    await expect(idempotencyRows()).resolves.toBe(0);
  });
});

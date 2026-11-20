import { randomBytes } from 'node:crypto';

import type { NestExpressApplication } from '@nestjs/platform-express';
import type { Pool } from 'pg';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { RateLimitStore } from '../src/db/rate-limit-store.js';
import { RATE_LIMITER } from '../src/modules/auth/rate-limiter.js';
import type { DbRateLimiter } from '../src/modules/auth/db-rate-limiter.js';
import { PasswordService } from '../src/modules/auth/password.service.js';
import { parseEnv } from '../src/config/env.js';
import { assignRole, createTenant, createUser, ownerPool } from './setup/db.js';
import { buildAuthApp } from './setup/auth-app.js';

/**
 * Rate-limit boundaries (ADR-007 A11, owner T06): per-IP and per-account fixed
 * windows, Retry-After on 429, atomic upsert under concurrency, lazy + sweep
 * cleanup, one non-oracle (an unknown identifier gets the same buckets as a
 * known one) and HASHED keys. Two app instances carry different limits — the
 * config is read once per compile.
 */

const STAFF_PW = 'Correct-Horse!Battery9';

let owner: Pool;
let appIp: NestExpressApplication;
let appAccount: NestExpressApplication;
let code: string;
let tenantId: string;
let username: string;

function login(
  app: NestExpressApplication,
  identifier: string,
  headers: Record<string, string> = {},
  password: string = STAFF_PW,
) {
  return request(app.getHttpServer())
    .post('/api/v1/auth/login')
    .set(headers)
    .send({ identifier, password });
}

async function clearBuckets(): Promise<void> {
  await owner.query('DELETE FROM auth_rate_limits');
}

describe('login rate limits (A11)', () => {
  beforeAll(async () => {
    owner = ownerPool();
    const suffix = randomBytes(4).toString('hex');
    code = `rl-${suffix}`;
    tenantId = await createTenant(owner, code);
    username = 'rl.user';
    const userId = await createUser(owner, tenantId, { username });

    appIp = await buildAuthApp({
      AUTH_RL_LOGIN_IP_PER_MIN: '5',
      AUTH_RL_LOGIN_ACCOUNT_PER_MIN: '1000',
      AUTH_RL_LOGIN_TENANT_PER_MIN: '1000',
    });
    appAccount = await buildAuthApp({
      AUTH_RL_LOGIN_IP_PER_MIN: '1000',
      AUTH_RL_LOGIN_ACCOUNT_PER_MIN: '3',
      AUTH_RL_LOGIN_TENANT_PER_MIN: '1000',
    });
    const passwords = new PasswordService(parseEnv(process.env));
    await owner.query(
      'INSERT INTO user_credentials (id, tenant_id, user_id, password_hash) VALUES ($1,$2,$3,$4)',
      [uuidv7(), tenantId, userId, await passwords.hash(STAFF_PW)],
    );
    await assignRole(owner, tenantId, userId, 'FACTORY_OPERATOR', 'tenant');
    await clearBuckets();
  });

  afterAll(async () => {
    if (appIp !== undefined) {
      await appIp.close();
    }
    if (appAccount !== undefined) {
      await appAccount.close();
    }
  });

  it('per-IP: the 6th request in the window is 429 with Retry-After', async () => {
    await clearBuckets();
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const res = await login(appIp, `ghost${attempt}@${code}`);
      expect(res.status, `attempt ${attempt}`).toBe(401);
    }
    const blocked = await login(appIp, `ghost6@${code}`);
    expect(blocked.status).toBe(429);
    expect(blocked.body).toMatchObject({ error: { code: 'TOO_MANY_REQUESTS' } });
    const retryAfter = Number(blocked.headers['retry-after']);
    expect(Number.isInteger(retryAfter)).toBe(true);
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(60);
  });

  it('X-Forwarded-For spoofing does not move the per-IP bucket (trust proxy is off)', async () => {
    await clearBuckets();
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const res = await login(appIp, `spoof${attempt}@${code}`, {
        'X-Forwarded-For': `203.0.113.${attempt}`,
      });
      expect(res.status).toBe(401);
    }
    const blocked = await login(appIp, `spoof9@${code}`, { 'X-Forwarded-For': '198.51.100.9' });
    expect(blocked.status).toBe(429);
  });

  it('per-account: the 4th attempt for one hashed identifier is 429', async () => {
    await clearBuckets();
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      await login(appAccount, `${username}@${code}`, {}, 'Wrong-Passphrase-1').expect(401);
    }
    const blocked = await login(appAccount, `${username}@${code}`, {}, 'Wrong-Passphrase-1');
    expect(blocked.status).toBe(429);
    expect(blocked.body).toMatchObject({ error: { code: 'TOO_MANY_REQUESTS' } });
  });

  it('the per-account 429 is identical for unknown and known identifiers (no oracle)', async () => {
    await clearBuckets();
    const known = `${username}@${code}`;
    const unknown = `ghost.user@${code}`;
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      await login(appAccount, known, {}, 'Wrong-Passphrase-1').expect(401);
      await login(appAccount, unknown).expect(401);
    }
    const knownBlocked = await login(appAccount, known, {}, 'Wrong-Passphrase-1');
    const unknownBlocked = await login(appAccount, unknown);
    expect(knownBlocked.status).toBe(429);
    expect(unknownBlocked.status).toBe(429);
    expect(unknownBlocked.body).toEqual(knownBlocked.body);
    expect(typeof unknownBlocked.headers['retry-after']).toBe(
      typeof knownBlocked.headers['retry-after'],
    );
  });

  it('persists only hashed key material — never a raw username or tenant code', async () => {
    const rows = await owner.query<{ key: string }>('SELECT key FROM auth_rate_limits');
    expect(rows.rows.length).toBeGreaterThan(0);
    for (const row of rows.rows) {
      expect(row.key).not.toContain(username);
      expect(row.key).not.toContain(code);
      expect(row.key).toMatch(/^login:(ip|acct|tenant):/);
    }
    // Both hashed dimensions are present, and the tenant key exists.
    expect(rows.rows.some((row) => row.key.startsWith('login:acct:'))).toBe(true);
    expect(rows.rows.some((row) => row.key.startsWith('login:tenant:'))).toBe(true);
  });

  it('the window expires lazily: an expired row restarts at count 1', async () => {
    await clearBuckets();
    await login(appAccount, `lazy@${code}`).expect(401);
    await owner.query(
      `UPDATE auth_rate_limits SET expires_at = now() - interval '1 second' WHERE key LIKE 'login:acct:%'`,
    );
    const store = appAccount.get(RateLimitStore);
    const key = (
      await owner.query<{ key: string }>(
        `SELECT key FROM auth_rate_limits WHERE key LIKE 'login:acct:%' LIMIT 1`,
      )
    ).rows[0]?.key;
    if (key === undefined) {
      throw new Error('expected an account bucket');
    }
    const hit = await store.hit(key, 60);
    expect(hit.count).toBe(1);
  });

  it('the sweep removes expired buckets', async () => {
    await owner.query(
      `INSERT INTO auth_rate_limits (key, count, expires_at)
       VALUES ('login:ip:203.0.113.250', 3, now() - interval '1 minute')
       ON CONFLICT (key) DO UPDATE SET expires_at = now() - interval '1 minute'`,
    );
    const limiter = appIp.get<DbRateLimiter>(RATE_LIMITER);
    const removed = await limiter.sweep();
    expect(removed).toBeGreaterThanOrEqual(1);
    const left = await owner.query(
      `SELECT 1 FROM auth_rate_limits WHERE key = 'login:ip:203.0.113.250'`,
    );
    expect(left.rowCount).toBe(0);
  });

  it('the atomic upsert never undercounts under 50 parallel hits', async () => {
    const store = appIp.get(RateLimitStore);
    const key = `login:acct:${'x'.repeat(43)}`;
    await owner.query('DELETE FROM auth_rate_limits WHERE key = $1', [key]);
    await Promise.all(Array.from({ length: 50 }, () => store.hit(key, 60)));
    const row = await owner.query<{ count: number }>(
      'SELECT count FROM auth_rate_limits WHERE key = $1',
      [key],
    );
    expect(row.rows[0]?.count).toBe(50);
  });
});

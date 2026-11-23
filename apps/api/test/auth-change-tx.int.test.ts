import { randomBytes } from 'node:crypto';

import type { NestExpressApplication } from '@nestjs/platform-express';
import type { Pool } from 'pg';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { PasswordService } from '../src/modules/auth/password.service.js';
import { parseEnv } from '../src/config/env.js';
import { assignRole, createTenant, createUser, ownerPool } from './setup/db.js';
import { buildAuthApp } from './setup/auth-app.js';

/**
 * F1-07 T01: a password-change transaction that loses to a deadlock (40P01) or
 * a statement timeout (57014) is translated to a generic 503 + Retry-After.
 * The two SQLSTATEs are injected at the database boundary with a synthetic
 * trigger on user_credentials, so the real transaction, the real rollback and
 * the real error wrapper are exercised; no write and no audit row may survive.
 */

const TEMP_PW = 'Temp-Passphrase-9';
const NEW_PW = 'An0ther-Strong!Passw0rd';

let owner: Pool;
let app: NestExpressApplication;
let tenantId: string;
let code: string;
let passwords: PasswordService;
let userA: string;
let userB: string;

const TRIGGER = 'f1_07_change_tx_fail';
const TRIGGER_FN = 'f1_07_change_tx_fail_fn';

async function createForcedChangeUser(username: string): Promise<string> {
  const userId = await createUser(owner, tenantId, { username });
  await assignRole(owner, tenantId, userId, 'FACTORY_OPERATOR', 'tenant');
  await owner.query(
    `INSERT INTO user_credentials
       (id, tenant_id, user_id, password_hash, must_change_password, temporary_password_expires_at)
     VALUES ($1,$2,$3,$4,true,now() + interval '1 day')`,
    [uuidv7(), tenantId, userId, await passwords.hash(TEMP_PW)],
  );
  return userId;
}

function login(username: string) {
  return request(app.getHttpServer())
    .post('/api/v1/auth/login')
    .send({ identifier: `${username}@${code}`, password: TEMP_PW });
}

async function installFailingTrigger(sqlState: '40P01' | '57014', userId: string): Promise<void> {
  // Scoped to the test user and dropped first, so a leaked trigger can never
  // break an unrelated fixture that updates user_credentials in the shared DB.
  await removeFailingTrigger();
  await owner.query(
    `CREATE OR REPLACE FUNCTION public.${TRIGGER_FN}() RETURNS trigger
     LANGUAGE plpgsql AS $$
     BEGIN
       RAISE EXCEPTION 'synthetic transaction failure' USING ERRCODE = '${sqlState}';
     END $$`,
  );
  await owner.query(
    `CREATE TRIGGER ${TRIGGER} AFTER UPDATE ON public.user_credentials
       FOR EACH ROW WHEN (OLD.user_id = '${userId}'::uuid)
       EXECUTE FUNCTION public.${TRIGGER_FN}()`,
  );
}

async function removeFailingTrigger(): Promise<void> {
  await owner.query(`DROP TRIGGER IF EXISTS ${TRIGGER} ON public.user_credentials`);
  await owner.query(`DROP FUNCTION IF EXISTS public.${TRIGGER_FN}()`);
}

async function credentialState(userId: string) {
  const res = await owner.query<{ password_hash: string; must_change_password: boolean }>(
    'SELECT password_hash, must_change_password FROM user_credentials WHERE user_id = $1',
    [userId],
  );
  return res.rows[0];
}

async function changeCounts(userId: string) {
  const sessions = await owner.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM auth_sessions WHERE tenant_id = $1 AND user_id = $2',
    [tenantId, userId],
  );
  const audits = await owner.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action = 'auth.password.changed'",
    [tenantId],
  );
  return { sessions: sessions.rows[0]?.n ?? 0, audits: audits.rows[0]?.n ?? 0 };
}

describe('password-change transaction failures (F1-07 T01)', () => {
  beforeAll(async () => {
    owner = ownerPool();
    code = `chgtx-${randomBytes(4).toString('hex')}`;
    tenantId = await createTenant(owner, code);
    // buildAuthApp sets DATABASE_URL from the provided container URL, so it
    // must run before parseEnv reads the environment.
    app = await buildAuthApp({
      AUTH_RL_LOGIN_IP_PER_MIN: '1000',
      AUTH_RL_LOGIN_ACCOUNT_PER_MIN: '1000',
      AUTH_RL_LOGIN_TENANT_PER_MIN: '1000',
    });
    passwords = new PasswordService(parseEnv(process.env));
    userA = await createForcedChangeUser('chgtx.a');
    userB = await createForcedChangeUser('chgtx.b');
  });

  afterAll(async () => {
    await removeFailingTrigger();
    if (app !== undefined) {
      await app.close();
    }
  });

  it.each(['40P01', '57014'] as const)(
    'maps SQLSTATE %s to a generic 503 + Retry-After with no write and no audit row',
    async (sqlState) => {
      const userId = sqlState === '40P01' ? userA : userB;
      const username = sqlState === '40P01' ? 'chgtx.a' : 'chgtx.b';

      const loginRes = await login(username);
      expect(loginRes.status).toBe(200);
      const changeToken = (loginRes.body as { data: { changeToken: string } }).data.changeToken;
      const before = await credentialState(userId);
      const countsBefore = await changeCounts(userId);

      await installFailingTrigger(sqlState, userId);
      let response: request.Response | undefined;
      try {
        response = await request(app.getHttpServer())
          .post('/api/v1/auth/password/change')
          .set('Authorization', `Bearer ${changeToken}`)
          .send({ newPassword: NEW_PW });
      } finally {
        await removeFailingTrigger();
      }

      if (response === undefined) {
        throw new Error('expected a response');
      }
      const res = response;
      expect(res.status).toBe(503);
      expect(res.status).not.toBe(500);
      expect(res.body).toMatchObject({ error: { code: 'SERVICE_UNAVAILABLE' } });
      expect(res.body).not.toHaveProperty('error.details');
      expect(res.headers['retry-after']).toBe('1');

      const after = await credentialState(userId);
      expect(after).toEqual(before);
      const countsAfter = await changeCounts(userId);
      expect(countsAfter).toEqual(countsBefore);
    },
  );
});

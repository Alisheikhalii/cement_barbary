import { randomBytes } from 'node:crypto';

import type { NestExpressApplication } from '@nestjs/platform-express';
import type { Pool } from 'pg';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { parseEnv } from '../src/config/env.js';
import { PasswordService } from '../src/modules/auth/password.service.js';
import { assignRole, createTenant, createUser, ownerPool } from './setup/db.js';
import { buildAuthApp, CSRF_HEADERS } from './setup/auth-app.js';

/**
 * End-to-end auth over HTTP (T07): the five endpoints, cookie attributes on
 * the wire, enumeration equality, CSRF, forced change, BR-18 and A18. Runs
 * against the real AppModule and the integration Postgres as bitabar_app.
 * Rate-limit boundaries live in auth-rate-limit.int.test.ts; timing numbers in
 * auth-timing.int.test.ts.
 */

const STAFF_PW = 'Correct-Horse!Battery9';
const DRIVER_PIN = '73910526';
const TEMP_PW = 'Temp-Password!2026';
const NEW_PW = 'Brand-New-Passphrase-9';
const WRONG_PW = 'Wrong-Passphrase-1';

let app: NestExpressApplication;
let owner: Pool;
let passwords: PasswordService;

let tenantA: string;
let tenantB: string;
let codeA: string;
let codeB: string;
let operator: string;
let carrier: string;
let driverA: string;
let disabledStaff: string;
let deletedStaff: string;
let mustChangeUser: string;
let weakChangeUser: string;
let expiredTempUser: string;
let noCredsUser: string;
let delayUser: string;
let a18Disabled: string;
let a18Deleted: string;
let policyStaff: string;
let policyDriver: string;
let fanoutA: string;
let fanoutB: string;
let suspendedTenant: string;
let suspendedCode: string;
let suspendedStaff: string;
let tenantBUser: string;

async function addCredentials(
  tenantId: string,
  userId: string,
  passwordHash: string,
  opts: { mustChange?: boolean; tempPasswordExpiresAt?: Date | null } = {},
): Promise<void> {
  await owner.query(
    `INSERT INTO user_credentials
       (id, tenant_id, user_id, password_hash, must_change_password, temporary_password_expires_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      uuidv7(),
      tenantId,
      userId,
      passwordHash,
      opts.mustChange ?? false,
      opts.tempPasswordExpiresAt ?? null,
    ],
  );
}

function login(identifier: string, password: string, headers: Record<string, string> = {}) {
  return request(app.getHttpServer())
    .post('/api/v1/auth/login')
    .set(headers)
    .send({ identifier, password });
}

function cookieValue(response: request.Response): string {
  const setCookie = response.headers['set-cookie'];
  const raw = Array.isArray(setCookie) ? setCookie : setCookie === undefined ? [] : [setCookie];
  const cookie = raw.find((value) => value.startsWith('bitabar_refresh='));
  if (cookie === undefined) {
    throw new Error('expected a refresh cookie');
  }
  return cookie.split(';')[0] ?? '';
}

function refreshCookieHeader(response: request.Response): string {
  return cookieValue(response);
}

function refresh(cookie: string, headers: Record<string, string> = CSRF_HEADERS) {
  return request(app.getHttpServer())
    .post('/api/v1/auth/refresh')
    .set(headers)
    .set('Cookie', cookie);
}

async function liveSessions(userId: string): Promise<number> {
  const res = await owner.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM auth_sessions WHERE user_id = $1 AND revoked_at IS NULL',
    [userId],
  );
  return res.rows[0]?.n ?? 0;
}

async function resetDelayCounters(): Promise<void> {
  await owner.query(
    'UPDATE user_credentials SET failed_attempts = 0, next_attempt_at = NULL WHERE tenant_id = ANY($1)',
    [[tenantA, tenantB]],
  );
}

describe('auth HTTP endpoints (T07)', () => {
  beforeAll(async () => {
    app = await buildAuthApp({
      AUTH_RL_LOGIN_IP_PER_MIN: '10000',
      AUTH_RL_LOGIN_ACCOUNT_PER_MIN: '1000',
      AUTH_RL_LOGIN_TENANT_PER_MIN: '100000',
    });
    owner = ownerPool();
    await owner.query('DELETE FROM auth_rate_limits');
    passwords = new PasswordService(parseEnv(process.env));

    const staffPhc = await passwords.hash(STAFF_PW);
    const driverPhc = await passwords.hash(DRIVER_PIN);
    const tempPhc = await passwords.hash(TEMP_PW);

    const suffix = randomBytes(4).toString('hex');
    codeA = `e2e-a-${suffix}`;
    codeB = `e2e-b-${suffix}`;
    suspendedCode = `e2e-susp-${suffix}`;
    tenantA = await createTenant(owner, codeA);
    tenantB = await createTenant(owner, codeB);
    suspendedTenant = await createTenant(owner, suspendedCode);
    await owner.query(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, [suspendedTenant]);

    const seedUser = async (
      tenantId: string,
      options: { username?: string; phone?: string; role?: string },
    ): Promise<string> => {
      const id = await createUser(owner, tenantId, {
        ...(options.username === undefined ? {} : { username: options.username }),
        ...(options.phone === undefined ? {} : { phone: options.phone }),
      });
      if (options.role !== undefined) {
        const scope =
          options.role === 'DRIVER'
            ? 'driver'
            : options.role === 'CARRIER_ADMIN'
              ? 'carrier'
              : 'tenant';
        await assignRole(owner, tenantId, id, options.role, scope);
      }
      return id;
    };

    operator = await seedUser(tenantA, { username: 'operator', role: 'FACTORY_OPERATOR' });
    carrier = await seedUser(tenantA, { username: 'carrier', role: 'CARRIER_ADMIN' });
    driverA = await seedUser(tenantA, { phone: '09120000001', role: 'DRIVER' });
    disabledStaff = await seedUser(tenantA, { username: 'disabled', role: 'FACTORY_OPERATOR' });
    deletedStaff = await seedUser(tenantA, { username: 'deleted', role: 'FACTORY_OPERATOR' });
    mustChangeUser = await seedUser(tenantA, { username: 'mustchange', role: 'FACTORY_OPERATOR' });
    weakChangeUser = await seedUser(tenantA, { username: 'weakchange', role: 'FACTORY_OPERATOR' });
    expiredTempUser = await seedUser(tenantA, {
      username: 'expired-temp',
      role: 'FACTORY_OPERATOR',
    });
    noCredsUser = await seedUser(tenantA, { username: 'nocreds', role: 'FACTORY_OPERATOR' });
    delayUser = await seedUser(tenantA, { username: 'delayuser', role: 'FACTORY_OPERATOR' });
    a18Disabled = await seedUser(tenantA, { username: 'a18.disabled', role: 'FACTORY_OPERATOR' });
    a18Deleted = await seedUser(tenantA, { username: 'a18.deleted', role: 'FACTORY_OPERATOR' });
    policyStaff = await seedUser(tenantA, {
      username: 'policy.staff',
      phone: '09120000004',
      role: 'FACTORY_OPERATOR',
    });
    policyDriver = await seedUser(tenantA, { phone: '09120000003', role: 'DRIVER' });
    fanoutA = await seedUser(tenantA, { phone: '09120000002', role: 'DRIVER' });
    fanoutB = await seedUser(tenantB, { phone: '09120000002', role: 'DRIVER' });
    suspendedStaff = await seedUser(suspendedTenant, {
      username: 'susp.operator',
      role: 'FACTORY_OPERATOR',
    });
    tenantBUser = await seedUser(tenantB, { username: 'operator.b', role: 'FACTORY_OPERATOR' });

    for (const id of [operator, carrier, disabledStaff, deletedStaff]) {
      await addCredentials(tenantA, id, staffPhc);
    }
    await addCredentials(tenantA, driverA, driverPhc);
    await addCredentials(tenantA, mustChangeUser, tempPhc, {
      mustChange: true,
      tempPasswordExpiresAt: new Date(Date.now() + 60 * 60 * 1000),
    });
    await addCredentials(tenantA, weakChangeUser, tempPhc, {
      mustChange: true,
      tempPasswordExpiresAt: new Date(Date.now() + 60 * 60 * 1000),
    });
    await addCredentials(tenantA, expiredTempUser, tempPhc, {
      mustChange: true,
      tempPasswordExpiresAt: new Date(Date.now() - 60 * 1000),
    });
    await addCredentials(tenantA, delayUser, staffPhc);
    await addCredentials(tenantA, a18Disabled, staffPhc);
    await addCredentials(tenantA, a18Deleted, staffPhc);
    await addCredentials(tenantA, policyStaff, staffPhc);
    await addCredentials(tenantA, policyDriver, driverPhc);
    await addCredentials(tenantA, fanoutA, driverPhc);
    await addCredentials(tenantB, fanoutB, driverPhc);
    await addCredentials(suspendedTenant, suspendedStaff, staffPhc);
    await addCredentials(tenantB, tenantBUser, staffPhc);
    // noCredsUser intentionally has no credentials row.

    await owner.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [disabledStaff]);
    await owner.query(`UPDATE users SET deleted_at = now() WHERE id = $1`, [deletedStaff]);
  });

  afterAll(async () => {
    if (app !== undefined) {
      await app.close();
    }
  });

  it('logs a staff member in: access token in the body, refresh only in the cookie', async () => {
    const res = await login(`operator@${codeA}`, STAFF_PW);
    expect(res.status).toBe(200);
    const body = res.body as {
      data: {
        accessToken: string;
        tokenType: string;
        expiresIn: number;
        user: { id: string; tenantId: string; roles: string[] };
      };
    };
    expect(body.data.tokenType).toBe('Bearer');
    expect(body.data.expiresIn).toBe(600);
    expect(body.data.user).toEqual({
      id: operator,
      tenantId: tenantA,
      roles: ['FACTORY_OPERATOR'],
    });
    const cookie = cookieValue(res);
    expect(JSON.stringify(res.body)).not.toContain(cookie.split('=')[1]);

    const rawCookie = (res.headers['set-cookie'] as unknown as string[])[0] ?? '';
    expect(rawCookie).toContain('HttpOnly');
    expect(rawCookie).toContain('SameSite=Lax');
    expect(rawCookie).toContain('Path=/api/v1/auth');
    expect(rawCookie).not.toContain('Secure'); // NODE_ENV=test
    expect(rawCookie).not.toContain('Domain=');
    const maxAge = Number(/Max-Age=(\d+)/.exec(rawCookie)?.[1]);
    expect(maxAge).toBeGreaterThan(0);
    expect(maxAge).toBeLessThanOrEqual(30 * 24 * 60 * 60);
  });

  it('logs a driver in by phone and PIN', async () => {
    const res = await login('09120000001', DRIVER_PIN);
    expect(res.status).toBe(200);
    expect((res.body as { data: { user: { roles: string[] } } }).data.user.roles).toEqual([
      'DRIVER',
    ]);
    expect(cookieValue(res)).toContain('bitabar_refresh=');
  });

  it('serves /auth/me only with a valid access token (deny by default)', async () => {
    await request(app.getHttpServer()).get('/api/v1/auth/me').expect(401);
    await request(app.getHttpServer())
      .get('/api/v1/auth/me')
      .set('Authorization', 'Bearer not-a-token')
      .expect(401);

    const loginRes = await login(`operator@${codeA}`, STAFF_PW);
    const accessToken = (loginRes.body as { data: { accessToken: string } }).data.accessToken;
    const me = await request(app.getHttpServer())
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(me.status).toBe(200);
    expect(me.body).toMatchObject({
      data: {
        id: operator,
        tenantId: tenantA,
        roles: ['FACTORY_OPERATOR'],
      },
    });
    expect(typeof (me.body as { data: { sessionId: string } }).data.sessionId).toBe('string');
  });

  it('keeps health public under the global guard', async () => {
    await request(app.getHttpServer()).get('/health/live').expect(200);
  });

  it('forced change: no session, a weak password is refused, then a bound single-use token', async () => {
    const weakLogin = await login(`weakchange@${codeA}`, TEMP_PW);
    expect(weakLogin.status).toBe(200);
    const weakToken = (weakLogin.body as { data: { changeToken: string } }).data.changeToken;
    expect(weakLogin.headers['set-cookie']).toBeUndefined();

    const weak = await request(app.getHttpServer())
      .post('/api/v1/auth/password/change')
      .set('Authorization', `Bearer ${weakToken}`)
      .send({ newPassword: 'short-pass1' });
    expect(weak.status).toBe(400);
    expect(weak.body).toMatchObject({
      error: { code: 'BAD_INPUT', details: { reason: 'too_short' } },
    });

    const loginRes = await login(`mustchange@${codeA}`, TEMP_PW);
    expect(loginRes.status).toBe(200);
    const data = loginRes.body as { data: { changeToken: string; expiresIn: number } };
    expect(data.data.expiresIn).toBe(300);
    expect((data.data as { accessToken?: string }).accessToken).toBeUndefined();
    expect(loginRes.headers['set-cookie']).toBeUndefined();

    // A change token is not an access token.
    await request(app.getHttpServer())
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${data.data.changeToken}`)
      .expect(401);

    const changed = await request(app.getHttpServer())
      .post('/api/v1/auth/password/change')
      .set('Authorization', `Bearer ${data.data.changeToken}`)
      .send({ newPassword: NEW_PW });
    expect(changed.status).toBe(200);
    expect(cookieValue(changed)).toContain('bitabar_refresh=');
    const accessToken = (changed.body as { data: { accessToken: string } }).data.accessToken;
    await request(app.getHttpServer())
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    const row = await owner.query<{
      must_change_password: boolean;
      temporary_password_expires_at: Date | null;
      password_hash: string;
    }>(
      'SELECT must_change_password, temporary_password_expires_at, password_hash FROM user_credentials WHERE user_id = $1',
      [mustChangeUser],
    );
    expect(row.rows[0]?.must_change_password).toBe(false);
    expect(row.rows[0]?.temporary_password_expires_at).toBeNull();
    expect(row.rows[0]?.password_hash.startsWith('$argon2id$')).toBe(true);

    // Single use: the same change token no longer matches the credential row.
    await request(app.getHttpServer())
      .post('/api/v1/auth/password/change')
      .set('Authorization', `Bearer ${data.data.changeToken}`)
      .send({ newPassword: 'Yet-Another-Password-7' })
      .expect(401);

    // Access-token branch requires the current password.
    const missing = await request(app.getHttpServer())
      .post('/api/v1/auth/password/change')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ newPassword: 'Yet-Another-Password-7' });
    expect(missing.status).toBe(400);
    const wrong = await request(app.getHttpServer())
      .post('/api/v1/auth/password/change')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ currentPassword: 'Wrong-Current-1', newPassword: 'Yet-Another-Password-7' });
    expect(wrong.status).toBe(401);
    expect(wrong.body).toMatchObject({ error: { code: 'INVALID_CREDENTIALS' } });
    const ok = await request(app.getHttpServer())
      .post('/api/v1/auth/password/change')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ currentPassword: NEW_PW, newPassword: 'Yet-Another-Password-7' });
    expect(ok.status).toBe(200);
  });

  it('two parallel changes with one change token: exactly one applies (CAS)', async () => {
    const loginRes = await login(`weakchange@${codeA}`, TEMP_PW);
    const changeToken = (loginRes.body as { data: { changeToken: string } }).data.changeToken;
    const [first, second] = await Promise.all([
      request(app.getHttpServer())
        .post('/api/v1/auth/password/change')
        .set('Authorization', `Bearer ${changeToken}`)
        .send({ newPassword: 'Parallel-Winner-A-9' }),
      request(app.getHttpServer())
        .post('/api/v1/auth/password/change')
        .set('Authorization', `Bearer ${changeToken}`)
        .send({ newPassword: 'Parallel-Winner-B-8' }),
    ]);
    expect([first.status, second.status].sort()).toEqual([200, 401]);

    const a = await login(`weakchange@${codeA}`, 'Parallel-Winner-A-9');
    const b = await login(`weakchange@${codeA}`, 'Parallel-Winner-B-8');
    expect([a.status, b.status].sort()).toEqual([200, 401]);
  });

  it('password change rejects a bad access token and a bad change token identically', async () => {
    // The service tries the access-token verifier, then the change-token
    // verifier (audience `bitabar-api:password-change`). Both failure paths
    // must be indistinguishable: neither response may reveal which verifier
    // rejected the token.
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({ sub: uuidv7(), tid: tenantA, aud: 'bitabar-api', exp: 4102444800 }),
    ).toString('base64url');
    const shapedToken = `${header}.${payload}.${randomBytes(32).toString('base64url')}`;

    const responses = await Promise.all(
      ['not-a-jwt', shapedToken].map((token) =>
        request(app.getHttpServer())
          .post('/api/v1/auth/password/change')
          .set('Authorization', `Bearer ${token}`)
          .send({ newPassword: NEW_PW }),
      ),
    );

    const first = responses[0];
    const second = responses[1];
    if (first === undefined || second === undefined) {
      throw new Error('expected two responses');
    }
    expect(first.status).toBe(401);
    expect(second.status).toBe(401);
    expect(second.body).toEqual(first.body);
    expect(second.headers['content-type']).toBe(first.headers['content-type']);
    expect(second.headers['content-length']).toBe(first.headers['content-length']);
    expect(first.headers['set-cookie']).toBeUndefined();
    expect(second.headers['set-cookie']).toBeUndefined();
  });

  it('answers every credential failure with one byte-identical generic 401', async () => {
    const noCreds = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM user_credentials WHERE user_id = $1',
      [noCredsUser],
    );
    expect(noCreds.rows[0]?.n).toBe(0);
    const cases: { label: string; identifier: string; password: string }[] = [
      { label: 'unknown tenant code', identifier: 'ghost@no-such-tenant-x', password: STAFF_PW },
      { label: 'unknown username', identifier: `ghost.user@${codeA}`, password: STAFF_PW },
      { label: 'unknown phone', identifier: '09120000009', password: DRIVER_PIN },
      { label: 'malformed identifier', identifier: 'not-an-identifier', password: STAFF_PW },
      {
        label: 'wrong staff password',
        identifier: `operator@${codeA}`,
        password: WRONG_PW,
      },
      { label: 'wrong driver PIN', identifier: '09120000001', password: '7'.repeat(8) },
      { label: 'disabled account', identifier: `disabled@${codeA}`, password: STAFF_PW },
      { label: 'deleted account', identifier: `deleted@${codeA}`, password: STAFF_PW },
      {
        label: 'suspended tenant',
        identifier: `susp.operator@${suspendedCode}`,
        password: STAFF_PW,
      },
      {
        label: 'expired temporary password',
        identifier: `expired-temp@${codeA}`,
        password: TEMP_PW,
      },
      { label: 'account without credentials', identifier: `nocreds@${codeA}`, password: STAFF_PW },
    ];
    const snapshots = [];
    for (const testCase of cases) {
      const res = await login(testCase.identifier, testCase.password);
      expect(res.status, testCase.label).toBe(401);
      expect(res.body, testCase.label).toEqual({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'اطلاعات ورود نامعتبر است',
        },
      });
      expect(res.headers['set-cookie'], testCase.label).toBeUndefined();
      expect(res.headers['www-authenticate'], testCase.label).toBeUndefined();
      snapshots.push({
        status: res.status,
        body: JSON.stringify(res.body),
        type: res.headers['content-type'],
        length: res.headers['content-length'],
      });
    }
    for (const snapshot of snapshots) {
      expect(snapshot).toEqual(snapshots[0]);
    }
    // The identifiers themselves never appear in the responses.
    for (const testCase of cases) {
      expect(JSON.stringify(snapshots)).not.toContain(testCase.identifier);
      expect(JSON.stringify(snapshots)).not.toContain(testCase.password);
    }
    await resetDelayCounters();
  });

  it('A2: failures delay the next attempt with the generic 401 and reset on success', async () => {
    await resetDelayCounters();
    const first = await login(`delayuser@${codeA}`, 'Wrong-Passphrase-1');
    expect(first.status).toBe(401);
    const row = await owner.query<{ failed_attempts: number; next_attempt_at: Date | null }>(
      'SELECT failed_attempts, next_attempt_at FROM user_credentials WHERE user_id = $1',
      [delayUser],
    );
    expect(row.rows[0]?.failed_attempts).toBe(1);
    const delayMs = (row.rows[0]?.next_attempt_at?.getTime() ?? 0) - Date.now();
    expect(delayMs).toBeGreaterThan(0);
    expect(delayMs).toBeLessThanOrEqual(1500);

    // During the delay the correct password ALSO gets the generic 401, and the
    // counter does not advance (no extension of the window).
    const delayed = await login(`delayuser@${codeA}`, STAFF_PW);
    expect(delayed.status).toBe(401);
    expect(delayed.body).toMatchObject({ error: { code: 'INVALID_CREDENTIALS' } });
    const during = await owner.query<{ failed_attempts: number }>(
      'SELECT failed_attempts FROM user_credentials WHERE user_id = $1',
      [delayUser],
    );
    expect(during.rows[0]?.failed_attempts).toBe(1);

    // Once the window passes, success is possible and clears the counters.
    await owner.query(
      `UPDATE user_credentials SET next_attempt_at = now() - interval '1 second' WHERE user_id = $1`,
      [delayUser],
    );
    const success = await login(`delayuser@${codeA}`, STAFF_PW);
    expect(success.status).toBe(200);
    const after = await owner.query<{ failed_attempts: number; next_attempt_at: Date | null }>(
      'SELECT failed_attempts, next_attempt_at FROM user_credentials WHERE user_id = $1',
      [delayUser],
    );
    expect(after.rows[0]).toEqual({ failed_attempts: 0, next_attempt_at: null });
  });

  it('rotates the refresh cookie and revokes the family on replay', async () => {
    const loginRes = await login(`operator@${codeA}`, STAFF_PW);
    const firstCookie = refreshCookieHeader(loginRes);
    const rotated = await refresh(firstCookie);
    expect(rotated.status).toBe(200);
    const secondCookie = refreshCookieHeader(rotated);
    expect(secondCookie).not.toBe(firstCookie);
    expect(rotated.headers['set-cookie']).toBeDefined();
    const raw = (rotated.headers['set-cookie'] as unknown as string[])[0] ?? '';
    const maxAge = Number(/Max-Age=(\d+)/.exec(raw)?.[1]);
    expect(maxAge).toBeGreaterThan(0);
    expect(maxAge).toBeLessThanOrEqual(30 * 24 * 60 * 60);

    // Replaying the rotated-out cookie revokes the whole family.
    await refresh(firstCookie).expect(401);
    const afterReuse = await refresh(secondCookie);
    expect(afterReuse.status).toBe(401);
  });

  it('enforces CSRF on cookie endpoints before any cookie lookup', async () => {
    const loginRes = await login(`carrier@${codeA}`, STAFF_PW);
    const cookie = refreshCookieHeader(loginRes);

    const noHeader = await refresh(cookie, {});
    expect(noHeader.status).toBe(403);
    const noHeaderInvalidCookie = await refresh('bitabar_refresh=invalid', {});
    expect(noHeaderInvalidCookie.status).toBe(403);
    expect(noHeaderInvalidCookie.body).toEqual(noHeader.body);

    const evil = await refresh(cookie, { ...CSRF_HEADERS, Origin: 'https://evil.example' });
    expect(evil.status).toBe(403);
    expect(evil.headers['set-cookie']).toBeUndefined();

    const allowed = await refresh(cookie, {
      ...CSRF_HEADERS,
      Origin: 'http://localhost:3000',
    });
    expect(allowed.status).toBe(200);
  });

  it('logout revokes the session, clears the cookie and is idempotent', async () => {
    const loginRes = await login(`carrier@${codeA}`, STAFF_PW);
    const cookie = refreshCookieHeader(loginRes);
    const accessToken = (loginRes.body as { data: { accessToken: string } }).data.accessToken;

    const out = await request(app.getHttpServer())
      .post('/api/v1/auth/logout')
      .set(CSRF_HEADERS)
      .set('Cookie', cookie);
    expect(out.status).toBe(200);
    expect(out.body).toEqual({ data: { loggedOut: true } });
    const cleared = (out.headers['set-cookie'] as unknown as string[])[0] ?? '';
    expect(cleared).toContain('bitabar_refresh=;');
    expect(cleared).toContain('Max-Age=0');

    await refresh(cookie).expect(401);
    await request(app.getHttpServer())
      .post('/api/v1/auth/logout')
      .set(CSRF_HEADERS)
      .set('Cookie', cookie)
      .expect(200);

    // The access token remains valid until exp (documented A7 risk).
    await request(app.getHttpServer())
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);
  });

  it('BR-18: parallel driver logins leave exactly one live session; staff keep both', async () => {
    await resetDelayCounters();
    const results = await Promise.all([
      login('09120000001', DRIVER_PIN),
      login('09120000001', DRIVER_PIN),
    ]);
    for (const res of results) {
      expect(res.status).toBe(200);
    }
    expect(await liveSessions(driverA)).toBe(1);

    const staffResults = await Promise.all([
      login(`operator@${codeA}`, STAFF_PW),
      login(`operator@${codeA}`, STAFF_PW),
    ]);
    for (const res of staffResults) {
      expect(res.status).toBe(200);
    }
    expect(await liveSessions(operator)).toBeGreaterThanOrEqual(2);
  });

  it('A5: a phone in two tenants advances both counters and still logs in once', async () => {
    await resetDelayCounters();
    const wrong = await login('09120000002', '7'.repeat(8));
    expect(wrong.status).toBe(401);
    const rows = await owner.query<{ tenant_id: string; failed_attempts: number }>(
      `SELECT tenant_id, failed_attempts FROM user_credentials WHERE user_id = ANY($1)`,
      [[fanoutA, fanoutB]],
    );
    expect(rows.rows).toHaveLength(2);
    for (const row of rows.rows) {
      expect(row.failed_attempts).toBe(1);
    }

    await resetDelayCounters();
    const ok = await login('09120000002', DRIVER_PIN);
    expect(ok.status).toBe(200);
    const identity = (ok.body as { data: { user: { ids?: string; tenantId: string } } }).data.user;
    expect([tenantA, tenantB]).toContain(identity.tenantId);
  });

  it('A20: the new password may not equal any form of the login identifier', async () => {
    const staffLogin = await login(`policy.staff@${codeA}`, STAFF_PW);
    const staffToken = (staffLogin.body as { data: { accessToken: string } }).data.accessToken;
    const composite = await request(app.getHttpServer())
      .post('/api/v1/auth/password/change')
      .set('Authorization', `Bearer ${staffToken}`)
      .send({ currentPassword: STAFF_PW, newPassword: `policy.staff@${codeA}` });
    expect(composite.status).toBe(400);
    expect(composite.body).toMatchObject({
      error: { code: 'BAD_INPUT', details: { reason: 'equals_identifier' } },
    });

    const driverLogin = await login('09120000003', DRIVER_PIN);
    const driverToken = (driverLogin.body as { data: { accessToken: string } }).data.accessToken;
    const phonePin = await request(app.getHttpServer())
      .post('/api/v1/auth/password/change')
      .set('Authorization', `Bearer ${driverToken}`)
      .send({ currentPassword: DRIVER_PIN, newPassword: '09120000003' });
    expect(phonePin.status).toBe(400);
    expect(phonePin.body).toMatchObject({
      error: { code: 'BAD_INPUT', details: { reason: 'equals_identifier' } },
    });

    // Phone aliases normalize to the same login identifier.
    const aliasPin = await request(app.getHttpServer())
      .post('/api/v1/auth/password/change')
      .set('Authorization', `Bearer ${driverToken}`)
      .send({ currentPassword: DRIVER_PIN, newPassword: '9120000003' });
    expect(aliasPin.status).toBe(400);
    expect(aliasPin.body).toMatchObject({
      error: { code: 'BAD_INPUT', details: { reason: 'equals_identifier' } },
    });

    // A phone-carrying staff account cannot use the +98/98 alias either.
    const staffAlias = await request(app.getHttpServer())
      .post('/api/v1/auth/password/change')
      .set('Authorization', `Bearer ${staffToken}`)
      .send({ currentPassword: STAFF_PW, newPassword: '989120000004' });
    expect(staffAlias.status).toBe(400);
    expect(staffAlias.body).toMatchObject({
      error: { code: 'BAD_INPUT', details: { reason: 'equals_identifier' } },
    });
  });

  it('A18: refresh fails and revokes after disable, delete or tenant suspension', async () => {
    await resetDelayCounters();
    const disabledLogin = await login(`a18.disabled@${codeA}`, STAFF_PW);
    const disabledCookie = refreshCookieHeader(disabledLogin);
    await owner.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [a18Disabled]);
    await refresh(disabledCookie).expect(401);
    expect(await liveSessions(a18Disabled)).toBe(0);
    await owner.query(`UPDATE users SET status = 'active' WHERE id = $1`, [a18Disabled]);

    // Two sessions, neither refreshed during the suspension: the trigger must
    // revoke the DORMANT one too, so reactivation cannot revive it (R1).
    const tenantBLogin = await login(`operator.b@${codeB}`, STAFF_PW);
    const tenantBCookie = refreshCookieHeader(tenantBLogin);
    const tenantBLogin2 = await login(`operator.b@${codeB}`, STAFF_PW);
    const tenantBCookie2 = refreshCookieHeader(tenantBLogin2);
    const tenantBUser = await owner.query<{ id: string }>(
      `SELECT id FROM users WHERE tenant_id = $1 AND username = 'operator.b'`,
      [tenantB],
    );
    const tenantBUserId = tenantBUser.rows[0]?.id;
    if (tenantBUserId === undefined) {
      throw new Error('tenant B operator fixture missing');
    }
    expect(await liveSessions(tenantBUserId)).toBe(2);
    await owner.query(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, [tenantB]);
    expect(await liveSessions(tenantBUserId)).toBe(0);
    await owner.query(`UPDATE tenants SET status = 'active' WHERE id = $1`, [tenantB]);
    await refresh(tenantBCookie).expect(401);
    await refresh(tenantBCookie2).expect(401);

    const deletedLogin = await login(`a18.deleted@${codeA}`, STAFF_PW);
    const deletedCookie = refreshCookieHeader(deletedLogin);
    await owner.query(`UPDATE users SET deleted_at = now() WHERE id = $1`, [a18Deleted]);
    await refresh(deletedCookie).expect(401);
    expect(await liveSessions(a18Deleted)).toBe(0);
    await owner.query(`UPDATE users SET deleted_at = NULL WHERE id = $1`, [a18Deleted]);
  });

  it('rejects malformed request bodies uniformly and truncates user_agent', async () => {
    const extra = await login(`operator@${codeA}`, STAFF_PW, {});
    expect(extra.status).toBe(200);
    const withExtra = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({ identifier: `operator@${codeA}`, password: STAFF_PW, tenantId: tenantB });
    expect(withExtra.status).toBe(400);
    const missing = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({ identifier: `operator@${codeA}` });
    expect(missing.status).toBe(400);

    // Login CSRF: a cross-site form post cannot authenticate or plant a cookie.
    const formLogin = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .type('form')
      .send({ identifier: `operator@${codeA}`, password: STAFF_PW });
    expect(formLogin.status).toBe(400);
    expect(formLogin.headers['set-cookie']).toBeUndefined();

    const longUa = 'u'.repeat(1000);
    const res = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .set('User-Agent', longUa)
      .send({ identifier: '09120000001', password: DRIVER_PIN });
    expect(res.status).toBe(200);
    const stored = await owner.query<{ len: number }>(
      `SELECT length(user_agent)::int AS len FROM auth_sessions
       WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [driverA],
    );
    expect(stored.rows[0]?.len).toBe(512);
  });
});

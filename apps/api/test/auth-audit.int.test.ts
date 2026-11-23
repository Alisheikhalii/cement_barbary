import { randomBytes, randomInt } from 'node:crypto';

import type { NestExpressApplication } from '@nestjs/platform-express';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { AuditWriter } from '../src/modules/audit/audit-writer.js';
import { AuthService } from '../src/modules/auth/auth.service.js';
import { PasswordService } from '../src/modules/auth/password.service.js';
import { assignRole, createTenant, createUser, ownerPool } from './setup/db.js';
import { buildAuthApp } from './setup/auth-app.js';

/**
 * Auth-event audit (F1-06 T06, ADR-009 L5) against real PostgreSQL, through
 * the real AppModule (persistent hook). Records only paths that already write:
 * login success, logout, refresh reuse, BR-18 new-device revocation and
 * password change. Failed logins produce no row (Q1) and no raw identifier.
 */

const STAFF_PW = 'Correct-Horse!Battery9';
const STAFF_NEW_PW = 'An0ther-Strong!Passw0rd';
const DRIVER_PIN = '9182736450';
/** Synthetic wrong password for the negative login case (never a real credential). */
const WRONG_STAFF_PW = randomBytes(18).toString('base64url');

let app: NestExpressApplication;
let auth: AuthService;
let passwords: PasswordService;
let owner: Pool;
let tenantId: string;
let tenantCode: string;
let driverPhone: string | null = null;

async function createAccount(options: {
  readonly username?: string;
  readonly phone?: string;
  readonly role: 'FACTORY_OPERATOR' | 'DRIVER';
  readonly password: string;
}): Promise<string> {
  const userId = await createUser(owner, tenantId, {
    ...(options.username === undefined ? {} : { username: options.username }),
    ...(options.phone === undefined ? {} : { phone: options.phone }),
  });
  await assignRole(
    owner,
    tenantId,
    userId,
    options.role,
    options.role === 'DRIVER' ? 'driver' : 'tenant',
  );
  await owner.query(
    `INSERT INTO user_credentials (id, tenant_id, user_id, password_hash, must_change_password)
     VALUES ($1,$2,$3,$4,false)`,
    [uuidv7(), tenantId, userId, await passwords.hash(options.password)],
  );
  return userId;
}

async function auditRows(action: string) {
  const result = await owner.query<{
    actor_type: string;
    actor_user_id: string | null;
    actor_session_id: string | null;
    http_status: number | null;
    metadata: unknown;
    resource_type: string;
    before: unknown;
    after: unknown;
  }>(
    `SELECT actor_type, actor_user_id, actor_session_id, http_status, metadata, resource_type,
            before, after
       FROM audit_logs WHERE tenant_id = $1 AND action = $2 ORDER BY occurred_at`,
    [tenantId, action],
  );
  return result.rows;
}

beforeAll(async () => {
  app = await buildAuthApp({}, [], { rateLimiter: { hit: async () => ({ allowed: true }) } });
  auth = app.get(AuthService);
  passwords = app.get(PasswordService);
  owner = ownerPool();
  tenantCode = `authaudit-${uuidv7().slice(0, 8)}`;
  tenantId = await createTenant(owner, tenantCode);
}, 120_000);

afterAll(async () => {
  await app?.close();
});

describe('auth events', () => {
  it('records a successful login with prior_failed_attempts read before the reset', async () => {
    const username = `staff.login.${uuidv7().slice(0, 6)}`;
    const userId = await createAccount({
      username,
      role: 'FACTORY_OPERATOR',
      password: STAFF_PW,
    });
    // Two earlier failures (registered by the credential store, not audited).
    await owner.query(
      'UPDATE user_credentials SET failed_attempts = 2 WHERE tenant_id = $1 AND user_id = $2',
      [tenantId, userId],
    );

    const result = await auth.login(
      { identifier: `${username}@${tenantCode}`, password: STAFF_PW },
      { ip: '203.0.113.30' },
    );
    expect(result.kind).toBe('session');

    const rows = await auditRows('auth.login.success');
    const row = rows.find((candidate) => candidate.actor_user_id === userId);
    expect(row).toMatchObject({
      actor_type: 'user',
      resource_type: 'auth_session',
      metadata: { method: 'password', prior_failed_attempts: 2 },
    });
    expect(row?.actor_session_id).toEqual(expect.any(String));
    const counter = await owner.query<{ failed_attempts: number }>(
      'SELECT failed_attempts FROM user_credentials WHERE tenant_id = $1 AND user_id = $2',
      [tenantId, userId],
    );
    expect(counter.rows[0]?.failed_attempts).toBe(0);
  });

  it('records no row for a failed login', async () => {
    const username = `staff.fail.${uuidv7().slice(0, 6)}`;
    const userId = await createAccount({
      username,
      role: 'FACTORY_OPERATOR',
      password: STAFF_PW,
    });
    const before = await auditRows('auth.login.success');
    await expect(
      auth.login({ identifier: `${username}@${tenantCode}`, password: WRONG_STAFF_PW }, {}),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    const after = await auditRows('auth.login.success');
    expect(after).toHaveLength(before.length);
    const rows = await owner.query(
      'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND actor_user_id = $2',
      [tenantId, userId],
    );
    expect(rows.rows[0]?.n).toBe(0);
  });

  it('records logout only when a session was actually revoked', async () => {
    const username = `staff.logout.${uuidv7().slice(0, 6)}`;
    await createAccount({ username, role: 'FACTORY_OPERATOR', password: STAFF_PW });
    const login = await auth.login(
      { identifier: `${username}@${tenantCode}`, password: STAFF_PW },
      { ip: '203.0.113.31' },
    );
    if (login.kind !== 'session') {
      throw new Error('expected a session');
    }

    await auth.logout(login.refreshToken);
    const rows = await auditRows('auth.logout');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.actor_type).toBe('user');

    // A second logout with the same (now revoked) token is a silent no-op.
    await auth.logout(login.refreshToken);
    expect(await auditRows('auth.logout')).toHaveLength(1);
  });

  it('records rotated-token reuse and revokes the family', async () => {
    const username = `staff.reuse.${uuidv7().slice(0, 6)}`;
    await createAccount({ username, role: 'FACTORY_OPERATOR', password: STAFF_PW });
    const login = await auth.login(
      { identifier: `${username}@${tenantCode}`, password: STAFF_PW },
      { ip: '203.0.113.32' },
    );
    if (login.kind !== 'session') {
      throw new Error('expected a session');
    }
    const rotated = await auth.refresh(login.refreshToken, { ip: '203.0.113.32' });
    expect(rotated).not.toBeNull();

    await expect(auth.refresh(login.refreshToken, { ip: '203.0.113.32' })).rejects.toMatchObject({
      code: 'UNAUTHORIZED',
    });
    const rows = await auditRows('auth.refresh.reuse_detected');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.metadata).toMatchObject({ revoked: expect.any(Number) });

    // Replaying the same dead token changes nothing and writes no extra row.
    await expect(auth.refresh(login.refreshToken, {})).rejects.toMatchObject({
      code: 'UNAUTHORIZED',
    });
    expect(await auditRows('auth.refresh.reuse_detected')).toHaveLength(1);
  });

  it('records the BR-18 new-device revocation on a second driver login', async () => {
    const phone = `0912${String(randomInt(0, 10_000_000)).padStart(7, '0')}`;
    driverPhone = phone;
    await createAccount({ phone, role: 'DRIVER', password: DRIVER_PIN });

    const first = await auth.login({ identifier: phone, password: DRIVER_PIN }, {});
    expect(first.kind).toBe('session');
    const second = await auth.login({ identifier: phone, password: DRIVER_PIN }, {});
    expect(second.kind).toBe('session');

    const rows = await auditRows('auth.session.revoked_new_device');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.metadata).toMatchObject({ revoked: 1 });
  });

  it('records a password change in the same transaction as the new session', async () => {
    const username = `staff.change.${uuidv7().slice(0, 6)}`;
    await createAccount({ username, role: 'FACTORY_OPERATOR', password: STAFF_PW });
    const login = await auth.login(
      { identifier: `${username}@${tenantCode}`, password: STAFF_PW },
      { ip: '203.0.113.33' },
    );
    if (login.kind !== 'session') {
      throw new Error('expected a session');
    }

    const changed = await auth.changePassword(
      { currentPassword: STAFF_PW, newPassword: STAFF_NEW_PW },
      `Bearer ${login.tokens.accessToken}`,
      {},
    );
    expect(changed.tokens.accessToken.length).toBeGreaterThan(0);
    const rows = await auditRows('auth.password.changed');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.actor_type).toBe('user');
  });

  it('rolls the session back when the login audit write fails (fail-closed)', async () => {
    const username = `staff.auditdown.${uuidv7().slice(0, 6)}`;
    const userId = await createAccount({
      username,
      role: 'FACTORY_OPERATOR',
      password: STAFF_PW,
    });
    const failing = await buildAuthApp(
      {},
      [],
      { rateLimiter: { hit: async () => ({ allowed: true }) } },
      [
        {
          provide: AuditWriter,
          useValue: {
            append: async (): Promise<string> => {
              throw new Error('AUDIT_DOWN');
            },
          },
        },
      ],
    );
    try {
      const failingAuth = failing.get(AuthService);
      await expect(
        failingAuth.login({ identifier: `${username}@${tenantCode}`, password: STAFF_PW }, {}),
      ).rejects.toThrow('AUDIT_DOWN');
    } finally {
      await failing.close();
    }
    const sessions = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM auth_sessions WHERE tenant_id = $1 AND user_id = $2',
      [tenantId, userId],
    );
    expect(sessions.rows[0]?.n).toBe(0);
  });

  it('never stores a raw phone, password or token in the audit table', async () => {
    const dump = await owner.query<{ blob: string }>(
      `SELECT coalesce(
          (SELECT string_agg(to_jsonb(a)::text, ' ') FROM audit_logs a WHERE a.tenant_id = $1),
          ''
        ) AS blob`,
      [tenantId],
    );
    const blob = dump.rows[0]?.blob ?? '';
    if (driverPhone === null) {
      throw new Error('the driver fixture did not run');
    }
    for (const secret of [STAFF_PW, STAFF_NEW_PW, DRIVER_PIN, driverPhone]) {
      expect(blob).not.toContain(secret);
    }
  });
});

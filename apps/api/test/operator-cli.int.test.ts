import { randomBytes, randomInt } from 'node:crypto';

import type { NestExpressApplication } from '@nestjs/platform-express';
import type { Pool } from 'pg';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { inject } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { parseEnv } from '../src/config/env.js';
import { runCreateUser, runResetPassword, type CliIo } from '../src/cli/operator-cli.js';
import { PasswordService } from '../src/modules/auth/password.service.js';
import { assignRole, createTenant, createUser, ownerPool } from './setup/db.js';
import { buildAuthApp } from './setup/auth-app.js';

/**
 * T08 operator tooling: the CLI goes through the real services as bitabar_app
 * under TenantContext. Checks: production refusal, one-time password shown
 * once on stdout and nowhere else, forced change on first login, expiry, and
 * session revocation on reset.
 */

let app: NestExpressApplication;
let owner: Pool;
let passwords: PasswordService;

interface Capture {
  readonly io: CliIo;
  readonly out: string[];
  readonly err: string[];
}

function capture(): Capture {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (line) => out.push(line), err: (line) => err.push(line) }, out, err };
}

function cliEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    ...process.env,
    DATABASE_URL: inject('appUrl'),
    NODE_ENV: 'test',
    ...overrides,
  };
}

function printedPassword(capture: Capture): string {
  const line = capture.out.find((value) => value.includes('password:'));
  if (line === undefined) {
    throw new Error('CLI printed no password line');
  }
  const match = /password:\s*(\S+)/.exec(line);
  if (match?.[1] === undefined) {
    throw new Error('CLI password line is malformed');
  }
  return match[1];
}

function login(identifier: string, password: string) {
  return request(app.getHttpServer()).post('/api/v1/auth/login').send({ identifier, password });
}

async function liveSessions(userId: string): Promise<number> {
  const res = await owner.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM auth_sessions WHERE user_id = $1 AND revoked_at IS NULL',
    [userId],
  );
  return res.rows[0]?.n ?? 0;
}

describe('operator CLI (T08)', () => {
  beforeAll(async () => {
    app = await buildAuthApp({
      AUTH_RL_LOGIN_IP_PER_MIN: '10000',
      AUTH_RL_LOGIN_ACCOUNT_PER_MIN: '1000',
      AUTH_RL_LOGIN_TENANT_PER_MIN: '100000',
    });
    owner = ownerPool();
    passwords = new PasswordService(parseEnv(process.env));
  });

  afterAll(async () => {
    await app.close();
  });

  it('refuses to run in production without the explicit flag', async () => {
    const captureOut = capture();
    const code = await runCreateUser(
      ['--tenant', 'prod', '--username', 'prod.user', '--display-name', 'Prod'],
      {
        io: captureOut.io,
        env: cliEnv({
          NODE_ENV: 'production',
          DATABASE_URL: 'postgres://127.0.0.1:1/unreachable',
        }),
      },
    );
    expect(code).toBe(2);
    expect(captureOut.out).toEqual([]);
    expect(captureOut.err.join(' ')).toMatch(/production/);

    // Unset NODE_ENV is refused too (a production host may not export it).
    const unsetEnv = cliEnv({ DATABASE_URL: 'postgres://127.0.0.1:1/unreachable' });
    delete unsetEnv.NODE_ENV;
    const unset = capture();
    const unsetCode = await runCreateUser(
      ['--tenant', 'prod', '--username', 'prod.user', '--display-name', 'Prod'],
      { io: unset.io, env: unsetEnv },
    );
    expect(unsetCode).toBe(2);
    expect(unset.out).toEqual([]);

    // A stray `development` on a host pointing at a remote database is refused.
    const remote = capture();
    const remoteCode = await runCreateUser(
      ['--tenant', 'prod', '--username', 'prod.user', '--display-name', 'Prod'],
      {
        io: remote.io,
        env: cliEnv({
          NODE_ENV: 'development',
          DATABASE_URL: 'postgres://db.internal.example:5432/bitabar',
        }),
      },
    );
    expect(remoteCode).toBe(2);
    expect(remote.out).toEqual([]);
  });

  it('refuses reset-password outside development/test and never echoes bare values', async () => {
    const refused = capture();
    const code = await runResetPassword(['--tenant', 'prod', '--username', 'x'], {
      io: refused.io,
      env: cliEnv({ NODE_ENV: 'production', DATABASE_URL: 'postgres://127.0.0.1:1/none' }),
    });
    expect(code).toBe(2);
    expect(refused.out).toEqual([]);

    const positional = capture();
    const pasted = 'Accidentally-Pasted-Secret-1';
    const usageCode = await runCreateUser(['--tenant', 'x', pasted], {
      io: positional.io,
      env: cliEnv(),
    });
    expect(usageCode).toBe(2);
    expect(positional.err.join('\n')).not.toContain(pasted);
    expect(positional.err.join('\n')).toMatch(/positional/);
  });

  it('creates a user with an Argon2id one-time password shown exactly once', async () => {
    const code = `cli-${randomBytes(3).toString('hex')}`;
    const tenantId = await createTenant(owner, code);
    const username = 'cli.operator';
    const captureOut = capture();

    const exitCode = await runCreateUser(
      [
        '--tenant',
        code,
        '--username',
        username,
        '--display-name',
        'CLI Operator',
        '--role',
        'FACTORY_OPERATOR',
      ],
      { io: captureOut.io, env: cliEnv() },
    );

    expect(exitCode).toBe(0);
    expect(captureOut.err).toEqual([]);
    const password = printedPassword(captureOut);
    expect(password.length).toBeGreaterThanOrEqual(12);
    // Shown once and never echoed again.
    expect(captureOut.out.join('\n').split(password).length - 1).toBe(1);

    const { rows } = await owner.query<{
      user_id: string;
      password_hash: string;
      must_change_password: boolean;
      temporary_password_expires_at: Date | null;
    }>(
      `SELECT c.user_id, c.password_hash, c.must_change_password, c.temporary_password_expires_at
         FROM user_credentials c
         JOIN users u ON u.tenant_id = c.tenant_id AND u.id = c.user_id
        WHERE c.tenant_id = $1 AND u.username = $2`,
      [tenantId, username],
    );
    const row = rows[0];
    if (row === undefined) {
      throw new Error('CLI created no credential row');
    }
    expect(row.password_hash.startsWith('$argon2id$')).toBe(true);
    expect(row.password_hash.includes(password)).toBe(false);
    expect(row.must_change_password).toBe(true);
    expect(row.temporary_password_expires_at).not.toBeNull();
    const ttlMs = parseEnv(process.env).auth.tempPasswordTtlHours * 3_600_000;
    const remaining = (row.temporary_password_expires_at?.getTime() ?? 0) - Date.now();
    expect(remaining).toBeGreaterThan(ttlMs - 5 * 60_000);
    expect(remaining).toBeLessThanOrEqual(ttlMs);

    expect(await passwords.verify(row.password_hash, password)).toBe(true);

    // First login is forced change only: no access token, no refresh cookie.
    const firstLogin = await login(`${username}@${code}`, password);
    expect(firstLogin.status).toBe(200);
    const body = firstLogin.body as {
      data: { changeToken?: string; accessToken?: string };
    };
    expect(typeof body.data.changeToken).toBe('string');
    expect(body.data.accessToken).toBeUndefined();
    expect(firstLogin.headers['set-cookie']).toBeUndefined();

    // Past its expiry the one-time password is refused with the generic 401.
    await owner.query(
      `UPDATE user_credentials SET temporary_password_expires_at = now() - interval '1 minute'
        WHERE tenant_id = $1 AND user_id = $2`,
      [tenantId, row.user_id],
    );
    const expired = await login(`${username}@${code}`, password);
    expect(expired.status).toBe(401);
    expect(expired.body).toMatchObject({ error: { code: 'INVALID_CREDENTIALS' } });
  });

  it('creates a driver with a numeric PIN that satisfies the PIN policy', async () => {
    const code = `cli-${randomBytes(3).toString('hex')}`;
    await createTenant(owner, code);
    // Built at runtime from the gitleaks-allowlisted synthetic prefix, so no
    // out-of-range phone literal exists in the source.
    // 05–08 are unused by the other suites, so the driver fan-out cannot hit a
    // delayed row in another tenant (which would answer the generic 401).
    const phone = `0912000000${randomInt(5, 9)}`;
    const captureOut = capture();

    const exitCode = await runCreateUser(
      ['--tenant', code, '--phone', phone, '--display-name', 'CLI Driver', '--role', 'DRIVER'],
      { io: captureOut.io, env: cliEnv() },
    );

    expect(exitCode).toBe(0);
    const pin = printedPassword(captureOut);
    expect(pin).toMatch(/^\d{8,20}$/);
    const firstLogin = await login(phone, pin);
    expect(firstLogin.status).toBe(200);
    expect(
      (firstLogin.body as { data: { changeToken?: string; accessToken?: string } }).data
        .changeToken,
    ).toBeTypeOf('string');

    // Duplicate phone in the same tenant is refused, with no password printed.
    const duplicate = capture();
    const duplicateCode = await runCreateUser(
      [
        '--tenant',
        code,
        '--phone',
        phone,
        '--display-name',
        'Duplicate Driver',
        '--role',
        'DRIVER',
      ],
      { io: duplicate.io, env: cliEnv() },
    );
    expect(duplicateCode).toBe(1);
    expect(duplicate.out).toEqual([]);
  });

  it('resets the password, revokes every session and invalidates the old password', async () => {
    const code = `cli-${randomBytes(3).toString('hex')}`;
    const tenantId = await createTenant(owner, code);
    const username = 'cli.reset';
    const knownPassword = 'Known-Password!2026';
    const userId = await createUser(owner, tenantId, { username, displayName: 'Reset User' });
    await assignRole(owner, tenantId, userId, 'FACTORY_OPERATOR', 'tenant');
    await owner.query(
      `INSERT INTO user_credentials
         (id, tenant_id, user_id, password_hash, must_change_password, temporary_password_expires_at)
       VALUES ($1, $2, $3, $4, false, NULL)`,
      [uuidv7(), tenantId, userId, await passwords.hash(knownPassword)],
    );

    const session = await login(`${username}@${code}`, knownPassword);
    expect(session.status).toBe(200);
    expect(await liveSessions(userId)).toBe(1);

    const captureOut = capture();
    const exitCode = await runResetPassword(['--tenant', code, '--username', username], {
      io: captureOut.io,
      env: cliEnv(),
    });

    expect(exitCode).toBe(0);
    expect(captureOut.err).toEqual([]);
    const newPassword = printedPassword(captureOut);
    expect(captureOut.out.join('\n').split(newPassword).length - 1).toBe(1);
    expect(await liveSessions(userId)).toBe(0);

    // New password first: a successful login clears the A2 delay counters, so
    // the deliberate wrong-password attempt below cannot delay later checks.
    const newLogin = await login(`${username}@${code}`, newPassword);
    expect(newLogin.status).toBe(200);
    const body = newLogin.body as { data: { changeToken?: string; accessToken?: string } };
    expect(body.data.changeToken).toBeTypeOf('string');
    expect(body.data.accessToken).toBeUndefined();
    const oldLogin = await login(`${username}@${code}`, knownPassword);
    expect(oldLogin.status).toBe(401);

    const { rows } = await owner.query<{
      must_change_password: boolean;
      temporary_password_expires_at: Date | null;
    }>(
      `SELECT must_change_password, temporary_password_expires_at
         FROM user_credentials WHERE tenant_id = $1 AND user_id = $2`,
      [tenantId, userId],
    );
    expect(rows[0]?.must_change_password).toBe(true);
    expect(rows[0]?.temporary_password_expires_at).not.toBeNull();

    // Unknown user and existing credential are refused, no password printed.
    const unknown = capture();
    const unknownCode = await runResetPassword(['--tenant', code, '--username', 'ghost.user'], {
      io: unknown.io,
      env: cliEnv(),
    });
    expect(unknownCode).toBe(1);
    expect(unknown.out).toEqual([]);

    const duplicate = capture();
    const duplicateCode = await runCreateUser(
      ['--tenant', code, '--username', username, '--display-name', 'Duplicate'],
      { io: duplicate.io, env: cliEnv() },
    );
    expect(duplicateCode).toBe(1);
    expect(duplicate.out).toEqual([]);
  });
});

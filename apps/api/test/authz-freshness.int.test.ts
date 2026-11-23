import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import { Controller, Get, Module } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';
import { z } from 'zod';

import { TenantContext } from '../src/db/tenant-context.js';
import { PasswordService } from '../src/modules/auth/password.service.js';
import { TokenService } from '../src/modules/auth/token.service.js';
import { UsersRepository } from '../src/modules/users/users.repository.js';
import { RequirePermission, ZodBody } from '../src/security/authz/decorators.js';
import { sensitiveReasonSchema } from '../src/security/authz/sensitive-reason.js';
import { buildAuthApp, CSRF_HEADERS } from './setup/auth-app.js';
import {
  assignRole as assignRoleFixture,
  createTenant,
  createUser,
  ownerPool,
} from './setup/db.js';

/**
 * Sensitive-authorization freshness and Z7 transaction guarantees (ADR-008
 * Z6/Z7, CP1 SR-06). Runs against real PostgreSQL as the runtime role. The
 * probe route exists only in this test module.
 */
@Controller('authz-freshness')
class FreshnessProbeController {
  @RequirePermission('carrier_membership.write')
  @Get('probe')
  probe(@ZodBody(z.strictObject({ reason: sensitiveReasonSchema })) body: { reason: string }): {
    ok: true;
    length: number;
  } {
    return { ok: true, length: body.reason.length };
  }
}

@Module({ controllers: [FreshnessProbeController] })
class FreshnessProbeModule {}

const PASSWORD = 'Freshness!Pass9';
const REASON = 'valid reason';
const SENSITIVE_ROUTE = '/api/v1/authz-freshness/probe';

type Role = 'FACTORY_OPERATOR' | 'CARRIER_ADMIN' | 'DRIVER';
const ROLE_SCOPE: Record<Role, string> = {
  FACTORY_OPERATOR: 'tenant',
  CARRIER_ADMIN: 'carrier',
  DRIVER: 'driver',
};

let app: NestExpressApplication;
let owner: ReturnType<typeof ownerPool>;
let passwords: PasswordService;
let tokens: TokenService;
let tenantContext: TenantContext;
let users: UsersRepository;
let counter = 0;

interface Account {
  readonly tenantId: string;
  readonly userId: string;
  readonly tenantCode: string;
  readonly username: string;
  readonly accessToken: string;
  readonly refreshCookie: string;
  readonly sessionId: string;
}

beforeAll(async () => {
  app = await buildAuthApp(
    {
      AUTH_RL_LOGIN_IP_PER_MIN: '10000',
      AUTH_RL_LOGIN_ACCOUNT_PER_MIN: '1000',
      AUTH_RL_LOGIN_TENANT_PER_MIN: '10000',
    },
    [FreshnessProbeModule],
  );
  owner = ownerPool();
  passwords = app.get(PasswordService);
  tokens = app.get(TokenService);
  tenantContext = app.get(TenantContext);
  users = app.get(UsersRepository);
}, 120000);

afterAll(async () => {
  await app?.close();
});

function refreshCookieOf(response: request.Response): string {
  const raw = response.headers['set-cookie'];
  const cookies = raw === undefined ? [] : Array.isArray(raw) ? raw : [raw];
  const cookie = cookies.find((value) => value.startsWith('bitabar_refresh='));
  return cookie === undefined ? '' : (cookie.split(';')[0] ?? '');
}

async function createAccount(role: Role): Promise<{
  tenantId: string;
  userId: string;
  tenantCode: string;
  username: string;
}> {
  counter += 1;
  const tenantCode = `fresh-${counter}-${randomBytes(3).toString('hex')}`;
  const username = `fresh${counter}`;
  const tenantId = await createTenant(owner, tenantCode);
  const userId = await createUser(owner, tenantId, { username });
  await assignRoleFixture(owner, tenantId, userId, role, ROLE_SCOPE[role]);
  const hash = await passwords.hash(PASSWORD);
  await owner.query(
    `INSERT INTO user_credentials
       (id, tenant_id, user_id, password_hash, must_change_password, temporary_password_expires_at)
     VALUES ($1, $2, $3, $4, false, null)`,
    [uuidv7(), tenantId, userId, hash],
  );
  return { tenantId, userId, tenantCode, username };
}

async function login(account: {
  tenantId: string;
  userId: string;
  tenantCode: string;
  username: string;
}): Promise<Account> {
  const response = await request(app.getHttpServer())
    .post('/api/v1/auth/login')
    .send({ identifier: `${account.username}@${account.tenantCode}`, password: PASSWORD })
    .expect(200);
  const body = response.body as { data: { accessToken: string } };
  const claims = await tokens.verifyAccessToken(body.data.accessToken);
  return {
    ...account,
    accessToken: body.data.accessToken,
    refreshCookie: refreshCookieOf(response),
    sessionId: claims.sid,
  };
}

async function accountWithRole(role: Role): Promise<Account> {
  return login(await createAccount(role));
}

function probe(accessToken: string): request.Test {
  return request(app.getHttpServer())
    .get(SENSITIVE_ROUTE)
    .set('authorization', `Bearer ${accessToken}`)
    .send({ reason: REASON });
}

async function sessionRevokedReason(sessionId: string): Promise<string | null> {
  const result = await owner.query<{ revoke_reason: string | null }>(
    'SELECT revoke_reason FROM auth_sessions WHERE id = $1',
    [sessionId],
  );
  return result.rows[0]?.revoke_reason ?? null;
}

describe('sensitive authorization — fresh state', () => {
  it('allows an active operator with a live session and denies a carrier', async () => {
    const operator = await accountWithRole('FACTORY_OPERATOR');
    const carrier = await accountWithRole('CARRIER_ADMIN');
    await probe(operator.accessToken).expect(200);
    await probe(carrier.accessToken).expect(403);
  });

  it('rejects a logged-out session even though the access token is unexpired', async () => {
    const account = await accountWithRole('FACTORY_OPERATOR');
    await request(app.getHttpServer())
      .post('/api/v1/auth/logout')
      .set('Cookie', account.refreshCookie)
      .set(CSRF_HEADERS)
      .expect(200);
    const response = await probe(account.accessToken).expect(401);
    expect(response.body.error.code).toBe('UNAUTHORIZED');
  });

  it('rejects a session revoked by a role change', async () => {
    const account = await accountWithRole('FACTORY_OPERATOR');
    await tenantContext.run({ tenantId: account.tenantId }, () =>
      users.revokeRole(account.userId, 'FACTORY_OPERATOR'),
    );
    await probe(account.accessToken).expect(401);
    expect(await sessionRevokedReason(account.sessionId)).toBe('role_change');
  });

  it('rejects a disabled user', async () => {
    const account = await accountWithRole('FACTORY_OPERATOR');
    await owner.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [account.userId]);
    await probe(account.accessToken).expect(401);
  });

  it('rejects a suspended tenant', async () => {
    const account = await accountWithRole('FACTORY_OPERATOR');
    await owner.query(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, [account.tenantId]);
    await probe(account.accessToken).expect(401);
  });

  it('rejects a soft-deleted user', async () => {
    const account = await accountWithRole('FACTORY_OPERATOR');
    await owner.query(`UPDATE users SET deleted_at = now() WHERE id = $1`, [account.userId]);
    await probe(account.accessToken).expect(401);
  });

  it('rejects a soft-deleted tenant', async () => {
    const account = await accountWithRole('FACTORY_OPERATOR');
    await owner.query(`UPDATE tenants SET deleted_at = now() WHERE id = $1`, [account.tenantId]);
    await probe(account.accessToken).expect(401);
  });

  it('rejects an expired session', async () => {
    const account = await accountWithRole('FACTORY_OPERATOR');
    await owner.query(
      `UPDATE auth_sessions SET expires_at = now() - interval '1 minute' WHERE id = $1`,
      [account.sessionId],
    );
    await probe(account.accessToken).expect(401);
  });

  it('does not grant a token role that the DB no longer has', async () => {
    const carrier = await accountWithRole('CARRIER_ADMIN');
    const forged = await tokens.signAccessToken({
      userId: carrier.userId,
      tenantId: carrier.tenantId,
      sessionId: carrier.sessionId,
      roles: ['FACTORY_OPERATOR'],
    });
    await probe(forged).expect(403);
  });

  it('does not grant a DB role that the token does not carry', async () => {
    const operator = await accountWithRole('FACTORY_OPERATOR');
    const forged = await tokens.signAccessToken({
      userId: operator.userId,
      tenantId: operator.tenantId,
      sessionId: operator.sessionId,
      roles: ['CARRIER_ADMIN'],
    });
    await probe(forged).expect(403);
  });
});

describe('refresh transaction (Z7a) and role-change revocation (Z7b)', () => {
  it('mints a new token from roles read in the rotation transaction', async () => {
    const account = await accountWithRole('FACTORY_OPERATOR');
    // Bypass the repository so the session stays live while DB roles change.
    await owner.query(`DELETE FROM user_roles WHERE tenant_id = $1 AND user_id = $2`, [
      account.tenantId,
      account.userId,
    ]);
    await owner.query(
      `INSERT INTO user_roles (tenant_id, user_id, role_code, role_scope)
       VALUES ($1, $2, 'DRIVER', 'driver')`,
      [account.tenantId, account.userId],
    );

    const response = await request(app.getHttpServer())
      .post('/api/v1/auth/refresh')
      .set('Cookie', account.refreshCookie)
      .set(CSRF_HEADERS)
      .expect(200);
    const body = response.body as { data: { accessToken: string } };
    const claims = await tokens.verifyAccessToken(body.data.accessToken);
    expect(claims.roles).toEqual(['DRIVER']);
    // The sensitive route still requires FACTORY_OPERATOR, so the fresh token
    // cannot perform it.
    await probe(body.data.accessToken).expect(403);
  });

  it('revokes the session when refresh sees a disabled user', async () => {
    const account = await accountWithRole('FACTORY_OPERATOR');
    await owner.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [account.userId]);
    await request(app.getHttpServer())
      .post('/api/v1/auth/refresh')
      .set('Cookie', account.refreshCookie)
      .set(CSRF_HEADERS)
      .expect(401);
    expect(await sessionRevokedReason(account.sessionId)).toBe('disabled');
  });

  it('assignRole revokes all live sessions in the same transaction', async () => {
    const account = await accountWithRole('CARRIER_ADMIN');
    const second = await login(account);
    await tenantContext.run({ tenantId: account.tenantId }, () =>
      users.assignRole(account.userId, 'FACTORY_OPERATOR'),
    );
    await probe(account.accessToken).expect(401);
    await probe(second.accessToken).expect(401);
    const rows = await owner.query<{ revoked_reason: string | null }>(
      'SELECT revoke_reason AS revoked_reason FROM auth_sessions WHERE user_id = $1',
      [account.userId],
    );
    expect(rows.rows).toHaveLength(2);
    expect(rows.rows.every((row) => row.revoked_reason === 'role_change')).toBe(true);
  });

  it('revokeRole revokes all live sessions in the same transaction', async () => {
    const account = await accountWithRole('CARRIER_ADMIN');
    const second = await login(account);
    const removed = await tenantContext.run({ tenantId: account.tenantId }, () =>
      users.revokeRole(account.userId, 'CARRIER_ADMIN'),
    );
    expect(removed).toBe(true);
    await probe(account.accessToken).expect(401);
    await probe(second.accessToken).expect(401);
    const rows = await owner.query<{ revoked_reason: string | null }>(
      'SELECT revoke_reason AS revoked_reason FROM auth_sessions WHERE user_id = $1',
      [account.userId],
    );
    expect(rows.rows).toHaveLength(2);
    expect(rows.rows.every((row) => row.revoked_reason === 'role_change')).toBe(true);
  });
});

import { randomBytes } from 'node:crypto';

import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { beforeAll, describe, expect, it } from 'vitest';

import { AuditStore } from '../src/db/audit-store.js';
import { AuthLookupService } from '../src/db/auth-lookup.service.js';
import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb } from '../src/db/tenant-db.js';
import { AuditWriter } from '../src/modules/audit/audit-writer.js';
import { generateRefreshToken, hashRefreshToken } from '../src/modules/auth/refresh-token.js';
import { SessionRepository } from '../src/modules/auth/session.repository.js';
import {
  REFRESH_SESSION_TTL_SECONDS,
  SessionService,
  type RotatedSession,
} from '../src/modules/auth/session.service.js';
import { appPool, createTenant, createUser, ownerPool, testPii } from './setup/db.js';

/**
 * Refresh-session lifecycle against real PostgreSQL (ADR-007 A8–A10, T05):
 * hash-at-rest, rotation chain, reuse revocation, atomic concurrency, logout,
 * password-change revocation and the BR-18 single-session hook. Every service
 * call runs as `bitabar_app`; the owner pool is used only for fixtures and
 * assertions about final row state.
 */

const db = () => drizzle(appPool(), { schema });
const context = new TenantContext();
const tenantDb = new TenantDb(db());
const repository = new SessionRepository(tenantDb, context);
const audit = new AuditWriter(context, testPii(), new AuditStore(tenantDb));
const service = new SessionService(
  new AuthLookupService(db()),
  context,
  tenantDb,
  repository,
  audit,
);

let owner: Pool;
let tenantA: string;
let tenantB: string;
let userA1: string;
let userA2: string;
let brUser: string;
let allUser: string;
let userB: string;

interface SessionRow {
  id: string;
  tenant_id: string;
  user_id: string;
  family_id: string;
  refresh_hash: Buffer;
  previous_refresh_hash: Buffer | null;
  rotated_at: Date | null;
  revoked_at: Date | null;
  revoke_reason: string | null;
  last_used_at: Date | null;
  expires_at: Date;
  user_agent: string | null;
  ip: string | null;
}

/** Row lookup for assertions; a missing row is a test failure, not a value. */
async function sessionRow(id: string): Promise<SessionRow> {
  const res = await owner.query<SessionRow>('SELECT * FROM auth_sessions WHERE id = $1', [id]);
  const row = res.rows[0];
  if (!row) {
    throw new Error('expected the session row to exist');
  }
  return row;
}

function requireRotated(value: RotatedSession | null): RotatedSession {
  if (value === null) {
    throw new Error('expected the rotation to succeed');
  }
  return value;
}

function requireHash(value: Buffer | null): Buffer {
  if (value === null) {
    throw new Error('expected a stored previous-refresh hash');
  }
  return value;
}

function issue(userId: string = userA1, tenantId: string = tenantA) {
  return context.run({ tenantId }, () =>
    service.issue(userId, { ip: '203.0.113.7', userAgent: 'int-test' }),
  );
}

describe('SessionService (ADR-007 A8–A10)', () => {
  beforeAll(async () => {
    owner = ownerPool();
    const suffix = randomBytes(4).toString('hex');
    tenantA = await createTenant(owner, `ss-a-${suffix}`);
    tenantB = await createTenant(owner, `ss-b-${suffix}`);
    userA1 = await createUser(owner, tenantA, { username: 'ss.a1' });
    userA2 = await createUser(owner, tenantA, { username: 'ss.a2' });
    brUser = await createUser(owner, tenantA, { username: 'ss.br' });
    allUser = await createUser(owner, tenantA, { username: 'ss.all' });
    userB = await createUser(owner, tenantB, { username: 'ss.b1' });
  });

  it('issues a session that stores only the SHA-256 hash — never the token', async () => {
    const issued = await issue();
    const row = await sessionRow(issued.sessionId);
    expect(row).toMatchObject({
      tenant_id: tenantA,
      user_id: userA1,
      family_id: issued.familyId,
      rotated_at: null,
      revoked_at: null,
      revoke_reason: null,
      user_agent: 'int-test',
      ip: '203.0.113.7',
    });
    expect(row.refresh_hash.equals(hashRefreshToken(issued.refreshToken))).toBe(true);
    expect(JSON.stringify(row)).not.toContain(issued.refreshToken);
    const expected = Date.now() + REFRESH_SESSION_TTL_SECONDS * 1000;
    expect(Math.abs(new Date(row.expires_at).getTime() - expected)).toBeLessThan(5000);
  });

  it('refuses to issue without a tenant context', async () => {
    await expect(service.issue(userA1)).rejects.toMatchObject({ code: 'TENANT_CONTEXT_MISSING' });
  });

  it('rotates: the new hash becomes current, the old one moves to previous', async () => {
    const first = await issue();
    const second = requireRotated(
      await service.rotate(first.refreshToken, { ip: '203.0.113.8', userAgent: 'rotated-ua' }),
    );
    expect(second).toMatchObject({
      sessionId: first.sessionId,
      familyId: first.familyId,
      tenantId: tenantA,
      userId: userA1,
    });
    const row = await sessionRow(first.sessionId);
    expect(row.refresh_hash.equals(hashRefreshToken(second.refreshToken))).toBe(true);
    expect(
      requireHash(row.previous_refresh_hash).equals(hashRefreshToken(first.refreshToken)),
    ).toBe(true);
    expect(row.rotated_at).not.toBeNull();
    expect(row.last_used_at).not.toBeNull();
    expect(row.user_agent).toBe('rotated-ua');
    // One row per session — rotation updates, never inserts.
    const count = await owner.query<{ n: string }>(
      'SELECT count(*)::text AS n FROM auth_sessions WHERE family_id = $1',
      [first.familyId],
    );
    expect(count.rows[0]?.n).toBe('1');
    // The chain continues from the new token.
    await expect(service.rotate(second.refreshToken)).resolves.not.toBeNull();
  });

  it('detects reuse of a rotated token: the whole family is revoked', async () => {
    const first = await issue();
    const second = requireRotated(await service.rotate(first.refreshToken));
    await expect(service.rotate(first.refreshToken)).resolves.toBeNull();
    const row = await sessionRow(first.sessionId);
    expect(row.revoked_at).not.toBeNull();
    expect(row.revoke_reason).toBe('reuse_detected');
    // Even the newest token of the family is dead.
    await expect(service.rotate(second.refreshToken)).resolves.toBeNull();
  });

  it('returns null for unknown, malformed and expired tokens alike', async () => {
    await expect(service.rotate(generateRefreshToken())).resolves.toBeNull();
    await expect(service.rotate('not-a-token')).resolves.toBeNull();
    await expect(service.rotate('')).resolves.toBeNull();

    const expired = await issue();
    await owner.query(
      `UPDATE auth_sessions SET expires_at = now() - interval '1 minute' WHERE id = $1`,
      [expired.sessionId],
    );
    await expect(service.rotate(expired.refreshToken)).resolves.toBeNull();
    expect((await sessionRow(expired.sessionId)).revoked_at).toBeNull();
  });

  it('50 concurrent refreshes of one token yield exactly one success', async () => {
    const issued = await issue();
    const attempts = await Promise.all(
      Array.from({ length: 50 }, () => service.rotate(issued.refreshToken)),
    );
    const winners = attempts.filter((result) => result !== null);
    expect(winners).toHaveLength(1);
    const winner = winners[0];
    if (!winner) {
      throw new Error('expected exactly one winning rotation');
    }
    // The losers replayed a rotated-out token: the family was revoked as reuse.
    const row = await sessionRow(issued.sessionId);
    expect(row.revoked_at).not.toBeNull();
    expect(row.revoke_reason).toBe('reuse_detected');
    await expect(service.rotate(winner.refreshToken)).resolves.toBeNull();
  });

  it('logout revokes the session, is idempotent and never throws on junk input', async () => {
    const issued = await issue();
    await service.revokeByToken(issued.refreshToken);
    const row = await sessionRow(issued.sessionId);
    expect(row.revoked_at).not.toBeNull();
    expect(row.revoke_reason).toBe('logout');
    await expect(service.revokeByToken(issued.refreshToken)).resolves.toBeUndefined();
    await expect(service.revokeByToken('junk')).resolves.toBeUndefined();
    await expect(service.revokeByToken(generateRefreshToken())).resolves.toBeUndefined();
    await expect(service.rotate(issued.refreshToken)).resolves.toBeNull();
  });

  it('logout with a rotated-out token follows the reuse rule', async () => {
    const first = await issue();
    await service.rotate(first.refreshToken);
    await service.revokeByToken(first.refreshToken);
    const row = await sessionRow(first.sessionId);
    expect(row.revoke_reason).toBe('reuse_detected');
  });

  it('revokeAllForUser revokes every live session of that user only', async () => {
    const one = await issue(allUser);
    const two = await issue(allUser);
    const bystander = await issue(userA2);
    const revoked = await context.run({ tenantId: tenantA }, () =>
      service.revokeAllForUser(allUser),
    );
    expect(revoked).toBe(2);
    for (const sessionId of [one.sessionId, two.sessionId]) {
      const row = await sessionRow(sessionId);
      expect(row.revoked_at).not.toBeNull();
      expect(row.revoke_reason).toBe('password_change');
    }
    expect((await sessionRow(bystander.sessionId)).revoked_at).toBeNull();
  });

  it('BR-18 hook: revokeOtherSessions keeps the newest session and revokes the rest', async () => {
    const older = await issue(brUser);
    const newer = await issue(brUser);
    const revoked = await context.run({ tenantId: tenantA }, () =>
      service.revokeOtherSessions(brUser, newer.sessionId),
    );
    expect(revoked).toBe(1);
    const oldRow = await sessionRow(older.sessionId);
    expect(oldRow.revoked_at).not.toBeNull();
    expect(oldRow.revoke_reason).toBe('sibling');
    expect((await sessionRow(newer.sessionId)).revoked_at).toBeNull();
    await expect(service.rotate(newer.refreshToken)).resolves.not.toBeNull();
  });

  it('tenant B sessions rotate under tenant B, and tenant A cannot revoke them', async () => {
    const issued = await issue(userB, tenantB);
    const denied = await context.run({ tenantId: tenantA }, () =>
      repository.revokeSession(issued.sessionId, 'intruder'),
    );
    expect(denied).toBe(false);
    expect((await sessionRow(issued.sessionId)).revoked_at).toBeNull();
    await expect(service.rotate(issued.refreshToken)).resolves.not.toBeNull();
  });
});

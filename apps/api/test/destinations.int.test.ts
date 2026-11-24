import { randomBytes } from 'node:crypto';

import type { NestExpressApplication } from '@nestjs/platform-express';
import type { Pool } from 'pg';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { TokenService } from '../src/modules/auth/token.service.js';
import { buildAuthApp } from './setup/auth-app.js';
import { createTenant, createUser, ownerPool } from './setup/db.js';

/**
 * Destinations end-to-end over HTTP and real PostgreSQL (F1-07 T04,
 * ADR-011). The first real business endpoint, so this file is the template:
 * permissions, tenant scope, strict input, pagination/sort/q, optimistic
 * concurrency, soft delete, audit atomicity and idempotency.
 */

const API = '/api/v1/base/destinations';

let app: NestExpressApplication;
let owner: Pool;
let tenantA: string;
let tenantB: string;
let userA: string;
let userB: string;
let tokenA: string;
let tokenB: string;
let carrierToken: string;
let driverToken: string;

function auth(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

function idemKey(): string {
  return `dest-${uuidv7()}`;
}

/** Unique per call; uuidv7's leading hex is a shared timestamp, not a random tag. */
function tag(): string {
  return randomBytes(4).toString('hex');
}

function agent() {
  return request(app.getHttpServer());
}

function create(
  body: Record<string, unknown>,
  options: { token?: string; key?: string | null; query?: Record<string, string> } = {},
) {
  let call = agent()
    .post(API)
    .set(auth(options.token ?? tokenA));
  if (options.key !== null) {
    call = call.set('idempotency-key', options.key ?? idemKey());
  }
  return call.query(options.query ?? {}).send(body);
}

async function createOk(body: Record<string, unknown>): Promise<{ id: string; version: number }> {
  const res = await create(body);
  if (res.status !== 201) {
    throw new Error(`create failed: ${res.status} ${res.text}`);
  }
  return res.body.data as { id: string; version: number };
}

function liveCount(tenantId: string): Promise<number> {
  return owner
    .query<{ n: number }>(
      'SELECT count(*)::int AS n FROM destinations WHERE tenant_id = $1 AND deleted_at IS NULL',
      [tenantId],
    )
    .then((res) => res.rows[0]?.n ?? 0);
}

function auditCount(tenantId: string, resourceId: string): Promise<number> {
  return owner
    .query<{ n: number }>(
      'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2',
      [tenantId, resourceId],
    )
    .then((res) => res.rows[0]?.n ?? 0);
}

interface AuditRow {
  action: string;
  actor_user_id: string | null;
  actor_session_id: string | null;
  resource_type: string;
  http_status: number | null;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
}

async function auditRows(tenantId: string, resourceId: string): Promise<AuditRow[]> {
  const res = await owner.query<AuditRow>(
    `SELECT action, actor_user_id, actor_session_id, resource_type, http_status, before, after
       FROM audit_logs
      WHERE tenant_id = $1 AND resource_id = $2
      ORDER BY occurred_at, id`,
    [tenantId, resourceId],
  );
  return res.rows;
}

beforeAll(async () => {
  app = await buildAuthApp();
  owner = ownerPool();
  const suffix = tag();
  tenantA = await createTenant(owner, `dest-a-${suffix}`);
  tenantB = await createTenant(owner, `dest-b-${suffix}`);
  userA = await createUser(owner, tenantA, { username: `dest.op.a.${suffix}` });
  userB = await createUser(owner, tenantB, { username: `dest.op.b.${suffix}` });
  const tokens = app.get(TokenService);
  const sessionA = uuidv7();
  const sessionB = uuidv7();
  tokenA = await tokens.signAccessToken({
    userId: userA,
    tenantId: tenantA,
    sessionId: sessionA,
    roles: ['FACTORY_OPERATOR'],
  });
  tokenB = await tokens.signAccessToken({
    userId: userB,
    tenantId: tenantB,
    sessionId: sessionB,
    roles: ['FACTORY_OPERATOR'],
  });
  carrierToken = await tokens.signAccessToken({
    userId: userA,
    tenantId: tenantA,
    sessionId: sessionA,
    roles: ['CARRIER_ADMIN'],
  });
  driverToken = await tokens.signAccessToken({
    userId: userA,
    tenantId: tenantA,
    sessionId: sessionA,
    roles: ['DRIVER'],
  });
}, 120_000);

afterAll(async () => {
  await app?.close();
});

describe('destinations — access control', () => {
  it('answers 401 to every route without a token', async () => {
    const id = uuidv7();
    await agent().get(API).expect(401);
    await agent().get(`${API}/${id}`).expect(401);
    await agent().post(API).send({ name: 'Anon' }).expect(401);
    await agent().patch(`${API}/${id}`).send({ isActive: false, expectedVersion: 1 }).expect(401);
    await agent().delete(`${API}/${id}`).query({ expectedVersion: 1 }).expect(401);
  });

  it('denies CARRIER_ADMIN and DRIVER with byte-identical 403 bodies', async () => {
    const carrier = await agent().get(API).set(auth(carrierToken)).expect(403);
    const driver = await agent().get(API).set(auth(driverToken)).expect(403);
    expect(carrier.body).toEqual(driver.body);
    expect(JSON.stringify(carrier.body)).not.toMatch(/destination|FACTORY_OPERATOR|permission/i);

    const carrierWrite = await create(
      { name: 'Denied' },
      { token: carrierToken, key: idemKey() },
    ).expect(403);
    const driverWrite = await create(
      { name: 'Denied' },
      { token: driverToken, key: idemKey() },
    ).expect(403);
    expect(carrierWrite.body).toEqual(driverWrite.body);
  });
});

describe('destinations — CRUD, pagination and view', () => {
  it('creates 201, reads it back, updates with CAS, soft-deletes 204', async () => {
    const t = tag();
    const firstName = `کارخانه شرق ${t}`;
    const secondName = `کارخانه غرب ${t}`;
    const created = await agent()
      .post(API)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ name: firstName, provinceName: 'کرمان', displayOrder: 2 })
      .expect(201);
    const dto = created.body.data as {
      id: string;
      name: string;
      provinceName: string | null;
      isActive: boolean;
      displayOrder: number;
      version: number;
      createdAt: string;
      updatedAt: string;
    };
    expect(dto).toMatchObject({
      name: firstName,
      provinceName: 'کرمان',
      isActive: true,
      displayOrder: 2,
      version: 1,
    });
    expect(dto.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(dto).not.toHaveProperty('nameKey');
    expect(dto).not.toHaveProperty('tenantId');
    expect(dto).not.toHaveProperty('deletedAt');

    const read = await agent().get(`${API}/${dto.id}`).set(auth(tokenA)).expect(200);
    expect(read.body.data).toEqual(dto);

    const patched = await agent()
      .patch(`${API}/${dto.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ name: secondName, displayOrder: 5, expectedVersion: 1 })
      .expect(200);
    expect(patched.body.data).toMatchObject({
      id: dto.id,
      name: secondName,
      provinceName: 'کرمان',
      displayOrder: 5,
      version: 2,
    });

    const removed = await agent()
      .delete(`${API}/${dto.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 2 })
      .expect(204);
    expect(removed.text).toBe('');

    await agent().get(`${API}/${dto.id}`).set(auth(tokenA)).expect(404);
    const list = await agent().get(API).set(auth(tokenA)).expect(200);
    expect((list.body.data as { id: string }[]).some((row) => row.id === dto.id)).toBe(false);
  });

  it('lists with default page size, paging metadata and the isActive filter', async () => {
    const t = tag();
    const word = `List${t}`;
    const first = await createOk({ name: `${word} A ${t}`, isActive: false, displayOrder: 1 });
    const second = await createOk({ name: `${word} B ${t}`, isActive: true, displayOrder: 2 });
    const third = await createOk({ name: `${word} C ${t}`, isActive: true, displayOrder: 3 });

    const page = await agent()
      .get(API)
      .query({ page: 1, pageSize: 2, isActive: 'true', q: word })
      .set(auth(tokenA))
      .expect(200);
    expect(page.body.meta).toEqual({ page: 1, pageSize: 2, total: 2 });
    expect(page.body.data.map((row: { id: string }) => row.id)).toEqual([second.id, third.id]);

    const inactive = await agent()
      .get(API)
      .query({ isActive: 'false', q: word })
      .set(auth(tokenA))
      .expect(200);
    expect(inactive.body.data.map((row: { id: string }) => row.id)).toEqual([first.id]);

    // No pageSize in the request: the shared default of 50 applies.
    const defaults = await agent().get(API).query({ q: word }).set(auth(tokenA)).expect(200);
    expect(defaults.body.meta).toEqual({ page: 1, pageSize: 50, total: 3 });
  });

  it('enforces page/pageSize bounds and sort allowlist', async () => {
    for (const query of [
      { pageSize: 101 },
      { pageSize: 0 },
      { page: 0 },
      { page: 'x' },
      { sort: 'tenantId' },
      { sort: 'name,name' },
      { sort: '+name' },
      { sort: '' },
      { sort: 'displayOrder,' },
      { isActive: '1' },
      { tenantId: tenantA },
      { nameKey: 'x' },
      { q: 'x'.repeat(65) },
      { q: '   ' },
    ]) {
      const res = await agent().get(API).query(query).set(auth(tokenA));
      expect(res.status, JSON.stringify(query)).toBe(400);
    }
    const sorted = await agent()
      .get(API)
      .query({ sort: '-createdAt', pageSize: 100 })
      .set(auth(tokenA))
      .expect(200);
    expect(sorted.body.meta.pageSize).toBe(100);

    // A huge but allowed page is a clean empty page; beyond the safe OFFSET
    // bound it is a 400. Neither may become a 500.
    const huge = await agent()
      .get(API)
      .query({ page: 1_000_000_000 })
      .set(auth(tokenA))
      .expect(200);
    expect(huge.body.data).toEqual([]);
    expect(huge.body.meta.page).toBe(1_000_000_000);
    await agent().get(API).query({ page: 1_000_000_001 }).set(auth(tokenA)).expect(400);
  });

  it('escapes LIKE metacharacters in q', async () => {
    const t = tag();
    const percent = await createOk({ name: `100% ${t}` });
    const x = await createOk({ name: `100x ${t}` });
    const underscore = await createOk({ name: `a_b ${t}` });
    const plain = await createOk({ name: `axb ${t}` });

    const p = await agent()
      .get(API)
      .query({ q: `100% ${t}` })
      .set(auth(tokenA))
      .expect(200);
    expect(p.body.data.map((row: { id: string }) => row.id)).toEqual([percent.id]);

    const u = await agent()
      .get(API)
      .query({ q: `a_b ${t}` })
      .set(auth(tokenA))
      .expect(200);
    expect(u.body.data.map((row: { id: string }) => row.id)).toEqual([underscore.id]);
    expect(u.body.data.map((row: { id: string }) => row.id)).not.toContain(plain.id);
    expect(u.body.data.map((row: { id: string }) => row.id)).not.toContain(x.id);
  });

  it('normalizes q before the search (Persian/Arabic variants match)', async () => {
    const t = tag();
    const created = await createOk({ name: `کریمان ${t}` });
    const res = await agent()
      .get(API)
      .query({ q: `كريمان ${t}` })
      .set(auth(tokenA))
      .expect(200);
    expect(res.body.data.map((row: { id: string }) => row.id)).toEqual([created.id]);
  });
});

describe('destinations — strict input and mass assignment', () => {
  it('rejects forbidden or unknown body keys at every level', async () => {
    for (const extra of [
      { tenantId: tenantA },
      { tenant_id: tenantA },
      { status: 'active' },
      { createdBy: userA },
      { nameKey: 'x' },
      { version: 2 },
      { id: uuidv7() },
      { createdAt: new Date().toISOString() },
      { updatedAt: new Date().toISOString() },
      { deletedAt: null },
    ]) {
      const res = await create({ name: 'Mass Assignment', ...extra }, { key: idemKey() });
      expect(res.status, JSON.stringify(extra)).toBe(400);
    }
    const unknown = await create({ name: 'Mass Assignment', extra: 1 }, { key: idemKey() });
    expect(unknown.status).toBe(400);

    const created = await createOk({ name: `Mass Patch ${tag()}` });
    for (const extra of [{ tenantId: tenantA }, { nameKey: 'x' }, { version: 2 }]) {
      const res = await agent()
        .patch(`${API}/${created.id}`)
        .set(auth(tokenA))
        .set('idempotency-key', idemKey())
        .send({ displayOrder: 1, expectedVersion: 1, ...extra });
      expect(res.status, JSON.stringify(extra)).toBe(400);
    }
  });

  it('rejects forbidden/unknown query keys and a missing or non-canonical expectedVersion', async () => {
    const created = await createOk({ name: `Strict ${tag()}` });
    for (const query of [{ tenantId: tenantA }, { nameKey: 'x' }, { foo: '1' }]) {
      const res = await agent().get(`${API}/${created.id}`).query(query).set(auth(tokenA));
      expect(res.status, JSON.stringify(query)).toBe(400);
    }
    const badPostQuery = await create({ name: 'Strict Query' }, { query: { foo: '1' } });
    expect(badPostQuery.status).toBe(400);

    for (const query of [
      {},
      { expectedVersion: '03' },
      { expectedVersion: '-1' },
      {
        expectedVersion: '1.5',
      },
      { expectedVersion: 'abc' },
      { expectedVersion: '3 ' },
    ]) {
      const res = await agent()
        .delete(`${API}/${created.id}`)
        .set(auth(tokenA))
        .set('idempotency-key', idemKey())
        .query(query);
      expect(res.status, JSON.stringify(query)).toBe(400);
    }

    const noFields = await agent()
      .patch(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ expectedVersion: 1 });
    expect(noFields.status).toBe(400);
  });

  it('rejects a malformed UUID param with 400', async () => {
    await agent().get(`${API}/not-a-uuid`).set(auth(tokenA)).expect(400);
  });

  it('runs authentication and authorization before input validation', async () => {
    // Guards run before pipes: an invalid id must not become a 400 oracle.
    await agent().get(`${API}/not-a-uuid`).expect(401);
    await agent().get(`${API}/not-a-uuid`).set(auth(carrierToken)).expect(403);
    await agent().get(`${API}/not-a-uuid`).set(auth(tokenA)).expect(400);
  });

  it('rejects NUL and unpaired surrogates as 400, never a database 500', async () => {
    for (const body of [
      { name: 'ab\u0000cd' },
      { name: 'ab\uD800cd' },
      { name: 'Unstorable Province', provinceName: 'x\u0000y' },
      { name: 'Unstorable Province', provinceName: 'x\uD800y' },
    ]) {
      const res = await create(body, { key: idemKey() });
      expect(res.status, JSON.stringify(body)).toBe(400);
    }
    await agent().get(API).query({ q: 'ab\u0000cd' }).set(auth(tokenA)).expect(400);

    const created = await createOk({ name: `Surrogate Patch ${tag()}` });
    await agent()
      .patch(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ provinceName: 'x\u0000y', expectedVersion: 1 })
      .expect(400);
  });

  it('enforces the documented field bounds', async () => {
    for (const body of [
      { name: 'a' },
      { name: 'x'.repeat(65) },
      { name: 'Bounds', displayOrder: -1 },
      { name: 'Bounds', displayOrder: 10000 },
      { name: 'Bounds', provinceName: 'p'.repeat(65) },
      { name: 'Bounds', isActive: 'true' },
    ]) {
      const res = await create(body, { key: idemKey() });
      expect(res.status, JSON.stringify(body)).toBe(400);
    }
  });
});

describe('destinations — uniqueness and optimistic concurrency', () => {
  it('maps normalized duplicates to 409 CONFLICT with details.field = name', async () => {
    const t = tag();
    await createOk({ name: `کریمان ${t}` });
    const res = await create({ name: `كريمان ${t}` });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatchObject({ code: 'CONFLICT', details: { field: 'name' } });
    expect(JSON.stringify(res.body)).not.toContain(`كريمان ${t}`);

    const caseBase = await createOk({ name: `CASE ${t}` });
    expect(caseBase.id).toBeTruthy();
    expect((await create({ name: `case ${t}` })).status).toBe(409);

    await createOk({ name: `درب ۱۲ ${t}` });
    expect((await create({ name: `درب 12 ${t}` })).status).toBe(409);

    const zwnj = `سالن‌${t}`;
    await createOk({ name: zwnj });
    expect((await create({ name: `سالن ${t}` })).status).toBe(409);
  });

  it('reuses a name after soft delete and returns 409 for a stale PATCH/DELETE', async () => {
    const t = tag();
    const created = await createOk({ name: `Reuse ${t}` });
    const first = await agent()
      .patch(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 })
      .expect(200);
    expect(first.body.data.version).toBe(2);

    const stalePatch = await agent()
      .patch(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 2, expectedVersion: 1 });
    expect(stalePatch.status).toBe(409);
    expect(stalePatch.body.error.code).toBe('STALE_VERSION');

    const staleDelete = await agent()
      .delete(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 });
    expect(staleDelete.status).toBe(409);
    expect(staleDelete.body.error.code).toBe('STALE_VERSION');

    await agent()
      .delete(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 2 })
      .expect(204);
    const again = await createOk({ name: `Reuse ${t}` });
    expect(again.id).not.toBe(created.id);

    await agent().get(`${API}/${created.id}`).set(auth(tokenA)).expect(404);
    await agent()
      .patch(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 3, expectedVersion: 2 })
      .expect(404);
    await agent()
      .delete(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 2 })
      .expect(404);
  });

  it('a PATCH to a duplicate name is 409 and rolls back the version and audit', async () => {
    const t = tag();
    const a = await createOk({ name: `Patch Dup A ${t}` });
    const b = await createOk({ name: `Patch Dup B ${t}` });
    const beforeAudit = await auditCount(tenantA, b.id);
    const res = await agent()
      .patch(`${API}/${b.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ name: `Patch Dup A ${t}`, expectedVersion: 1 });
    expect(res.status).toBe(409);
    const read = await agent().get(`${API}/${b.id}`).set(auth(tokenA)).expect(200);
    expect(read.body.data).toMatchObject({ name: `Patch Dup B ${t}`, version: 1 });
    expect(await auditCount(tenantA, b.id)).toBe(beforeAudit);
    expect(a.id).not.toBe(b.id);
  });
});

describe('destinations — tenant isolation', () => {
  it('gives tenant B the same 404 as a nonexistent row for read/patch/delete', async () => {
    const created = await createOk({ name: `Isolation ${tag()}` });
    const missing = uuidv7();
    const list = await agent().get(API).set(auth(tokenB)).expect(200);
    expect((list.body.data as { id: string }[]).some((row) => row.id === created.id)).toBe(false);

    const readB = await agent().get(`${API}/${created.id}`).set(auth(tokenB)).expect(404);
    const readMissing = await agent().get(`${API}/${missing}`).set(auth(tokenB)).expect(404);
    expect(readB.body).toEqual(readMissing.body);

    const patchB = await agent()
      .patch(`${API}/${created.id}`)
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 9, expectedVersion: 1 })
      .expect(404);
    const patchMissing = await agent()
      .patch(`${API}/${missing}`)
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 9, expectedVersion: 1 })
      .expect(404);
    expect(patchB.body).toEqual(patchMissing.body);

    const deleteB = await agent()
      .delete(`${API}/${created.id}`)
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(404);
    const deleteMissing = await agent()
      .delete(`${API}/${missing}`)
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(404);
    expect(deleteB.body).toEqual(deleteMissing.body);

    // Tenant A's row is untouched.
    await agent().get(`${API}/${created.id}`).set(auth(tokenA)).expect(200);
  });
});

describe('destinations — audit', () => {
  it('writes one destination.created row with an allowlisted snapshot and no replay duplicate', async () => {
    const key = idemKey();
    const name = `Audit Created ${tag()}`;
    const res = await agent()
      .post(API)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send({ name, displayOrder: 7 })
      .expect(201);
    const id = res.body.data.id as string;

    const rows = await auditRows(tenantA, id);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: 'destination.created',
      actor_user_id: userA,
      resource_type: 'destination',
      http_status: 201,
    });
    expect(rows[0]?.actor_session_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(rows[0]?.after).toMatchObject({
      id,
      name,
      displayOrder: 7,
      version: 1,
      provinceName: null,
    });
    expect(rows[0]?.before).toBeNull();
    expect(rows[0]?.after).not.toHaveProperty('nameKey');
    expect(rows[0]?.after).not.toHaveProperty('tenantId');
    expect(rows[0]?.after).toHaveProperty('createdAt');

    const replay = await agent()
      .post(API)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send({ name, displayOrder: 7 })
      .expect(201);
    expect(replay.headers['idempotent-replayed']).toBe('true');
    expect(replay.body).toEqual(res.body);
    expect(await auditRows(tenantA, id)).toHaveLength(1);
    expect(await liveCount(tenantA)).toBeGreaterThanOrEqual(1);
  });

  it('writes updated before/after snapshots with the version transition', async () => {
    const created = await createOk({ name: `Audit Update ${tag()}` });
    await agent()
      .patch(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ isActive: false, expectedVersion: 1 })
      .expect(200);
    const rows = await auditRows(tenantA, created.id);
    expect(rows.map((row) => row.action)).toEqual(['destination.created', 'destination.updated']);
    const updated = rows[1];
    expect(updated?.before).toMatchObject({ version: 1, isActive: true });
    expect(updated?.after).toMatchObject({ version: 2, isActive: false });
  });

  it('writes deleted snapshots and no row for a rolled-back conflict', async () => {
    const t = tag();
    const created = await createOk({ name: `Audit Delete ${t}` });
    await agent()
      .delete(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    const rows = await auditRows(tenantA, created.id);
    expect(rows.map((row) => row.action)).toEqual(['destination.created', 'destination.deleted']);
    expect(rows[1]?.after).toMatchObject({ version: 2 });
    expect(rows[1]?.after).toHaveProperty('deletedAt');
    expect(rows[1]?.after?.deletedAt).toEqual(expect.any(String));

    await createOk({ name: `Rollback ${t}` });
    const before = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1',
      [tenantA],
    );
    const conflict = await create({ name: `Rollback ${t}` });
    expect(conflict.status).toBe(409);
    const after = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1',
      [tenantA],
    );
    expect(after.rows[0]?.n).toBe(before.rows[0]?.n);
  });
});

describe('destinations — idempotency', () => {
  it('replays a success once, rejects a different payload, and requires a key', async () => {
    const key = idemKey();
    const body = { name: `Idem ${tag()}`, displayOrder: 4 };
    const first = await agent()
      .post(API)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send(body)
      .expect(201);
    const replay = await agent()
      .post(API)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send(body)
      .expect(201);
    expect(replay.body).toEqual(first.body);
    expect(replay.headers['idempotent-replayed']).toBe('true');

    const different = await agent()
      .post(API)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send({ ...body, displayOrder: 5 });
    expect(different.status).toBe(422);
    expect(different.body.error.code).toBe('IDEMPOTENCY_KEY_REUSED');

    const missing = await create({ name: `No Key ${tag()}` }, { key: null });
    expect(missing.status).toBe(400);
    expect(missing.body.error.code).toBe('IDEMPOTENCY_KEY_REQUIRED');

    const malformed = await agent()
      .post(API)
      .set(auth(tokenA))
      .set('idempotency-key', 'short')
      .send({ name: `Bad Key ${tag()}` });
    expect(malformed.status).toBe(400);

    const keyRows = await owner.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM idempotency_keys
        WHERE tenant_id = $1 AND user_id = $2 AND route_key = $3 AND idem_key = $4`,
      [tenantA, userA, 'POST /api/v1/base/destinations', key],
    );
    expect(keyRows.rows[0]?.n).toBe(1);
  });

  it('does not store or replay a handler error: the same key re-executes after the conflict clears', async () => {
    const t = tag();
    const name = `Conflict Replay ${t}`;
    const original = await createOk({ name });
    const key = idemKey();
    const failed = await agent()
      .post(API)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send({ name });
    expect(failed.status).toBe(409);

    const keyRows = await owner.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM idempotency_keys
        WHERE tenant_id = $1 AND user_id = $2 AND route_key = $3 AND idem_key = $4`,
      [tenantA, userA, 'POST /api/v1/base/destinations', key],
    );
    expect(keyRows.rows[0]?.n).toBe(0);

    // Clear the conflict, then retry with the SAME key: it must execute again.
    await owner.query('UPDATE destinations SET deleted_at = now() WHERE id = $1', [original.id]);
    const retried = await agent()
      .post(API)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send({ name })
      .expect(201);
    expect(retried.headers['idempotent-replayed']).toBeUndefined();
  });

  it('includes DELETE expectedVersion in the fingerprint, replays 204 once, and audits once', async () => {
    const created = await createOk({ name: `Idem Delete ${tag()}` });
    const key = idemKey();
    const first = await agent()
      .delete(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .query({ expectedVersion: 1 })
      .expect(204);
    expect(first.headers['idempotent-replayed']).toBeUndefined();

    const replay = await agent()
      .delete(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .query({ expectedVersion: 1 })
      .expect(204);
    expect(replay.headers['idempotent-replayed']).toBe('true');

    const different = await agent()
      .delete(`${API}/${created.id}`)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .query({ expectedVersion: 2 });
    expect(different.status).toBe(422);
    expect(different.body.error.code).toBe('IDEMPOTENCY_KEY_REUSED');

    const deletedRows = (await auditRows(tenantA, created.id)).filter(
      (row) => row.action === 'destination.deleted',
    );
    expect(deletedRows).toHaveLength(1);
  });

  it('20 parallel creates of one name produce exactly one 201 and one audit row', async () => {
    const name = `Parallel ${tag()}`;
    const responses = await Promise.all(
      Array.from({ length: 20 }, () =>
        agent().post(API).set(auth(tokenA)).set('idempotency-key', idemKey()).send({ name }),
      ),
    );
    const statuses = responses.map((res) => res.status).sort((a, b) => a - b);
    expect(statuses.filter((status) => status === 201)).toHaveLength(1);
    expect(statuses.filter((status) => status === 409)).toHaveLength(19);
    const winner = responses.find((res) => res.status === 201);
    const id = (winner?.body.data as { id: string }).id;
    expect(await auditCount(tenantA, id)).toBe(1);
    const count = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM destinations WHERE tenant_id = $1 AND name_key = $2 AND deleted_at IS NULL',
      [tenantA, name.toLowerCase()],
    );
    expect(count.rows[0]?.n).toBe(1);
  }, 60_000);
});

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
 * Halls + nested terminals end-to-end (F1-07 T05, ADR-011). Covers the
 * AT-11 locking rule in both directions, including the 50-iteration
 * delete-parent vs create-child race, cross-hall/cross-tenant 404 parity,
 * in-use delete, audit and idempotency.
 */

const HALLS = '/api/v1/base/halls';

function hallPath(id: string): string {
  return `${HALLS}/${id}`;
}

function terminalsPath(hallId: string): string {
  return `${HALLS}/${hallId}/terminals`;
}

function terminalPath(hallId: string, id: string): string {
  return `${HALLS}/${hallId}/terminals/${id}`;
}

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
  return `hall-${uuidv7()}`;
}

function tag(): string {
  return randomBytes(4).toString('hex');
}

function agent() {
  return request(app.getHttpServer());
}

function createHall(body: Record<string, unknown>, token = tokenA, key = idemKey()) {
  return agent().post(HALLS).set(auth(token)).set('idempotency-key', key).send(body);
}

async function createHallOk(body: Record<string, unknown> = {}): Promise<{
  id: string;
  version: number;
  name: string;
}> {
  const res = await createHall({ name: `Hall ${tag()}`, ...body });
  if (res.status !== 201) {
    throw new Error(`hall create failed: ${res.status} ${res.text}`);
  }
  return res.body.data as { id: string; version: number; name: string };
}

function createTerminal(
  hallId: string,
  body: Record<string, unknown>,
  token = tokenA,
  key = idemKey(),
) {
  return agent()
    .post(terminalsPath(hallId))
    .set(auth(token))
    .set('idempotency-key', key)
    .send(body);
}

async function createTerminalOk(
  hallId: string,
  body: Record<string, unknown> = {},
): Promise<{ id: string; version: number; hallId: string }> {
  const res = await createTerminal(hallId, { name: `Terminal ${tag()}`, ...body });
  if (res.status !== 201) {
    throw new Error(`terminal create failed: ${res.status} ${res.text}`);
  }
  return res.body.data as { id: string; version: number; hallId: string };
}

interface AuditRow {
  action: string;
  resource_type: string;
  actor_user_id: string | null;
  actor_session_id: string | null;
  metadata: Record<string, unknown> | null;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
}

async function auditRows(tenantId: string, resourceId: string): Promise<AuditRow[]> {
  const res = await owner.query<AuditRow>(
    `SELECT action, resource_type, actor_user_id, actor_session_id, metadata, before, after
       FROM audit_logs
      WHERE tenant_id = $1 AND resource_id = $2
      ORDER BY occurred_at, id`,
    [tenantId, resourceId],
  );
  return res.rows;
}

async function liveTerminals(hallId: string): Promise<number> {
  const res = await owner.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM hall_terminals WHERE hall_id = $1 AND deleted_at IS NULL',
    [hallId],
  );
  return res.rows[0]?.n ?? 0;
}

beforeAll(async () => {
  app = await buildAuthApp();
  owner = ownerPool();
  const suffix = tag();
  tenantA = await createTenant(owner, `hall-a-${suffix}`);
  tenantB = await createTenant(owner, `hall-b-${suffix}`);
  userA = await createUser(owner, tenantA, { username: `hall.op.a.${suffix}` });
  userB = await createUser(owner, tenantB, { username: `hall.op.b.${suffix}` });
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

describe('halls/terminals — access control', () => {
  it('answers 401 anonymously and byte-identical 403 for CARRIER_ADMIN/DRIVER', async () => {
    await agent().get(HALLS).expect(401);
    await agent().post(HALLS).send({ name: 'Anon' }).expect(401);
    const hall = await createHallOk();
    await agent().get(terminalsPath(hall.id)).expect(401);
    await agent().post(terminalsPath(hall.id)).send({ name: 'Anon Terminal' }).expect(401);

    const carrier = await agent().get(HALLS).set(auth(carrierToken)).expect(403);
    const driver = await agent().get(HALLS).set(auth(driverToken)).expect(403);
    expect(carrier.body).toEqual(driver.body);

    const carrierWrite = await createTerminal(
      hall.id,
      { name: 'Denied' },
      carrierToken,
      idemKey(),
    ).expect(403);
    const driverWrite = await createTerminal(
      hall.id,
      { name: 'Denied' },
      driverToken,
      idemKey(),
    ).expect(403);
    expect(carrierWrite.body).toEqual(driverWrite.body);
  });

  it('runs guards before input validation', async () => {
    await agent().get(`${HALLS}/not-a-uuid`).expect(401);
    await agent().get(`${HALLS}/not-a-uuid`).set(auth(carrierToken)).expect(403);
    await agent().get(`${HALLS}/not-a-uuid`).set(auth(tokenA)).expect(400);
    await agent().get(`${HALLS}/not-a-uuid/terminals`).set(auth(tokenA)).expect(400);
  });
});

describe('halls — CRUD, in-use and audit', () => {
  it('creates, reads, updates with CAS and soft-deletes', async () => {
    const t = tag();
    const name = `سالن اصلی ${t}`;
    const created = await agent()
      .post(HALLS)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ name, displayOrder: 3 })
      .expect(201);
    const dto = created.body.data as { id: string; name: string; version: number };
    expect(dto).toMatchObject({ name, displayOrder: 3, version: 1 });
    expect(dto).not.toHaveProperty('nameKey');
    expect(dto).not.toHaveProperty('tenantId');

    const read = await agent().get(hallPath(dto.id)).set(auth(tokenA)).expect(200);
    expect(read.body.data).toMatchObject({ id: dto.id, name });

    const patched = await agent()
      .patch(hallPath(dto.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ name: `سالن دوم ${t}`, expectedVersion: 1 })
      .expect(200);
    expect(patched.body.data).toMatchObject({ name: `سالن دوم ${t}`, version: 2 });

    const stale = await agent()
      .patch(hallPath(dto.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 });
    expect(stale.status).toBe(409);
    expect(stale.body.error.code).toBe('STALE_VERSION');

    await agent()
      .delete(hallPath(dto.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 2 })
      .expect(204);
    await agent().get(hallPath(dto.id)).set(auth(tokenA)).expect(404);

    const audit = await auditRows(tenantA, dto.id);
    expect(audit.map((row) => row.action)).toEqual([
      'hall.created',
      'hall.updated',
      'hall.deleted',
    ]);
    expect(audit[1]?.before).toMatchObject({ version: 1 });
    expect(audit[1]?.after).toMatchObject({ version: 2 });
    expect(audit[2]?.after).toHaveProperty('deletedAt');
    for (const row of audit) {
      expect(row.actor_user_id).toBe(userA);
      expect(row.actor_session_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(row.after).not.toHaveProperty('nameKey');
      expect(row.after).not.toHaveProperty('tenantId');
    }
  });

  it('maps duplicate names to 409 CONFLICT and reuses after soft delete', async () => {
    const t = tag();
    const created = await createHallOk({ name: `تکرار ${t}` });
    const duplicate = await createHall({ name: `تکرار ${t}` });
    expect(duplicate.status).toBe(409);
    expect(duplicate.body.error).toMatchObject({
      code: 'CONFLICT',
      details: { field: 'name' },
    });
    await agent()
      .delete(hallPath(created.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    await createHallOk({ name: `تکرار ${t}` });
  });

  it('blocks delete while a live terminal exists (409 IN_USE), even if inactive', async () => {
    const hall = await createHallOk();
    const terminal = await createTerminalOk(hall.id, { isActive: false });
    const blocked = await agent()
      .delete(hallPath(hall.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 });
    expect(blocked.status).toBe(409);
    expect(blocked.body.error.code).toBe('IN_USE');
    expect(JSON.stringify(blocked.body)).not.toContain(terminal.id);
    expect(JSON.stringify(blocked.body)).not.toContain('Terminal');

    // The hall is untouched and its terminal is still reachable.
    await agent().get(hallPath(hall.id)).set(auth(tokenA)).expect(200);
    await agent().get(terminalPath(hall.id, terminal.id)).set(auth(tokenA)).expect(200);

    await agent()
      .delete(terminalPath(hall.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    await agent()
      .delete(hallPath(hall.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
  });

  it('rejects mass assignment, unknown query keys and bad expectedVersion', async () => {
    for (const extra of [{ tenantId: tenantA }, { nameKey: 'x' }, { version: 2 }]) {
      const res = await createHall({ name: 'Mass Hall', ...extra });
      expect(res.status, JSON.stringify(extra)).toBe(400);
    }
    const created = await createHallOk();
    for (const query of [{ tenantId: tenantA }, { foo: '1' }]) {
      await agent().get(hallPath(created.id)).query(query).set(auth(tokenA)).expect(400);
    }
    for (const query of [{}, { expectedVersion: '03' }, { expectedVersion: 'x' }]) {
      const res = await agent()
        .delete(hallPath(created.id))
        .set(auth(tokenA))
        .set('idempotency-key', idemKey())
        .query(query);
      expect(res.status, JSON.stringify(query)).toBe(400);
    }
    const noFields = await agent()
      .patch(hallPath(created.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ expectedVersion: 1 });
    expect(noFields.status).toBe(400);
  });
});

describe('terminals — nested CRUD, scope and uniqueness', () => {
  it('creates under a hall, lists, reads, updates and deletes', async () => {
    const hall = await createHallOk();
    const t = tag();
    const created = await agent()
      .post(terminalsPath(hall.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ name: `بارگیر ۱ ${t}`, displayOrder: 2 })
      .expect(201);
    const dto = created.body.data as { id: string; hallId: string; version: number };
    expect(dto).toMatchObject({ hallId: hall.id, name: `بارگیر ۱ ${t}`, version: 1 });

    const list = await agent().get(terminalsPath(hall.id)).set(auth(tokenA)).expect(200);
    expect(list.body.meta).toEqual({ page: 1, pageSize: 50, total: 1 });
    expect(list.body.data.map((row: { id: string }) => row.id)).toEqual([dto.id]);

    const read = await agent().get(terminalPath(hall.id, dto.id)).set(auth(tokenA)).expect(200);
    expect(read.body.data).toMatchObject({ id: dto.id, hallId: hall.id });

    const patched = await agent()
      .patch(terminalPath(hall.id, dto.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 4, expectedVersion: 1 })
      .expect(200);
    expect(patched.body.data).toMatchObject({ displayOrder: 4, version: 2 });

    await agent()
      .delete(terminalPath(hall.id, dto.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 2 })
      .expect(204);
    const empty = await agent().get(terminalsPath(hall.id)).set(auth(tokenA)).expect(200);
    expect(empty.body.data).toEqual([]);
    expect(empty.body.meta.total).toBe(0);
    await agent().get(terminalPath(hall.id, dto.id)).set(auth(tokenA)).expect(404);

    const audit = await auditRows(tenantA, dto.id);
    expect(audit.map((row) => row.action)).toEqual([
      'terminal.created',
      'terminal.updated',
      'terminal.deleted',
    ]);
    for (const row of audit) {
      expect(row.metadata).toEqual({ hallId: hall.id });
      expect(row.actor_user_id).toBe(userA);
      expect(row.after).not.toHaveProperty('hallId');
      expect(row.after).not.toHaveProperty('nameKey');
    }
    expect(audit[1]?.before).toMatchObject({ version: 1 });
    expect(audit[1]?.after).toMatchObject({ version: 2 });
    expect(audit[2]?.after).toHaveProperty('deletedAt');
  });

  it('allows a terminal under an inactive hall and 404s on a deleted terminal', async () => {
    const inactive = await createHallOk({ isActive: false });
    const terminal = await createTerminalOk(inactive.id);
    await agent()
      .delete(terminalPath(inactive.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    await agent()
      .patch(terminalPath(inactive.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 2, expectedVersion: 2 })
      .expect(404);
    await agent()
      .delete(terminalPath(inactive.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 2 })
      .expect(404);
  });

  it('keeps names unique per hall, not per tenant, and reuses after delete', async () => {
    const hallA = await createHallOk();
    const hallB = await createHallOk();
    const name = `مشترک ${tag()}`;
    const first = await createTerminalOk(hallA.id, { name });
    await createTerminalOk(hallB.id, { name });
    const duplicate = await createTerminal(hallA.id, { name });
    expect(duplicate.status).toBe(409);
    expect(duplicate.body.error).toMatchObject({
      code: 'CONFLICT',
      details: { field: 'name' },
    });

    await agent()
      .delete(terminalPath(hallA.id, first.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    await createTerminalOk(hallA.id, { name });
  });

  it('returns the identical 404 for another hall path and another tenant', async () => {
    const hallA = await createHallOk();
    const hallB = await createHallOk();
    const terminal = await createTerminalOk(hallA.id);
    const bHall = await agent()
      .post(HALLS)
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send({ name: `Other Tenant ${tag()}` })
      .expect(201);
    const bHallId = bHall.body.data.id as string;

    const missing = uuidv7();
    const viaWrongHall = await agent()
      .get(terminalPath(hallB.id, terminal.id))
      .set(auth(tokenA))
      .expect(404);
    const missingBody = await agent()
      .get(terminalPath(hallB.id, missing))
      .set(auth(tokenA))
      .expect(404);
    expect(viaWrongHall.body).toEqual(missingBody.body);

    const patchWrong = await agent()
      .patch(terminalPath(hallB.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 })
      .expect(404);
    const patchMissing = await agent()
      .patch(terminalPath(hallB.id, missing))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 })
      .expect(404);
    expect(patchWrong.body).toEqual(patchMissing.body);

    const deleteWrong = await agent()
      .delete(terminalPath(hallB.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(404);
    const deleteMissing = await agent()
      .delete(terminalPath(hallB.id, missing))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(404);
    expect(deleteWrong.body).toEqual(deleteMissing.body);

    const crossTenant = await agent()
      .get(terminalPath(bHallId, terminal.id))
      .set(auth(tokenA))
      .expect(404);
    expect(crossTenant.body).toEqual(missingBody.body);

    // Listing under a foreign/missing hall is 404, not an empty page.
    const listForeign = await agent().get(terminalsPath(bHallId)).set(auth(tokenA)).expect(404);
    const listMissing = await agent().get(terminalsPath(missing)).set(auth(tokenA)).expect(404);
    expect(listForeign.body).toEqual(listMissing.body);

    // Tenant B sees neither hall nor terminal.
    expect((await agent().get(hallPath(hallA.id)).set(auth(tokenB)).expect(404)).body).toEqual(
      missingBody.body,
    );
    expect(
      (await agent().get(terminalPath(hallA.id, terminal.id)).set(auth(tokenB)).expect(404)).body,
    ).toEqual(missingBody.body);
    expect(hallA.id).not.toBe(hallB.id);
  });

  it('rejects a body hallId and other server-only keys; deleted hall is 404', async () => {
    const hall = await createHallOk();
    for (const extra of [
      { hallId: hall.id },
      { tenantId: tenantA },
      { nameKey: 'x' },
      { version: 2 },
    ]) {
      const res = await createTerminal(hall.id, { name: 'Mass Terminal', ...extra });
      expect(res.status, JSON.stringify(extra)).toBe(400);
    }
    await agent()
      .delete(hallPath(hall.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    await createTerminal(hall.id, { name: 'After Delete' }).expect(404);
    await agent().get(terminalsPath(hall.id)).set(auth(tokenA)).expect(404);
  });

  it('returns stale/invalid version errors for terminal mutations', async () => {
    const hall = await createHallOk();
    const terminal = await createTerminalOk(hall.id);
    const stale = await agent()
      .patch(terminalPath(hall.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 2, expectedVersion: 9 });
    expect(stale.status).toBe(409);
    expect(stale.body.error.code).toBe('STALE_VERSION');
    const badDelete = await agent()
      .delete(terminalPath(hall.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '01' });
    expect(badDelete.status).toBe(400);
  });
});

describe('halls/terminals — idempotency and audit', () => {
  it('replays hall and terminal creation once, with one audit row each', async () => {
    const hallKey = idemKey();
    const hallBody = { name: `Idem Hall ${tag()}` };
    const first = await agent()
      .post(HALLS)
      .set(auth(tokenA))
      .set('idempotency-key', hallKey)
      .send(hallBody)
      .expect(201);
    const replay = await agent()
      .post(HALLS)
      .set(auth(tokenA))
      .set('idempotency-key', hallKey)
      .send(hallBody)
      .expect(201);
    expect(replay.headers['idempotent-replayed']).toBe('true');
    expect(replay.body).toEqual(first.body);
    const hallId = first.body.data.id as string;
    expect((await auditRows(tenantA, hallId)).length).toBe(1);

    const key = idemKey();
    const body = { name: `Idem Terminal ${tag()}` };
    const tFirst = await agent()
      .post(terminalsPath(hallId))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send(body)
      .expect(201);
    const tReplay = await agent()
      .post(terminalsPath(hallId))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send(body)
      .expect(201);
    expect(tReplay.headers['idempotent-replayed']).toBe('true');
    expect(tReplay.body).toEqual(tFirst.body);
    const terminalId = tFirst.body.data.id as string;
    expect((await auditRows(tenantA, terminalId)).length).toBe(1);
  });

  it('includes DELETE expectedVersion in the fingerprint and writes one audit row', async () => {
    const hall = await createHallOk();
    const terminal = await createTerminalOk(hall.id);
    const key = idemKey();
    await agent()
      .delete(terminalPath(hall.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .query({ expectedVersion: 1 })
      .expect(204);
    const replay = await agent()
      .delete(terminalPath(hall.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .query({ expectedVersion: 1 })
      .expect(204);
    expect(replay.headers['idempotent-replayed']).toBe('true');
    const different = await agent()
      .delete(terminalPath(hall.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .query({ expectedVersion: 2 });
    expect(different.status).toBe(422);
    const deletedAudit = (await auditRows(tenantA, terminal.id)).filter(
      (row) => row.action === 'terminal.deleted',
    );
    expect(deletedAudit).toHaveLength(1);
    expect(deletedAudit[0]?.metadata).toEqual({ hallId: hall.id });
  });

  it('writes no audit row for a rolled-back duplicate terminal', async () => {
    const hall = await createHallOk();
    const name = `Rollback Terminal ${tag()}`;
    await createTerminalOk(hall.id, { name });
    const before = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1',
      [tenantA],
    );
    expect((await createTerminal(hall.id, { name })).status).toBe(409);
    const after = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1',
      [tenantA],
    );
    expect(after.rows[0]?.n).toBe(before.rows[0]?.n);
  });
});

describe('halls/terminals — listing', () => {
  it('lists halls with pagination, sort, q, isActive and soft-delete exclusion', async () => {
    const word = `HallList${tag()}`;
    const t = tag();
    const first = await createHallOk({
      name: `${word} A ${t}`,
      isActive: false,
      displayOrder: 1,
    });
    const second = await createHallOk({ name: `${word} B ${t}`, isActive: true, displayOrder: 2 });
    const third = await createHallOk({ name: `${word} C ${t}`, isActive: true, displayOrder: 3 });

    const page = await agent()
      .get(HALLS)
      .query({ q: word, pageSize: 2 })
      .set(auth(tokenA))
      .expect(200);
    expect(page.body.meta).toEqual({ page: 1, pageSize: 2, total: 3 });
    expect(page.body.data.map((row: { id: string }) => row.id)).toEqual([first.id, second.id]);

    const active = await agent()
      .get(HALLS)
      .query({ q: word, isActive: 'true' })
      .set(auth(tokenA))
      .expect(200);
    expect(active.body.meta).toEqual({ page: 1, pageSize: 50, total: 2 });
    expect(active.body.data.map((row: { id: string }) => row.id)).toEqual([second.id, third.id]);

    const inactive = await agent()
      .get(HALLS)
      .query({ q: word, isActive: 'false' })
      .set(auth(tokenA))
      .expect(200);
    expect(inactive.body.data.map((row: { id: string }) => row.id)).toEqual([first.id]);

    await agent()
      .get(HALLS)
      .query({ q: word, sort: '-createdAt', pageSize: 100 })
      .set(auth(tokenA))
      .expect(200);

    for (const query of [
      { pageSize: 101 },
      { page: 0 },
      { sort: 'tenantId' },
      { q: 'x'.repeat(65) },
      { tenantId: tenantA },
    ]) {
      const res = await agent().get(HALLS).query(query).set(auth(tokenA));
      expect(res.status, JSON.stringify(query)).toBe(400);
    }
    const huge = await agent()
      .get(HALLS)
      .query({ page: 1_000_000_000, q: word })
      .set(auth(tokenA))
      .expect(200);
    expect(huge.body.data).toEqual([]);
    await agent().get(HALLS).query({ page: 1_000_000_001 }).set(auth(tokenA)).expect(400);

    await agent()
      .delete(hallPath(third.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    const afterDelete = await agent().get(HALLS).query({ q: word }).set(auth(tokenA)).expect(200);
    expect(afterDelete.body.meta.total).toBe(2);
    expect(afterDelete.body.data.map((row: { id: string }) => row.id)).not.toContain(third.id);
  });

  it('escapes LIKE metacharacters and normalizes q for halls', async () => {
    const word = `Esc${tag()}`;
    const percent = await createHallOk({ name: `100% ${word}` });
    await createHallOk({ name: `100x ${word}` });
    const escape = await agent()
      .get(HALLS)
      .query({ q: `100% ${word}` })
      .set(auth(tokenA))
      .expect(200);
    expect(escape.body.data.map((row: { id: string }) => row.id)).toEqual([percent.id]);

    const fa = await createHallOk({ name: `کریمان ${word}` });
    const normalized = await agent()
      .get(HALLS)
      .query({ q: `كريمان ${word}` })
      .set(auth(tokenA))
      .expect(200);
    expect(normalized.body.data.map((row: { id: string }) => row.id)).toContain(fa.id);
  });

  it('lists terminals per hall with filters, sorting, bounds and soft-delete exclusion', async () => {
    const hall = await createHallOk();
    const other = await createHallOk();
    const word = `TermList${tag()}`;
    const a = await createTerminalOk(hall.id, {
      name: `${word} A ${tag()}`,
      isActive: false,
      displayOrder: 3,
    });
    const b = await createTerminalOk(hall.id, {
      name: `${word} B ${tag()}`,
      isActive: true,
      displayOrder: 1,
    });
    const c = await createTerminalOk(hall.id, {
      name: `${word} C ${tag()}`,
      isActive: true,
      displayOrder: 2,
    });
    const otherTerm = await createTerminalOk(other.id, { name: `${word} Other ${tag()}` });

    const list = await agent()
      .get(terminalsPath(hall.id))
      .query({ q: word })
      .set(auth(tokenA))
      .expect(200);
    expect(list.body.meta).toEqual({ page: 1, pageSize: 50, total: 3 });
    expect(list.body.data.map((row: { id: string }) => row.id)).toEqual([b.id, c.id, a.id]);

    const active = await agent()
      .get(terminalsPath(hall.id))
      .query({ q: word, isActive: 'true' })
      .set(auth(tokenA))
      .expect(200);
    expect(active.body.data.map((row: { id: string }) => row.id)).toEqual([b.id, c.id]);

    const page = await agent()
      .get(terminalsPath(hall.id))
      .query({ q: word, pageSize: 2 })
      .set(auth(tokenA))
      .expect(200);
    expect(page.body.meta).toEqual({ page: 1, pageSize: 2, total: 3 });
    expect(page.body.data).toHaveLength(2);

    await agent()
      .get(terminalsPath(hall.id))
      .query({ q: word, sort: 'name' })
      .set(auth(tokenA))
      .expect(200);

    for (const query of [{ pageSize: 101 }, { sort: 'tenantId' }, { tenantId: tenantA }]) {
      const res = await agent().get(terminalsPath(hall.id)).query(query).set(auth(tokenA));
      expect(res.status, JSON.stringify(query)).toBe(400);
    }

    await agent()
      .delete(terminalPath(hall.id, c.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    const afterDelete = await agent()
      .get(terminalsPath(hall.id))
      .query({ q: word })
      .set(auth(tokenA))
      .expect(200);
    expect(afterDelete.body.meta.total).toBe(2);
    expect(afterDelete.body.data.map((row: { id: string }) => row.id)).not.toContain(c.id);

    const otherList = await agent()
      .get(terminalsPath(other.id))
      .query({ q: word })
      .set(auth(tokenA))
      .expect(200);
    expect(otherList.body.data.map((row: { id: string }) => row.id)).toEqual([otherTerm.id]);
  });
});

describe('AT-11 — delete-parent vs create-child race', () => {
  it('never leaves a live terminal under a deleted hall across 50 iterations', async () => {
    for (let i = 0; i < 50; i += 1) {
      const hall = await createHallOk({ name: `Race ${i} ${tag()}` });
      const [deleted, created] = await Promise.all([
        agent()
          .delete(hallPath(hall.id))
          .set(auth(tokenA))
          .set('idempotency-key', idemKey())
          .query({ expectedVersion: 1 }),
        createTerminal(hall.id, { name: `Race Terminal ${i} ${tag()}` }),
      ]);

      expect([204, 409]).toContain(deleted.status);
      expect([201, 404]).toContain(created.status);

      const live = await liveTerminals(hall.id);
      if (deleted.status === 204) {
        // The hall was deleted first: the child create must have missed it.
        expect(created.status).toBe(404);
        expect(live).toBe(0);
      } else {
        // The child won: the hall delete saw it and refused.
        expect(deleted.body.error.code).toBe('IN_USE');
        expect(created.status).toBe(201);
        expect(live).toBe(1);
      }
    }
  }, 180_000);

  it('20 parallel terminal creates of one name produce exactly one 201', async () => {
    const hall = await createHallOk();
    const name = `Parallel Terminal ${tag()}`;
    const responses = await Promise.all(
      Array.from({ length: 20 }, () => createTerminal(hall.id, { name })),
    );
    const statuses = responses.map((res) => res.status);
    expect(statuses.filter((status) => status === 201)).toHaveLength(1);
    expect(statuses.filter((status) => status === 409)).toHaveLength(19);
    const winner = responses.find((res) => res.status === 201);
    const id = (winner?.body.data as { id: string }).id;
    expect((await auditRows(tenantA, id)).length).toBe(1);
    const count = await owner.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM hall_terminals
        WHERE tenant_id = $1 AND hall_id = $2 AND name_key = $3 AND deleted_at IS NULL`,
      [tenantA, hall.id, name.toLowerCase()],
    );
    expect(count.rows[0]?.n).toBe(1);
  }, 60_000);
});

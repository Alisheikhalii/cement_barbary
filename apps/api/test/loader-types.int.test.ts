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
 * Loader-type groups + loader types end-to-end (F1-07 T06, ADR-011). Covers
 * the AT-11 locking rule in both directions (delete-group vs create-type race),
 * the `groupId` body/filter semantics (foreign/deleted group → identical 404),
 * uniqueness, audit, idempotency and listing.
 */

const GROUPS = '/api/v1/base/loader-type-groups';
const TYPES = '/api/v1/base/loader-types';

function groupPath(id: string): string {
  return `${GROUPS}/${id}`;
}

function typePath(id: string): string {
  return `${TYPES}/${id}`;
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
  return `loader-${uuidv7()}`;
}

function tag(): string {
  return randomBytes(4).toString('hex');
}

function agent() {
  return request(app.getHttpServer());
}

function createGroup(body: Record<string, unknown>, token = tokenA, key = idemKey()) {
  return agent().post(GROUPS).set(auth(token)).set('idempotency-key', key).send(body);
}

async function createGroupOk(body: Record<string, unknown> = {}): Promise<{
  id: string;
  version: number;
  name: string;
}> {
  const res = await createGroup({ name: `Group ${tag()}`, ...body });
  if (res.status !== 201) {
    throw new Error(`group create failed: ${res.status} ${res.text}`);
  }
  return res.body.data as { id: string; version: number; name: string };
}

function createLoaderType(body: Record<string, unknown>, token = tokenA, key = idemKey()) {
  return agent().post(TYPES).set(auth(token)).set('idempotency-key', key).send(body);
}

async function createTypeOk(
  groupId: string,
  body: Record<string, unknown> = {},
): Promise<{ id: string; version: number; groupId: string; name: string }> {
  const res = await createLoaderType({ groupId, name: `Type ${tag()}`, ...body });
  if (res.status !== 201) {
    throw new Error(`type create failed: ${res.status} ${res.text}`);
  }
  return res.body.data as { id: string; version: number; groupId: string; name: string };
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

async function liveTypes(groupId: string): Promise<number> {
  const res = await owner.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM loader_types WHERE group_id = $1 AND deleted_at IS NULL',
    [groupId],
  );
  return res.rows[0]?.n ?? 0;
}

beforeAll(async () => {
  app = await buildAuthApp();
  owner = ownerPool();
  const suffix = tag();
  tenantA = await createTenant(owner, `loader-a-${suffix}`);
  tenantB = await createTenant(owner, `loader-b-${suffix}`);
  userA = await createUser(owner, tenantA, { username: `loader.op.a.${suffix}` });
  userB = await createUser(owner, tenantB, { username: `loader.op.b.${suffix}` });
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

describe('loader types/groups — access control', () => {
  it('answers 401 anonymously and byte-identical 403 for CARRIER_ADMIN/DRIVER', async () => {
    await agent().get(GROUPS).expect(401);
    await agent().post(GROUPS).send({ name: 'Anon' }).expect(401);
    await agent().get(TYPES).expect(401);
    await agent().post(TYPES).send({ name: 'Anon', groupId: uuidv7() }).expect(401);

    const carrierRead = await agent().get(TYPES).set(auth(carrierToken)).expect(403);
    const driverRead = await agent().get(TYPES).set(auth(driverToken)).expect(403);
    expect(carrierRead.body).toEqual(driverRead.body);

    const group = await createGroupOk();
    const carrierWrite = await createLoaderType(
      { groupId: group.id, name: 'Denied' },
      carrierToken,
    ).expect(403);
    const driverWrite = await createLoaderType(
      { groupId: group.id, name: 'Denied' },
      driverToken,
    ).expect(403);
    expect(carrierWrite.body).toEqual(driverWrite.body);
  });

  it('runs guards before input validation', async () => {
    await agent().get(`${TYPES}/not-a-uuid`).expect(401);
    await agent().get(`${TYPES}/not-a-uuid`).set(auth(carrierToken)).expect(403);
    await agent().get(`${TYPES}/not-a-uuid`).set(auth(tokenA)).expect(400);
    await agent().get(`${GROUPS}/not-a-uuid`).set(auth(tokenA)).expect(400);
    await agent().get(TYPES).query({ groupId: 'not-a-uuid' }).expect(401);
    await agent().get(TYPES).query({ groupId: 'not-a-uuid' }).set(auth(tokenA)).expect(400);
  });
});

describe('groups — CRUD, in-use and audit', () => {
  it('creates, reads, updates with CAS and soft-deletes', async () => {
    const t = tag();
    const name = `گروه بارگیر ${t}`;
    const created = await agent()
      .post(GROUPS)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ name, displayOrder: 3 })
      .expect(201);
    const dto = created.body.data as { id: string; name: string; version: number };
    expect(dto).toMatchObject({ name, displayOrder: 3, version: 1 });
    expect(dto).not.toHaveProperty('nameKey');
    expect(dto).not.toHaveProperty('tenantId');

    const read = await agent().get(groupPath(dto.id)).set(auth(tokenA)).expect(200);
    expect(read.body.data).toMatchObject({ id: dto.id, name });

    const patched = await agent()
      .patch(groupPath(dto.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ name: `گروه دوم ${t}`, expectedVersion: 1 })
      .expect(200);
    expect(patched.body.data).toMatchObject({ name: `گروه دوم ${t}`, version: 2 });

    const stale = await agent()
      .patch(groupPath(dto.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 });
    expect(stale.status).toBe(409);
    expect(stale.body.error.code).toBe('STALE_VERSION');

    await agent()
      .delete(groupPath(dto.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 2 })
      .expect(204);
    await agent().get(groupPath(dto.id)).set(auth(tokenA)).expect(404);

    const audit = await auditRows(tenantA, dto.id);
    expect(audit.map((row) => row.action)).toEqual([
      'loader_type_group.created',
      'loader_type_group.updated',
      'loader_type_group.deleted',
    ]);
    expect(audit[1]?.before).toMatchObject({ version: 1 });
    expect(audit[1]?.after).toMatchObject({ version: 2 });
    expect(audit[2]?.after).toHaveProperty('deletedAt');
    for (const row of audit) {
      expect(row.resource_type).toBe('loader_type_group');
      expect(row.actor_user_id).toBe(userA);
      expect(row.after).not.toHaveProperty('nameKey');
      expect(row.after).not.toHaveProperty('tenantId');
    }
  });

  it('maps duplicate names to 409 CONFLICT and reuses after soft delete', async () => {
    const t = tag();
    const created = await createGroupOk({ name: `تکرار گروه ${t}` });
    const duplicate = await createGroup({ name: `تکرار گروه ${t}` });
    expect(duplicate.status).toBe(409);
    expect(duplicate.body.error).toMatchObject({
      code: 'CONFLICT',
      details: { field: 'name' },
    });
    await agent()
      .delete(groupPath(created.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    await createGroupOk({ name: `تکرار گروه ${t}` });
  });

  it('blocks delete while a live type exists (409 IN_USE), even if inactive', async () => {
    const group = await createGroupOk();
    const type = await createTypeOk(group.id, { isActive: false });
    const blocked = await agent()
      .delete(groupPath(group.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 });
    expect(blocked.status).toBe(409);
    expect(blocked.body.error.code).toBe('IN_USE');
    expect(JSON.stringify(blocked.body)).not.toContain(type.id);
    expect(JSON.stringify(blocked.body)).not.toContain(type.name);

    // The group is untouched and its type is still reachable.
    await agent().get(groupPath(group.id)).set(auth(tokenA)).expect(200);
    await agent().get(typePath(type.id)).set(auth(tokenA)).expect(200);

    await agent()
      .delete(typePath(type.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    await agent()
      .delete(groupPath(group.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
  });

  it('rejects mass assignment, unknown query keys and bad expectedVersion', async () => {
    for (const extra of [{ tenantId: tenantA }, { nameKey: 'x' }, { version: 2 }]) {
      const res = await createGroup({ name: 'Mass Group', ...extra });
      expect(res.status, JSON.stringify(extra)).toBe(400);
    }
    const created = await createGroupOk();
    for (const query of [{ tenantId: tenantA }, { foo: '1' }]) {
      await agent().get(groupPath(created.id)).query(query).set(auth(tokenA)).expect(400);
    }
    for (const extra of [
      { tenantId: tenantA },
      { nameKey: 'x' },
      { id: uuidv7() },
      { version: 2 },
      { createdAt: new Date().toISOString() },
    ]) {
      const res = await agent()
        .patch(groupPath(created.id))
        .set(auth(tokenA))
        .set('idempotency-key', idemKey())
        .send({ displayOrder: 1, expectedVersion: 1, ...extra });
      expect(res.status, JSON.stringify(extra)).toBe(400);
    }
    await agent()
      .patch(groupPath(created.id))
      .query({ tenantId: tenantA })
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 })
      .expect(400);
    for (const query of [{}, { expectedVersion: '03' }, { expectedVersion: 'x' }]) {
      const res = await agent()
        .delete(groupPath(created.id))
        .set(auth(tokenA))
        .set('idempotency-key', idemKey())
        .query(query);
      expect(res.status, JSON.stringify(query)).toBe(400);
    }
    const noFields = await agent()
      .patch(groupPath(created.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ expectedVersion: 1 });
    expect(noFields.status).toBe(400);
  });
});

describe('types — CRUD, moves, scope and uniqueness', () => {
  it('creates, reads, updates, moves between groups and deletes with audit', async () => {
    const group1 = await createGroupOk();
    const group2 = await createGroupOk();
    const t = tag();
    const created = await agent()
      .post(TYPES)
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ groupId: group1.id, name: `بارگیر ${t}`, displayOrder: 2 })
      .expect(201);
    const dto = created.body.data as { id: string; groupId: string; version: number };
    expect(dto).toMatchObject({ groupId: group1.id, name: `بارگیر ${t}`, version: 1 });

    const list = await agent()
      .get(TYPES)
      .query({ groupId: group1.id })
      .set(auth(tokenA))
      .expect(200);
    expect(list.body.meta).toEqual({ page: 1, pageSize: 50, total: 1 });
    expect(list.body.data.map((row: { id: string }) => row.id)).toEqual([dto.id]);

    const read = await agent().get(typePath(dto.id)).set(auth(tokenA)).expect(200);
    expect(read.body.data).toMatchObject({ id: dto.id, groupId: group1.id });

    const patched = await agent()
      .patch(typePath(dto.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 4, expectedVersion: 1 })
      .expect(200);
    expect(patched.body.data).toMatchObject({ displayOrder: 4, version: 2 });

    const moved = await agent()
      .patch(typePath(dto.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ groupId: group2.id, expectedVersion: 2 })
      .expect(200);
    expect(moved.body.data).toMatchObject({ groupId: group2.id, version: 3 });

    const oldGroup = await agent()
      .get(TYPES)
      .query({ groupId: group1.id })
      .set(auth(tokenA))
      .expect(200);
    expect(oldGroup.body.meta.total).toBe(0);
    const newGroup = await agent()
      .get(TYPES)
      .query({ groupId: group2.id })
      .set(auth(tokenA))
      .expect(200);
    expect(newGroup.body.data.map((row: { id: string }) => row.id)).toEqual([dto.id]);

    await agent()
      .delete(typePath(dto.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 3 })
      .expect(204);
    await agent().get(typePath(dto.id)).set(auth(tokenA)).expect(404);

    const audit = await auditRows(tenantA, dto.id);
    expect(audit.map((row) => row.action)).toEqual([
      'loader_type.created',
      'loader_type.updated',
      'loader_type.updated',
      'loader_type.deleted',
    ]);
    expect(audit[0]?.metadata).toEqual({ groupId: group1.id });
    expect(audit[1]?.metadata).toEqual({ groupId: group1.id });
    expect(audit[2]?.metadata).toEqual({
      groupId: group2.id,
      previousGroupId: group1.id,
    });
    expect(audit[3]?.metadata).toEqual({ groupId: group2.id });
    for (const row of audit) {
      expect(row.resource_type).toBe('loader_type');
      expect(row.actor_user_id).toBe(userA);
      expect(row.after).not.toHaveProperty('groupId');
      expect(row.after).not.toHaveProperty('nameKey');
    }
  });

  it('keeps type names unique per tenant, not per group, and reuses after delete', async () => {
    const groupA = await createGroupOk();
    const groupB = await createGroupOk();
    const name = `مشترک ${tag()}`;
    const first = await createTypeOk(groupA.id, { name });
    const duplicate = await createLoaderType({ groupId: groupB.id, name });
    expect(duplicate.status).toBe(409);
    expect(duplicate.body.error).toMatchObject({
      code: 'CONFLICT',
      details: { field: 'name' },
    });

    await agent()
      .delete(typePath(first.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    await createTypeOk(groupB.id, { name });
  });

  it('maps rename collisions to 409 CONFLICT without writing an audit row', async () => {
    const t = tag();
    const groupA = await createGroupOk({ name: `Rename A ${t}` });
    const groupB = await createGroupOk({ name: `Rename B ${t}` });
    const groupConflict = await agent()
      .patch(groupPath(groupB.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ name: `Rename A ${t}`, expectedVersion: 1 });
    expect(groupConflict.status).toBe(409);
    expect(groupConflict.body.error).toMatchObject({
      code: 'CONFLICT',
      details: { field: 'name' },
    });
    expect((await auditRows(tenantA, groupB.id)).map((row) => row.action)).toEqual([
      'loader_type_group.created',
    ]);
    const groupRead = await agent().get(groupPath(groupB.id)).set(auth(tokenA)).expect(200);
    expect(groupRead.body.data).toMatchObject({ name: `Rename B ${t}`, version: 1 });

    await createTypeOk(groupA.id, { name: `Rename Type A ${t}` });
    const typeB = await createTypeOk(groupA.id, { name: `Rename Type B ${t}` });
    const typeConflict = await agent()
      .patch(typePath(typeB.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ name: `Rename Type A ${t}`, expectedVersion: 1 });
    expect(typeConflict.status).toBe(409);
    expect(typeConflict.body.error).toMatchObject({
      code: 'CONFLICT',
      details: { field: 'name' },
    });
    expect((await auditRows(tenantA, typeB.id)).map((row) => row.action)).toEqual([
      'loader_type.created',
    ]);
    const typeRead = await agent().get(typePath(typeB.id)).set(auth(tokenA)).expect(200);
    expect(typeRead.body.data).toMatchObject({ name: `Rename Type B ${t}`, version: 1 });
  });

  it('rejects a missing/malformed groupId and server-only keys', async () => {
    const group = await createGroupOk();
    const missing = await createLoaderType({ name: 'No Group' });
    expect(missing.status).toBe(400);
    expect((await createLoaderType({ groupId: 'not-a-uuid', name: 'Bad Group' })).status).toBe(400);
    for (const extra of [
      { tenantId: tenantA },
      { nameKey: 'x' },
      { version: 2 },
      { id: uuidv7() },
      { createdAt: new Date().toISOString() },
    ]) {
      const res = await createLoaderType({
        groupId: group.id,
        name: 'Mass Type',
        ...extra,
      });
      expect(res.status, JSON.stringify(extra)).toBe(400);
    }
    const type = await createTypeOk(group.id);
    for (const query of [{ tenantId: tenantA }, { foo: '1' }]) {
      await agent().get(typePath(type.id)).query(query).set(auth(tokenA)).expect(400);
    }
    for (const extra of [
      { tenantId: tenantA },
      { nameKey: 'x' },
      { id: uuidv7() },
      { version: 2 },
      { createdAt: new Date().toISOString() },
    ]) {
      const res = await agent()
        .patch(typePath(type.id))
        .set(auth(tokenA))
        .set('idempotency-key', idemKey())
        .send({ displayOrder: 1, expectedVersion: 1, ...extra });
      expect(res.status, JSON.stringify(extra)).toBe(400);
    }
    await agent()
      .patch(typePath(type.id))
      .query({ tenantId: tenantA })
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 })
      .expect(400);
    const noFields = await agent()
      .patch(typePath(type.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ expectedVersion: 1 });
    expect(noFields.status).toBe(400);
  });

  it('returns stale/invalid version errors for type mutations', async () => {
    const group = await createGroupOk();
    const type = await createTypeOk(group.id);
    const stale = await agent()
      .patch(typePath(type.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 2, expectedVersion: 9 });
    expect(stale.status).toBe(409);
    expect(stale.body.error.code).toBe('STALE_VERSION');
    const badDelete = await agent()
      .delete(typePath(type.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '01' });
    expect(badDelete.status).toBe(400);
  });
});

describe('types/groups — cross-scope and deleted-parent 404 parity', () => {
  it('returns the identical 404 for another tenant’s group or type', async () => {
    const groupA = await createGroupOk();
    const typeA = await createTypeOk(groupA.id);
    const bGroup = await agent()
      .post(GROUPS)
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send({ name: `Other Tenant Group ${tag()}` })
      .expect(201);
    const bGroupId = bGroup.body.data.id as string;
    const missing = uuidv7();
    const missingBody = await agent().get(groupPath(missing)).set(auth(tokenA)).expect(404);

    const foreignGroup = await agent().get(groupPath(bGroupId)).set(auth(tokenA)).expect(404);
    expect(foreignGroup.body).toEqual(missingBody.body);

    const patchForeign = await agent()
      .patch(groupPath(bGroupId))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 })
      .expect(404);
    const patchMissing = await agent()
      .patch(groupPath(missing))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 })
      .expect(404);
    expect(patchForeign.body).toEqual(patchMissing.body);

    const deleteForeign = await agent()
      .delete(groupPath(bGroupId))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(404);
    expect(deleteForeign.body).toEqual(missingBody.body);

    // Tenant B sees neither A's group nor A's type.
    expect((await agent().get(groupPath(groupA.id)).set(auth(tokenB)).expect(404)).body).toEqual(
      missingBody.body,
    );
    expect((await agent().get(typePath(typeA.id)).set(auth(tokenB)).expect(404)).body).toEqual(
      missingBody.body,
    );
  });

  it('answers a foreign body groupId and a foreign group filter with the same 404', async () => {
    const bGroup = await agent()
      .post(GROUPS)
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send({ name: `Foreign Group ${tag()}` })
      .expect(201);
    const bGroupId = bGroup.body.data.id as string;
    const missing = uuidv7();

    const createForeign = await createLoaderType({ groupId: bGroupId, name: 'Cross Tenant' });
    const createMissing = await createLoaderType({ groupId: missing, name: 'Cross Tenant' });
    expect(createForeign.status).toBe(404);
    expect(createForeign.body).toEqual(createMissing.body);

    const listForeign = await agent()
      .get(TYPES)
      .query({ groupId: bGroupId })
      .set(auth(tokenA))
      .expect(404);
    const listMissing = await agent()
      .get(TYPES)
      .query({ groupId: missing })
      .set(auth(tokenA))
      .expect(404);
    expect(listForeign.body).toEqual(listMissing.body);
  });

  it('treats a deleted group as missing for create, move and list-filter', async () => {
    const group1 = await createGroupOk();
    const group2 = await createGroupOk();
    const type = await createTypeOk(group1.id);
    await agent()
      .delete(groupPath(group2.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);

    const missingBody = await agent()
      .get(TYPES)
      .query({ groupId: uuidv7() })
      .set(auth(tokenA))
      .expect(404);

    const createDeleted = await createLoaderType({ groupId: group2.id, name: 'Under Deleted' });
    expect(createDeleted.status).toBe(404);
    expect(createDeleted.body).toEqual(missingBody.body);

    const moveDeleted = await agent()
      .patch(typePath(type.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ groupId: group2.id, expectedVersion: 1 })
      .expect(404);
    expect(moveDeleted.body).toEqual(missingBody.body);

    const listDeleted = await agent()
      .get(TYPES)
      .query({ groupId: group2.id })
      .set(auth(tokenA))
      .expect(404);
    expect(listDeleted.body).toEqual(missingBody.body);

    // The rejected move left the type in its original group.
    const read = await agent().get(typePath(type.id)).set(auth(tokenA)).expect(200);
    expect(read.body.data).toMatchObject({ groupId: group1.id, version: 1 });
  });
});

describe('loader types/groups — idempotency and audit', () => {
  it('replays group and type creation once, with one audit row each', async () => {
    const groupKey = idemKey();
    const groupBody = { name: `Idem Group ${tag()}` };
    const first = await agent()
      .post(GROUPS)
      .set(auth(tokenA))
      .set('idempotency-key', groupKey)
      .send(groupBody)
      .expect(201);
    const replay = await agent()
      .post(GROUPS)
      .set(auth(tokenA))
      .set('idempotency-key', groupKey)
      .send(groupBody)
      .expect(201);
    expect(replay.headers['idempotent-replayed']).toBe('true');
    expect(replay.body).toEqual(first.body);
    const groupId = first.body.data.id as string;
    expect((await auditRows(tenantA, groupId)).length).toBe(1);

    const key = idemKey();
    const body = { groupId, name: `Idem Type ${tag()}` };
    const tFirst = await agent()
      .post(TYPES)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send(body)
      .expect(201);
    const tReplay = await agent()
      .post(TYPES)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send(body)
      .expect(201);
    expect(tReplay.headers['idempotent-replayed']).toBe('true');
    expect(tReplay.body).toEqual(tFirst.body);
    const typeId = tFirst.body.data.id as string;
    expect((await auditRows(tenantA, typeId)).length).toBe(1);
  });

  it('includes DELETE expectedVersion in the fingerprint and writes one audit row', async () => {
    const group = await createGroupOk();
    const type = await createTypeOk(group.id);
    const key = idemKey();
    await agent()
      .delete(typePath(type.id))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .query({ expectedVersion: 1 })
      .expect(204);
    const replay = await agent()
      .delete(typePath(type.id))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .query({ expectedVersion: 1 })
      .expect(204);
    expect(replay.headers['idempotent-replayed']).toBe('true');
    const different = await agent()
      .delete(typePath(type.id))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .query({ expectedVersion: 2 });
    expect(different.status).toBe(422);
    const deletedAudit = (await auditRows(tenantA, type.id)).filter(
      (row) => row.action === 'loader_type.deleted',
    );
    expect(deletedAudit).toHaveLength(1);
    expect(deletedAudit[0]?.metadata).toEqual({ groupId: group.id });
  });

  it('writes no audit row for a rolled-back duplicate type', async () => {
    const group = await createGroupOk();
    const name = `Rollback Type ${tag()}`;
    await createTypeOk(group.id, { name });
    const before = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1',
      [tenantA],
    );
    expect((await createLoaderType({ groupId: group.id, name })).status).toBe(409);
    const after = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1',
      [tenantA],
    );
    expect(after.rows[0]?.n).toBe(before.rows[0]?.n);
  });
});

describe('loader types/groups — listing', () => {
  it('lists groups with pagination, sort, q, isActive and soft-delete exclusion', async () => {
    const word = `GroupList${tag()}`;
    const t = tag();
    const first = await createGroupOk({
      name: `${word} A ${t}`,
      isActive: false,
      displayOrder: 1,
    });
    const second = await createGroupOk({
      name: `${word} B ${t}`,
      isActive: true,
      displayOrder: 2,
    });
    const third = await createGroupOk({
      name: `${word} C ${t}`,
      isActive: true,
      displayOrder: 3,
    });

    const page = await agent()
      .get(GROUPS)
      .query({ q: word, pageSize: 2 })
      .set(auth(tokenA))
      .expect(200);
    expect(page.body.meta).toEqual({ page: 1, pageSize: 2, total: 3 });
    expect(page.body.data.map((row: { id: string }) => row.id)).toEqual([first.id, second.id]);

    const active = await agent()
      .get(GROUPS)
      .query({ q: word, isActive: 'true' })
      .set(auth(tokenA))
      .expect(200);
    expect(active.body.meta).toEqual({ page: 1, pageSize: 50, total: 2 });
    expect(active.body.data.map((row: { id: string }) => row.id)).toEqual([second.id, third.id]);

    const inactive = await agent()
      .get(GROUPS)
      .query({ q: word, isActive: 'false' })
      .set(auth(tokenA))
      .expect(200);
    expect(inactive.body.data.map((row: { id: string }) => row.id)).toEqual([first.id]);

    await agent()
      .get(GROUPS)
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
      const res = await agent().get(GROUPS).query(query).set(auth(tokenA));
      expect(res.status, JSON.stringify(query)).toBe(400);
    }
    const huge = await agent()
      .get(GROUPS)
      .query({ page: 1_000_000_000, q: word })
      .set(auth(tokenA))
      .expect(200);
    expect(huge.body.data).toEqual([]);
    await agent().get(GROUPS).query({ page: 1_000_000_001 }).set(auth(tokenA)).expect(400);

    await agent()
      .delete(groupPath(third.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    const afterDelete = await agent().get(GROUPS).query({ q: word }).set(auth(tokenA)).expect(200);
    expect(afterDelete.body.meta.total).toBe(2);
    expect(afterDelete.body.data.map((row: { id: string }) => row.id)).not.toContain(third.id);
  });

  it('escapes LIKE metacharacters and normalizes q for groups', async () => {
    const word = `Esc${tag()}`;
    const percent = await createGroupOk({ name: `100% ${word}` });
    await createGroupOk({ name: `100x ${word}` });
    const escape = await agent()
      .get(GROUPS)
      .query({ q: `100% ${word}` })
      .set(auth(tokenA))
      .expect(200);
    expect(escape.body.data.map((row: { id: string }) => row.id)).toEqual([percent.id]);

    const fa = await createGroupOk({ name: `کریمان ${word}` });
    const normalized = await agent()
      .get(GROUPS)
      .query({ q: `كريمان ${word}` })
      .set(auth(tokenA))
      .expect(200);
    expect(normalized.body.data.map((row: { id: string }) => row.id)).toContain(fa.id);
  });

  it('lists types with group filter, isActive, q, sort, bounds and soft-delete exclusion', async () => {
    const group = await createGroupOk();
    const other = await createGroupOk();
    const word = `TypeList${tag()}`;
    const a = await createTypeOk(group.id, {
      name: `${word} A ${tag()}`,
      isActive: false,
      displayOrder: 3,
    });
    const b = await createTypeOk(group.id, {
      name: `${word} B ${tag()}`,
      isActive: true,
      displayOrder: 1,
    });
    const c = await createTypeOk(group.id, {
      name: `${word} C ${tag()}`,
      isActive: true,
      displayOrder: 2,
    });
    const otherType = await createTypeOk(other.id, { name: `${word} Other ${tag()}` });

    const list = await agent()
      .get(TYPES)
      .query({ groupId: group.id, q: word })
      .set(auth(tokenA))
      .expect(200);
    expect(list.body.meta).toEqual({ page: 1, pageSize: 50, total: 3 });
    expect(list.body.data.map((row: { id: string }) => row.id)).toEqual([b.id, c.id, a.id]);

    const active = await agent()
      .get(TYPES)
      .query({ groupId: group.id, q: word, isActive: 'true' })
      .set(auth(tokenA))
      .expect(200);
    expect(active.body.data.map((row: { id: string }) => row.id)).toEqual([b.id, c.id]);

    const page = await agent()
      .get(TYPES)
      .query({ groupId: group.id, q: word, pageSize: 2 })
      .set(auth(tokenA))
      .expect(200);
    expect(page.body.meta).toEqual({ page: 1, pageSize: 2, total: 3 });
    expect(page.body.data).toHaveLength(2);

    await agent()
      .get(TYPES)
      .query({ groupId: group.id, q: word, sort: 'name' })
      .set(auth(tokenA))
      .expect(200);

    for (const query of [
      { pageSize: 101 },
      { sort: 'tenantId' },
      { tenantId: tenantA },
      { groupId: 'not-a-uuid' },
    ]) {
      const res = await agent().get(TYPES).query(query).set(auth(tokenA));
      expect(res.status, JSON.stringify(query)).toBe(400);
    }

    await agent()
      .delete(typePath(c.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: 1 })
      .expect(204);
    const afterDelete = await agent()
      .get(TYPES)
      .query({ groupId: group.id, q: word })
      .set(auth(tokenA))
      .expect(200);
    expect(afterDelete.body.meta.total).toBe(2);
    expect(afterDelete.body.data.map((row: { id: string }) => row.id)).not.toContain(c.id);

    const otherList = await agent()
      .get(TYPES)
      .query({ groupId: other.id, q: word })
      .set(auth(tokenA))
      .expect(200);
    expect(otherList.body.data.map((row: { id: string }) => row.id)).toEqual([otherType.id]);
  });

  it('escapes LIKE metacharacters and normalizes q for types', async () => {
    const group = await createGroupOk();
    const word = `EscType${tag()}`;
    const percent = await createTypeOk(group.id, { name: `100% ${word}` });
    await createTypeOk(group.id, { name: `100x ${word}` });
    const escape = await agent()
      .get(TYPES)
      .query({ groupId: group.id, q: `100% ${word}` })
      .set(auth(tokenA))
      .expect(200);
    expect(escape.body.data.map((row: { id: string }) => row.id)).toEqual([percent.id]);

    const fa = await createTypeOk(group.id, { name: `کریمان ${word}` });
    const normalized = await agent()
      .get(TYPES)
      .query({ groupId: group.id, q: `كريمان ${word}` })
      .set(auth(tokenA))
      .expect(200);
    expect(normalized.body.data.map((row: { id: string }) => row.id)).toContain(fa.id);
  });
});

describe('AT-11 — delete-group vs create/move type races', () => {
  it('never leaves a live type under a deleted group across 50 iterations', async () => {
    for (let i = 0; i < 50; i += 1) {
      const group = await createGroupOk({ name: `Race Group ${i} ${tag()}` });
      const [deleted, created] = await Promise.all([
        agent()
          .delete(groupPath(group.id))
          .set(auth(tokenA))
          .set('idempotency-key', idemKey())
          .query({ expectedVersion: 1 }),
        createLoaderType({ groupId: group.id, name: `Race Type ${i} ${tag()}` }),
      ]);

      expect([204, 409]).toContain(deleted.status);
      expect([201, 404]).toContain(created.status);

      const live = await liveTypes(group.id);
      if (deleted.status === 204) {
        // The group was deleted first: the child create must have missed it.
        expect(created.status).toBe(404);
        expect(live).toBe(0);
      } else {
        // The child won: the group delete saw it and refused.
        expect(deleted.body.error.code).toBe('IN_USE');
        expect(created.status).toBe(201);
        expect(live).toBe(1);
      }
    }
  }, 180_000);

  it('never moves a type into a group that is deleted across 50 iterations', async () => {
    for (let i = 0; i < 50; i += 1) {
      const source = await createGroupOk({ name: `Move Source ${i} ${tag()}` });
      const target = await createGroupOk({ name: `Move Target ${i} ${tag()}` });
      const type = await createTypeOk(source.id);
      const [deleted, moved] = await Promise.all([
        agent()
          .delete(groupPath(target.id))
          .set(auth(tokenA))
          .set('idempotency-key', idemKey())
          .query({ expectedVersion: 1 }),
        agent()
          .patch(typePath(type.id))
          .set(auth(tokenA))
          .set('idempotency-key', idemKey())
          .send({ groupId: target.id, expectedVersion: 1 }),
      ]);

      expect([204, 409]).toContain(deleted.status);
      expect([200, 404]).toContain(moved.status);

      const live = await liveTypes(target.id);
      if (deleted.status === 204) {
        // The group was deleted first: the move must have missed it.
        expect(moved.status).toBe(404);
        expect(live).toBe(0);
        const read = await agent().get(typePath(type.id)).set(auth(tokenA)).expect(200);
        expect(read.body.data).toMatchObject({ groupId: source.id, version: 1 });
      } else {
        // The move won: the group delete saw the moved type and refused.
        expect(deleted.body.error.code).toBe('IN_USE');
        expect(moved.status).toBe(200);
        expect(live).toBe(1);
        const read = await agent().get(typePath(type.id)).set(auth(tokenA)).expect(200);
        expect(read.body.data).toMatchObject({ groupId: target.id, version: 2 });
      }
    }
  }, 180_000);

  it('20 parallel type creates of one name produce exactly one 201', async () => {
    const group = await createGroupOk();
    const name = `Parallel Type ${tag()}`;
    const responses = await Promise.all(
      Array.from({ length: 20 }, () => createLoaderType({ groupId: group.id, name })),
    );
    const statuses = responses.map((res) => res.status);
    expect(statuses.filter((status) => status === 201)).toHaveLength(1);
    expect(statuses.filter((status) => status === 409)).toHaveLength(19);
    const winner = responses.find((res) => res.status === 201);
    const id = (winner?.body.data as { id: string }).id;
    expect((await auditRows(tenantA, id)).length).toBe(1);
    const count = await owner.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM loader_types
        WHERE tenant_id = $1 AND group_id = $2 AND name_key = $3 AND deleted_at IS NULL`,
      [tenantA, group.id, name.toLowerCase()],
    );
    expect(count.rows[0]?.n).toBe(1);
  }, 60_000);
});

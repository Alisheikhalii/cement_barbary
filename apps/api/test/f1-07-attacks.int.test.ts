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
 * F1-07 T07 attack suite (ADR-011; CP4).
 *
 * Attacks the five base-data resources over real HTTP + PostgreSQL:
 * cross-tenant IDOR byte parity, the `groupId` oracle, mass assignment on
 * body/query/params, idempotency abuse on all 15 mutating routes, LIKE and
 * sort abuse on every list, Unicode name collisions, the duplicate-name race
 * and the move-vs-source-group-delete race.
 *
 * Already-proven ground is not duplicated here: the `bitabar_app` DB
 * invariants live in `base-data-rls.int.test.ts`, and audit atomicity,
 * allowlisted snapshots, replay and rollback are asserted per resource in the
 * T04–T06 suites and mapped in the CP4 report.
 */

const DEST = '/api/v1/base/destinations';
const HALLS = '/api/v1/base/halls';
const GROUPS = '/api/v1/base/loader-type-groups';
const TYPES = '/api/v1/base/loader-types';

function destPath(id: string): string {
  return `${DEST}/${id}`;
}
function hallPath(id: string): string {
  return `${HALLS}/${id}`;
}
function terminalsPath(hallId: string): string {
  return `${HALLS}/${hallId}/terminals`;
}
function terminalPath(hallId: string, id: string): string {
  return `${terminalsPath(hallId)}/${id}`;
}
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

function auth(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

function idemKey(): string {
  return `atk-${uuidv7()}`;
}

function tag(): string {
  return randomBytes(4).toString('hex');
}

function agent() {
  return request(app.getHttpServer());
}

// ---------- raw senders (no implicit key, so abuse is explicit) ----------

function createDestination(body: Record<string, unknown>, token = tokenA, key = idemKey()) {
  return agent().post(DEST).set(auth(token)).set('idempotency-key', key).send(body);
}
function createHall(body: Record<string, unknown>, token = tokenA, key = idemKey()) {
  return agent().post(HALLS).set(auth(token)).set('idempotency-key', key).send(body);
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
function createGroup(body: Record<string, unknown>, token = tokenA, key = idemKey()) {
  return agent().post(GROUPS).set(auth(token)).set('idempotency-key', key).send(body);
}
function createLoaderType(body: Record<string, unknown>, token = tokenA, key = idemKey()) {
  return agent().post(TYPES).set(auth(token)).set('idempotency-key', key).send(body);
}

// ---------- fixtures ----------

interface Fixture {
  readonly id: string;
  readonly version: number;
}

async function createDestinationOk(body: Record<string, unknown> = {}): Promise<Fixture> {
  const res = await createDestination({ name: `Dest ${tag()}`, ...body });
  if (res.status !== 201) {
    throw new Error(`destination create failed: ${res.status} ${res.text}`);
  }
  return res.body.data as Fixture;
}
async function createHallOk(body: Record<string, unknown> = {}): Promise<Fixture> {
  const res = await createHall({ name: `Hall ${tag()}`, ...body });
  if (res.status !== 201) {
    throw new Error(`hall create failed: ${res.status} ${res.text}`);
  }
  return res.body.data as Fixture;
}
async function createTerminalOk(
  hallId: string,
  body: Record<string, unknown> = {},
): Promise<Fixture & { hallId: string }> {
  const res = await createTerminal(hallId, { name: `Terminal ${tag()}`, ...body });
  if (res.status !== 201) {
    throw new Error(`terminal create failed: ${res.status} ${res.text}`);
  }
  return res.body.data as Fixture & { hallId: string };
}
async function createGroupOk(body: Record<string, unknown> = {}): Promise<Fixture> {
  const res = await createGroup({ name: `Group ${tag()}`, ...body });
  if (res.status !== 201) {
    throw new Error(`group create failed: ${res.status} ${res.text}`);
  }
  return res.body.data as Fixture;
}
async function createTypeOk(
  groupId: string,
  body: Record<string, unknown> = {},
): Promise<Fixture & { groupId: string }> {
  const res = await createLoaderType({ groupId, name: `Type ${tag()}`, ...body });
  if (res.status !== 201) {
    throw new Error(`type create failed: ${res.status} ${res.text}`);
  }
  return res.body.data as Fixture & { groupId: string };
}

interface AuditRow {
  action: string;
  resource_type: string;
  actor_user_id: string | null;
}

async function auditRows(tenantId: string, resourceId: string): Promise<AuditRow[]> {
  const res = await owner.query<AuditRow>(
    `SELECT action, resource_type, actor_user_id
       FROM audit_logs
      WHERE tenant_id = $1 AND resource_id = $2
      ORDER BY occurred_at, id`,
    [tenantId, resourceId],
  );
  return res.rows;
}

async function liveTypes(groupId: string): Promise<number> {
  const res = await owner.query<{ legit: number }>(
    'SELECT count(*)::int AS legit FROM loader_types WHERE group_id = $1 AND deleted_at IS NULL',
    [groupId],
  );
  return res.rows[0]?.legit ?? 0;
}

/** Waits (bounded) until a query against `fragment` is blocked on a lock. */
async function waitForLockWait(fragment: string): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const res = await owner.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_stat_activity
        WHERE wait_event_type = 'Lock' AND state = 'active' AND query ILIKE $1`,
      [`%${fragment}%`],
    );
    if ((res.rows[0]?.n ?? 0) > 0) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`no query blocked on ${fragment}`);
}

function expectNameConflict(res: request.Response, variant: string): void {
  expect(res.status).toBe(409);
  expect(res.body.error).toMatchObject({ code: 'CONFLICT', details: { field: 'name' } });
  // The client value must never be echoed (no oracle, no reflected payload).
  expect(res.text).not.toContain(variant);
}

beforeAll(async () => {
  app = await buildAuthApp();
  owner = ownerPool();
  const suffix = tag();
  tenantA = await createTenant(owner, `attack-a-${suffix}`);
  tenantB = await createTenant(owner, `attack-b-${suffix}`);
  userA = await createUser(owner, tenantA, { username: `attack.op.a.${suffix}` });
  userB = await createUser(owner, tenantB, { username: `attack.op.b.${suffix}` });
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
}, 120_000);

afterAll(async () => {
  await app?.close();
});

// ═══════════════════════════════════════════════════════════════════════════
// AT-01..AT-05 — IDOR across all five resources
// ═══════════════════════════════════════════════════════════════════════════

describe('F1-07 attacks — IDOR across all five resources', () => {
  it('answers the same 404 bytes for tenant B read/patch/delete of a destination', async () => {
    const destination = await createDestinationOk();
    const missing = uuidv7();
    const patchBody = { displayOrder: 2, expectedVersion: 1 };

    const read = await agent().get(destPath(destination.id)).set(auth(tokenB)).expect(404);
    const readMissing = await agent().get(destPath(missing)).set(auth(tokenB)).expect(404);
    expect(read.text).toBe(readMissing.text);

    const patched = await agent()
      .patch(destPath(destination.id))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send(patchBody)
      .expect(404);
    const patchedMissing = await agent()
      .patch(destPath(missing))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send(patchBody)
      .expect(404);
    expect(patched.text).toBe(patchedMissing.text);

    const deleted = await agent()
      .delete(destPath(destination.id))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(404);
    const deletedMissing = await agent()
      .delete(destPath(missing))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(404);
    expect(deleted.text).toBe(deletedMissing.text);

    const still = await agent().get(destPath(destination.id)).set(auth(tokenA)).expect(200);
    expect(still.body.data).toMatchObject({ version: 1, displayOrder: 0 });
  });

  it('answers the same 404 bytes for tenant B read/patch/delete of a hall', async () => {
    const hall = await createHallOk();
    const missing = uuidv7();
    const patchBody = { displayOrder: 2, expectedVersion: 1 };

    const read = await agent().get(hallPath(hall.id)).set(auth(tokenB)).expect(404);
    const readMissing = await agent().get(hallPath(missing)).set(auth(tokenB)).expect(404);
    expect(read.text).toBe(readMissing.text);

    const patched = await agent()
      .patch(hallPath(hall.id))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send(patchBody)
      .expect(404);
    const patchedMissing = await agent()
      .patch(hallPath(missing))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send(patchBody)
      .expect(404);
    expect(patched.text).toBe(patchedMissing.text);

    const deleted = await agent()
      .delete(hallPath(hall.id))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(404);
    const deletedMissing = await agent()
      .delete(hallPath(missing))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(404);
    expect(deleted.text).toBe(deletedMissing.text);

    const still = await agent().get(hallPath(hall.id)).set(auth(tokenA)).expect(200);
    expect(still.body.data).toMatchObject({ version: 1 });
  });

  it('answers the same 404 for a terminal read through another hall or another tenant', async () => {
    const hallA = await createHallOk();
    const hallOther = await createHallOk();
    const terminal = await createTerminalOk(hallA.id);
    const bHallRes = await createHall({ name: `B Hall ${tag()}` }, tokenB).expect(201);
    const bHallId = bHallRes.body.data.id as string;
    const missing = uuidv7();

    // Same tenant, wrong hall path — GET/PATCH/DELETE.
    const wrongRead = await agent()
      .get(terminalPath(hallOther.id, terminal.id))
      .set(auth(tokenA))
      .expect(404);
    const wrongReadMissing = await agent()
      .get(terminalPath(hallOther.id, missing))
      .set(auth(tokenA))
      .expect(404);
    expect(wrongRead.text).toBe(wrongReadMissing.text);

    const wrongPatch = await agent()
      .patch(terminalPath(hallOther.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 })
      .expect(404);
    const wrongPatchMissing = await agent()
      .patch(terminalPath(hallOther.id, missing))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 })
      .expect(404);
    expect(wrongPatch.text).toBe(wrongPatchMissing.text);

    const wrongDelete = await agent()
      .delete(terminalPath(hallOther.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(404);
    const wrongDeleteMissing = await agent()
      .delete(terminalPath(hallOther.id, missing))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(404);
    expect(wrongDelete.text).toBe(wrongDeleteMissing.text);

    // Another tenant's token against A's hall and terminal.
    const foreignRead = await agent()
      .get(terminalPath(hallA.id, terminal.id))
      .set(auth(tokenB))
      .expect(404);
    expect(foreignRead.text).toBe(wrongReadMissing.text);

    const foreignPatch = await agent()
      .patch(terminalPath(bHallId, terminal.id))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 })
      .expect(404);
    const foreignPatchMissing = await agent()
      .patch(terminalPath(bHallId, missing))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 1, expectedVersion: 1 })
      .expect(404);
    expect(foreignPatch.text).toBe(foreignPatchMissing.text);

    const foreignDelete = await agent()
      .delete(terminalPath(bHallId, terminal.id))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(404);
    const foreignDeleteMissing = await agent()
      .delete(terminalPath(bHallId, missing))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(404);
    expect(foreignDelete.text).toBe(foreignDeleteMissing.text);

    const still = await agent()
      .get(terminalPath(hallA.id, terminal.id))
      .set(auth(tokenA))
      .expect(200);
    expect(still.body.data).toMatchObject({ hallId: hallA.id, version: 1 });
  });

  it('answers the same 404 bytes for tenant B read/patch/delete of a loader-type group', async () => {
    const group = await createGroupOk();
    const missing = uuidv7();
    const patchBody = { displayOrder: 2, expectedVersion: 1 };

    const read = await agent().get(groupPath(group.id)).set(auth(tokenB)).expect(404);
    const readMissing = await agent().get(groupPath(missing)).set(auth(tokenB)).expect(404);
    expect(read.text).toBe(readMissing.text);

    const patched = await agent()
      .patch(groupPath(group.id))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send(patchBody)
      .expect(404);
    const patchedMissing = await agent()
      .patch(groupPath(missing))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send(patchBody)
      .expect(404);
    expect(patched.text).toBe(patchedMissing.text);

    const deleted = await agent()
      .delete(groupPath(group.id))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(404);
    const deletedMissing = await agent()
      .delete(groupPath(missing))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(404);
    expect(deleted.text).toBe(deletedMissing.text);

    const still = await agent().get(groupPath(group.id)).set(auth(tokenA)).expect(200);
    expect(still.body.data).toMatchObject({ version: 1 });
  });

  it('answers the same 404 bytes for tenant B read/patch/delete/move of a loader type', async () => {
    const groupA = await createGroupOk();
    const type = await createTypeOk(groupA.id);
    const bGroupRes = await createGroup({ name: `B Group ${tag()}` }, tokenB).expect(201);
    const bGroupId = bGroupRes.body.data.id as string;
    const missing = uuidv7();

    const read = await agent().get(typePath(type.id)).set(auth(tokenB)).expect(404);
    const readMissing = await agent().get(typePath(missing)).set(auth(tokenB)).expect(404);
    expect(read.text).toBe(readMissing.text);

    const patched = await agent()
      .patch(typePath(type.id))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 2, expectedVersion: 1 })
      .expect(404);
    const patchedMissing = await agent()
      .patch(typePath(missing))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send({ displayOrder: 2, expectedVersion: 1 })
      .expect(404);
    expect(patched.text).toBe(patchedMissing.text);

    const moved = await agent()
      .patch(typePath(type.id))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send({ groupId: bGroupId, expectedVersion: 1 })
      .expect(404);
    const movedMissing = await agent()
      .patch(typePath(missing))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .send({ groupId: bGroupId, expectedVersion: 1 })
      .expect(404);
    expect(moved.text).toBe(movedMissing.text);

    const deleted = await agent()
      .delete(typePath(type.id))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(404);
    const deletedMissing = await agent()
      .delete(typePath(missing))
      .set(auth(tokenB))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(404);
    expect(deleted.text).toBe(deletedMissing.text);

    const still = await agent().get(typePath(type.id)).set(auth(tokenA)).expect(200);
    expect(still.body.data).toMatchObject({ groupId: groupA.id, version: 1 });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// AT-06 — groupId existence oracle
// ═══════════════════════════════════════════════════════════════════════════

describe('F1-07 attacks — groupId oracle', () => {
  it('answers the same 404 bytes for foreign, deleted and nonexistent groups on create/move/list', async () => {
    const source = await createGroupOk();
    const deleted = await createGroupOk();
    const type = await createTypeOk(source.id);
    const bGroupRes = await createGroup({ name: `Oracle B ${tag()}` }, tokenB).expect(201);
    const bGroupId = bGroupRes.body.data.id as string;
    const missing = uuidv7();

    await agent()
      .delete(groupPath(deleted.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(204);

    const foreignIds = [bGroupId, deleted.id, missing];
    const createName = `Oracle Type ${tag()}`;
    const createResponses = [];
    for (const groupId of foreignIds) {
      createResponses.push(await createLoaderType({ groupId, name: createName }).expect(404));
    }
    for (const response of createResponses.slice(1)) {
      expect(response.text).toBe(createResponses[0]?.text);
    }

    const moveResponses = [];
    for (const groupId of foreignIds) {
      moveResponses.push(
        await agent()
          .patch(typePath(type.id))
          .set(auth(tokenA))
          .set('idempotency-key', idemKey())
          .send({ groupId, expectedVersion: 1 })
          .expect(404),
      );
    }
    for (const response of moveResponses.slice(1)) {
      expect(response.text).toBe(moveResponses[0]?.text);
    }

    const listResponses = [];
    for (const groupId of foreignIds) {
      listResponses.push(await agent().get(TYPES).query({ groupId }).set(auth(tokenA)).expect(404));
    }
    for (const response of listResponses.slice(1)) {
      expect(response.text).toBe(listResponses[0]?.text);
    }

    const still = await agent().get(typePath(type.id)).set(auth(tokenA)).expect(200);
    expect(still.body.data).toMatchObject({ groupId: source.id, version: 1 });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// AT-07/AT-08 — mass assignment (body, query, params)
// ═══════════════════════════════════════════════════════════════════════════

const FORBIDDEN: readonly (readonly [string, unknown])[] = [
  ['tenantId', 'placeholder'],
  ['tenant_id', 'placeholder'],
  ['status', 'active'],
  ['id', 'placeholder'],
  ['version', 2],
  ['nameKey', 'x'],
  ['createdBy', 'placeholder'],
  ['created_by', 'placeholder'],
  ['deletedAt', '2026-01-01T00:00:00.000Z'],
];

function queryValue(value: unknown): string {
  return typeof value === 'string' ? value : String(value);
}

describe('F1-07 attacks — mass assignment', () => {
  it('rejects every server-only key in POST/PATCH bodies and every query on all five resources', async () => {
    const destination = await createDestinationOk();
    const hall = await createHallOk();
    const terminal = await createTerminalOk(hall.id);
    const group = await createGroupOk();
    const type = await createTypeOk(group.id);

    interface MassCase {
      readonly label: string;
      readonly list: string;
      readonly one: string;
      readonly createPath: string;
      readonly createBody: Record<string, unknown>;
      readonly extra?: readonly string[];
    }
    const cases: MassCase[] = [
      {
        label: 'destination',
        list: DEST,
        one: destPath(destination.id),
        createPath: DEST,
        createBody: { name: `Mass Dest ${tag()}` },
      },
      {
        label: 'hall',
        list: HALLS,
        one: hallPath(hall.id),
        createPath: HALLS,
        createBody: { name: `Mass Hall ${tag()}` },
      },
      {
        label: 'terminal',
        list: terminalsPath(hall.id),
        one: terminalPath(hall.id, terminal.id),
        createPath: terminalsPath(hall.id),
        createBody: { name: `Mass Terminal ${tag()}` },
        extra: ['hallId'],
      },
      {
        label: 'group',
        list: GROUPS,
        one: groupPath(group.id),
        createPath: GROUPS,
        createBody: { name: `Mass Group ${tag()}` },
      },
      {
        label: 'type',
        list: TYPES,
        one: typePath(type.id),
        createPath: TYPES,
        createBody: { name: `Mass Type ${tag()}`, groupId: group.id },
      },
    ];

    for (const resource of cases) {
      const keys: [string, unknown][] = [
        ...FORBIDDEN.map(([key, value]) => {
          const concrete =
            key === 'tenantId' || key === 'tenant_id'
              ? tenantA
              : key === 'id'
                ? uuidv7()
                : key === 'createdBy' || key === 'created_by'
                  ? userA
                  : value;
          return [key, concrete] as [string, unknown];
        }),
        ...(resource.extra === undefined
          ? []
          : resource.extra.map((key) => [key, hall.id] as [string, unknown])),
      ];

      for (const [key, value] of keys) {
        const post = await agent()
          .post(resource.createPath)
          .set(auth(tokenA))
          .set('idempotency-key', idemKey())
          .send({ ...resource.createBody, [key]: value });
        expect(post.status, `${resource.label} POST ${key}`).toBe(400);

        const patch = await agent()
          .patch(resource.one)
          .set(auth(tokenA))
          .set('idempotency-key', idemKey())
          .send({ displayOrder: 1, expectedVersion: 1, [key]: value });
        expect(patch.status, `${resource.label} PATCH ${key}`).toBe(400);

        const list = await agent()
          .get(resource.list)
          .query({ [key]: queryValue(value) })
          .set(auth(tokenA));
        expect(list.status, `${resource.label} LIST ${key}`).toBe(400);

        const one = await agent()
          .get(resource.one)
          .query({ [key]: queryValue(value) })
          .set(auth(tokenA));
        expect(one.status, `${resource.label} GET ${key}`).toBe(400);

        const del = await agent()
          .delete(resource.one)
          .query({ expectedVersion: '1', [key]: queryValue(value) })
          .set(auth(tokenA))
          .set('idempotency-key', idemKey());
        expect(del.status, `${resource.label} DELETE ${key}`).toBe(400);

        const patchQuery = await agent()
          .patch(resource.one)
          .query({ [key]: queryValue(value) })
          .set(auth(tokenA))
          .set('idempotency-key', idemKey())
          .send({ displayOrder: 1, expectedVersion: 1 });
        expect(patchQuery.status, `${resource.label} PATCH-QUERY ${key}`).toBe(400);
      }
    }

    // No forbidden request reached a handler: every fixture is untouched.
    for (const one of [
      destPath(destination.id),
      hallPath(hall.id),
      terminalPath(hall.id, terminal.id),
      groupPath(group.id),
      typePath(type.id),
    ]) {
      const res = await agent().get(one).set(auth(tokenA)).expect(200);
      expect(res.body.data.version).toBe(1);
    }
    expect((await auditRows(tenantA, destination.id)).map((row) => row.action)).toEqual([
      'destination.created',
    ]);
  }, 60_000);

  it('rejects malformed params and unmatched path segments without a 500', async () => {
    const destination = await createDestinationOk();
    const hall = await createHallOk();
    const terminal = await createTerminalOk(hall.id);
    const group = await createGroupOk();
    const type = await createTypeOk(group.id);

    for (const path of [DEST, HALLS, GROUPS, TYPES]) {
      await agent().get(`${path}/not-a-uuid`).set(auth(tokenA)).expect(400);
    }
    await agent()
      .get(`${terminalsPath(hall.id)}/not-a-uuid`)
      .set(auth(tokenA))
      .expect(400);
    await agent().get(`${DEST}/not-a-uuid`).expect(401);
    await agent().get(`${DEST}/not-a-uuid`).set(auth(carrierToken)).expect(403);

    for (const path of [
      `${destPath(destination.id)}/extra`,
      `${hallPath(hall.id)}/extra`,
      `${terminalPath(hall.id, terminal.id)}/extra`,
      `${groupPath(group.id)}/extra`,
      `${typePath(type.id)}/extra`,
    ]) {
      const res = await agent().get(path).set(auth(tokenA));
      expect(res.status, path).toBe(404);
    }

    // Encoded dot segments and duplicate slashes must never be a 500 or mutate.
    for (const path of [`${DEST}/%2e%2e`, `${DEST}//${destination.id}`]) {
      const res = await agent().get(path).set(auth(tokenA));
      expect(res.status, path).not.toBe(500);
    }
    const still = await agent().get(destPath(destination.id)).set(auth(tokenA)).expect(200);
    expect(still.body.data.version).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// AT-10/AT-11/AT-12 — idempotency abuse on all 15 mutating routes
// ═══════════════════════════════════════════════════════════════════════════

interface MutationSpec {
  readonly label: string;
  readonly method: 'post' | 'patch' | 'delete';
  readonly path: string;
  readonly body?: Record<string, unknown>;
  readonly query?: Record<string, string>;
}

function sendMutation(spec: MutationSpec, key?: string) {
  let call;
  if (spec.method === 'post') {
    call = agent().post(spec.path);
  } else if (spec.method === 'patch') {
    call = agent().patch(spec.path);
  } else {
    call = agent().delete(spec.path);
  }
  call = call.set(auth(tokenA));
  if (key !== undefined) {
    call = call.set('idempotency-key', key);
  }
  if (spec.body !== undefined) {
    call = call.send(spec.body);
  }
  if (spec.query !== undefined) {
    call = call.query(spec.query);
  }
  return call;
}

describe('F1-07 attacks — idempotency on all 15 mutating routes', () => {
  it('requires a well-formed key on every mutating route, with no side effect', async () => {
    const destination = await createDestinationOk();
    const hall = await createHallOk();
    const terminal = await createTerminalOk(hall.id);
    const group = await createGroupOk();
    const type = await createTypeOk(group.id);

    const mutations: MutationSpec[] = [
      { label: 'POST destination', method: 'post', path: DEST, body: { name: `Key ${tag()}` } },
      {
        label: 'PATCH destination',
        method: 'patch',
        path: destPath(destination.id),
        body: { displayOrder: 1, expectedVersion: 1 },
      },
      {
        label: 'DELETE destination',
        method: 'delete',
        path: destPath(destination.id),
        query: { expectedVersion: '1' },
      },
      { label: 'POST hall', method: 'post', path: HALLS, body: { name: `Key ${tag()}` } },
      {
        label: 'PATCH hall',
        method: 'patch',
        path: hallPath(hall.id),
        body: { displayOrder: 1, expectedVersion: 1 },
      },
      {
        label: 'DELETE hall',
        method: 'delete',
        path: hallPath(hall.id),
        query: { expectedVersion: '1' },
      },
      {
        label: 'POST terminal',
        method: 'post',
        path: terminalsPath(hall.id),
        body: { name: `Key ${tag()}` },
      },
      {
        label: 'PATCH terminal',
        method: 'patch',
        path: terminalPath(hall.id, terminal.id),
        body: { displayOrder: 1, expectedVersion: 1 },
      },
      {
        label: 'DELETE terminal',
        method: 'delete',
        path: terminalPath(hall.id, terminal.id),
        query: { expectedVersion: '1' },
      },
      { label: 'POST group', method: 'post', path: GROUPS, body: { name: `Key ${tag()}` } },
      {
        label: 'PATCH group',
        method: 'patch',
        path: groupPath(group.id),
        body: { displayOrder: 1, expectedVersion: 1 },
      },
      {
        label: 'DELETE group',
        method: 'delete',
        path: groupPath(group.id),
        query: { expectedVersion: '1' },
      },
      {
        label: 'POST type',
        method: 'post',
        path: TYPES,
        body: { name: `Key ${tag()}`, groupId: group.id },
      },
      {
        label: 'PATCH type',
        method: 'patch',
        path: typePath(type.id),
        body: { displayOrder: 1, expectedVersion: 1 },
      },
      {
        label: 'DELETE type',
        method: 'delete',
        path: typePath(type.id),
        query: { expectedVersion: '1' },
      },
    ];
    expect(mutations).toHaveLength(15);

    const auditBefore = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1',
      [tenantA],
    );
    for (const mutation of mutations) {
      const missing = await sendMutation(mutation);
      expect(missing.status, `${mutation.label} missing key`).toBe(400);
      expect(missing.body.error.code, mutation.label).toBe('IDEMPOTENCY_KEY_REQUIRED');

      const malformed = await sendMutation(mutation, 'short');
      expect(malformed.status, `${mutation.label} malformed key`).toBe(400);
      expect(malformed.body.error.code, mutation.label).toBe('IDEMPOTENCY_KEY_REQUIRED');
    }
    const auditAfter = await owner.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1',
      [tenantA],
    );
    expect(auditAfter.rows[0]?.n).toBe(auditBefore.rows[0]?.n);

    // No missing-key request reached a handler.
    for (const path of [
      destPath(destination.id),
      hallPath(hall.id),
      terminalPath(hall.id, terminal.id),
      groupPath(group.id),
      typePath(type.id),
    ]) {
      const res = await agent().get(path).set(auth(tokenA)).expect(200);
      expect(res.body.data.version).toBe(1);
    }
  });

  it('replays a PATCH exactly once and audits it once', async () => {
    const destination = await createDestinationOk();
    const key = idemKey();
    const body = { displayOrder: 5, expectedVersion: 1 };
    const first = await agent()
      .patch(destPath(destination.id))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send(body)
      .expect(200);
    expect(first.body.data).toMatchObject({ displayOrder: 5, version: 2 });

    const replay = await agent()
      .patch(destPath(destination.id))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send(body)
      .expect(200);
    expect(replay.headers['idempotent-replayed']).toBe('true');
    expect(replay.body).toEqual(first.body);

    const read = await agent().get(destPath(destination.id)).set(auth(tokenA)).expect(200);
    expect(read.body.data.version).toBe(2);
    const updates = (await auditRows(tenantA, destination.id)).filter(
      (row) => row.action === 'destination.updated',
    );
    expect(updates).toHaveLength(1);
  });

  it('rejects a key reused with a different body, path id or expectedVersion', async () => {
    const first = await createDestinationOk();
    const second = await createDestinationOk();
    const key = idemKey();
    const body = { displayOrder: 5, expectedVersion: 1 };
    await agent()
      .patch(destPath(first.id))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send(body)
      .expect(200);

    const differentBody = await agent()
      .patch(destPath(first.id))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send({ displayOrder: 6, expectedVersion: 1 });
    expect(differentBody.status).toBe(422);
    expect(differentBody.body.error.code).toBe('IDEMPOTENCY_KEY_REUSED');
    const firstRead = await agent().get(destPath(first.id)).set(auth(tokenA)).expect(200);
    expect(firstRead.body.data).toMatchObject({ displayOrder: 5, version: 2 });

    const differentId = await agent()
      .patch(destPath(second.id))
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send(body);
    expect(differentId.status).toBe(422);
    expect(differentId.body.error.code).toBe('IDEMPOTENCY_KEY_REUSED');
    const untouched = await agent().get(destPath(second.id)).set(auth(tokenA)).expect(200);
    expect(untouched.body.data.version).toBe(1);

    const third = await createDestinationOk();
    const deleteKey = idemKey();
    await agent()
      .delete(destPath(third.id))
      .set(auth(tokenA))
      .set('idempotency-key', deleteKey)
      .query({ expectedVersion: '1' })
      .expect(204);
    const differentVersion = await agent()
      .delete(destPath(third.id))
      .set(auth(tokenA))
      .set('idempotency-key', deleteKey)
      .query({ expectedVersion: '2' });
    expect(differentVersion.status).toBe(422);
    expect(differentVersion.body.error.code).toBe('IDEMPOTENCY_KEY_REUSED');
  });

  it('does not store or replay a business handler error (409)', async () => {
    const t = tag();
    const name = `Attack Rollback ${t}`;
    const original = await createDestinationOk({ name });
    const key = idemKey();
    const failed = await agent()
      .post(DEST)
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

    // Clear the conflict, then retry with the SAME key: the handler re-executes.
    await owner.query('UPDATE destinations SET deleted_at = now() WHERE id = $1', [original.id]);
    const retried = await agent()
      .post(DEST)
      .set(auth(tokenA))
      .set('idempotency-key', key)
      .send({ name })
      .expect(201);
    expect(retried.headers['idempotent-replayed']).toBeUndefined();
  });

  it('does not store a real 503 from DB lock contention and re-executes after the lock clears', async () => {
    // A dedicated app with a short lock/handler cap: the service's SELECT FOR
    // UPDATE waits behind an owner lock, PostgreSQL raises 55P03 (lock
    // timeout), and runGuarded answers a generic 503. The claim must roll back.
    const previousLock = process.env.IDEMPOTENCY_LOCK_TIMEOUT_MS;
    const previousHandler = process.env.IDEMPOTENCY_HANDLER_TIMEOUT_MS;
    let timeoutApp: NestExpressApplication | undefined;
    try {
      timeoutApp = await buildAuthApp({
        IDEMPOTENCY_LOCK_TIMEOUT_MS: '500',
        IDEMPOTENCY_HANDLER_TIMEOUT_MS: '1000',
      });
      const destination = await createDestinationOk();
      const key = idemKey();
      const routeKey = 'PATCH /api/v1/base/destinations/:id';
      const body = { displayOrder: 2, expectedVersion: 1 };
      const client = await owner.connect();
      try {
        await client.query('BEGIN');
        await client.query('SELECT id FROM destinations WHERE id = $1 FOR UPDATE', [
          destination.id,
        ]);
        const failed = await request(timeoutApp.getHttpServer())
          .patch(destPath(destination.id))
          .set(auth(tokenA))
          .set('idempotency-key', key)
          .send(body);
        expect(failed.status).toBe(503);
        // 55P03 normally wins; a starved event loop may surface 57014 first.
        expect(['SERVICE_UNAVAILABLE', 'IDEMPOTENCY_TIMEOUT']).toContain(failed.body.error.code);
      } finally {
        await client.query('ROLLBACK').catch(() => undefined);
        client.release();
      }

      const keyRows = await owner.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM idempotency_keys
          WHERE tenant_id = $1 AND user_id = $2 AND route_key = $3 AND idem_key = $4`,
        [tenantA, userA, routeKey, key],
      );
      expect(keyRows.rows[0]?.n).toBe(0);

      const retried = await agent()
        .patch(destPath(destination.id))
        .set(auth(tokenA))
        .set('idempotency-key', key)
        .send(body)
        .expect(200);
      expect(retried.headers['idempotent-replayed']).toBeUndefined();
      expect(retried.body.data.version).toBe(2);
    } finally {
      if (previousLock === undefined) {
        delete process.env.IDEMPOTENCY_LOCK_TIMEOUT_MS;
      } else {
        process.env.IDEMPOTENCY_LOCK_TIMEOUT_MS = previousLock;
      }
      if (previousHandler === undefined) {
        delete process.env.IDEMPOTENCY_HANDLER_TIMEOUT_MS;
      } else {
        process.env.IDEMPOTENCY_HANDLER_TIMEOUT_MS = previousHandler;
      }
      if (timeoutApp !== undefined) {
        await timeoutApp.close();
      }
    }
  }, 60_000);
});

// ═══════════════════════════════════════════════════════════════════════════
// AT-14/AT-15 — LIKE and sort abuse on every list
// ═══════════════════════════════════════════════════════════════════════════

describe('F1-07 attacks — LIKE escape and sort allowlist on every list', () => {
  it('matches %, _ and backslash literally on all five lists', async () => {
    const hall = await createHallOk();
    const group = await createGroupOk();
    const cases = [
      {
        label: 'destinations',
        path: DEST,
        create: (name: string) => createDestinationOk({ name }),
      },
      { label: 'halls', path: HALLS, create: (name: string) => createHallOk({ name }) },
      {
        label: 'terminals',
        path: terminalsPath(hall.id),
        create: (name: string) => createTerminalOk(hall.id, { name }),
      },
      { label: 'groups', path: GROUPS, create: (name: string) => createGroupOk({ name }) },
      {
        label: 'types',
        path: TYPES,
        create: (name: string) => createTypeOk(group.id, { name }),
      },
    ];

    for (const listCase of cases) {
      const word = `Like${tag()}`;
      const percent = await listCase.create(`100% ${word}`);
      const x = await listCase.create(`100x ${word}`);
      const underscore = await listCase.create(`a_b ${word}`);
      await listCase.create(`axb ${word}`);
      const backslash = await listCase.create(`a\\b ${word}`);

      for (const [q, expected] of [
        [`100% ${word}`, percent.id],
        [`100x ${word}`, x.id],
        [`a_b ${word}`, underscore.id],
        [`a\\b ${word}`, backslash.id],
      ] as const) {
        const res = await agent().get(listCase.path).query({ q }).set(auth(tokenA)).expect(200);
        expect(
          res.body.data.map((row: { id: string }) => row.id),
          `${listCase.label} q=${q}`,
        ).toEqual([expected]);
      }
    }
  });

  it('rejects every malformed sort value on every list', async () => {
    const hall = await createHallOk();
    const lists = [DEST, HALLS, terminalsPath(hall.id), GROUPS, TYPES];

    for (const path of lists) {
      for (const sort of [
        'tenantId',
        'name,name',
        '+name',
        'displayOrder,',
        '--name',
        '',
        'x'.repeat(201),
      ]) {
        const res = await agent().get(path).query({ sort }).set(auth(tokenA));
        expect(res.status, `${path} sort=${sort.slice(0, 20)}`).toBe(400);
      }
      await agent()
        .get(path)
        .query({ sort: '-createdAt', pageSize: 100 })
        .set(auth(tokenA))
        .expect(200);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// AT-16 — Unicode name collisions
// ═══════════════════════════════════════════════════════════════════════════

describe('F1-07 attacks — Unicode name collisions', () => {
  it('maps NFC, ZWNJ, digits, yeh/kaf and case variants to one live name on all five resources', async () => {
    const suffix = tag();
    const base = `کریمان ۱۲ Café ABC ${suffix}`;
    const variants = [
      base.replace('ی', 'ي'),
      base.replace('ک', 'ك'),
      base.replace('۱۲', '12'),
      base.replace('ABC', 'abc'),
      base.replace(' ', '‌'),
      base.replace('é', 'é'),
    ];
    for (const variant of variants) {
      expect(variant).not.toBe(base);
    }

    // Destinations
    const destination = await createDestinationOk({ name: base });
    for (const variant of variants) {
      expectNameConflict(await createDestination({ name: variant }), variant);
    }
    let list = await agent().get(DEST).query({ q: suffix }).set(auth(tokenA)).expect(200);
    expect(list.body.meta.total).toBe(1);
    await agent()
      .delete(destPath(destination.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(204);
    await createDestination({ name: variants[0] }).expect(201);

    // Halls
    const hall = await createHallOk({ name: base });
    for (const variant of variants) {
      expectNameConflict(await createHall({ name: variant }), variant);
    }
    list = await agent().get(HALLS).query({ q: suffix }).set(auth(tokenA)).expect(200);
    expect(list.body.meta.total).toBe(1);
    await agent()
      .delete(hallPath(hall.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(204);
    await createHall({ name: variants[0] }).expect(201);

    // Loader-type groups
    const group = await createGroupOk({ name: base });
    for (const variant of variants) {
      expectNameConflict(await createGroup({ name: variant }), variant);
    }
    list = await agent().get(GROUPS).query({ q: suffix }).set(auth(tokenA)).expect(200);
    expect(list.body.meta.total).toBe(1);
    await agent()
      .delete(groupPath(group.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(204);
    await createGroup({ name: variants[0] }).expect(201);

    // Loader types (unique per tenant, not per group)
    const typeGroup = await createGroupOk();
    const loaderType = await createTypeOk(typeGroup.id, { name: base });
    for (const variant of variants) {
      expectNameConflict(await createLoaderType({ groupId: typeGroup.id, name: variant }), variant);
    }
    list = await agent().get(TYPES).query({ q: suffix }).set(auth(tokenA)).expect(200);
    expect(list.body.meta.total).toBe(1);
    await agent()
      .delete(typePath(loaderType.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(204);
    await createLoaderType({ groupId: typeGroup.id, name: variants[0] }).expect(201);

    // Terminals (unique per hall)
    const terminalHall = await createHallOk();
    const terminal = await createTerminalOk(terminalHall.id, { name: base });
    for (const variant of variants) {
      expectNameConflict(await createTerminal(terminalHall.id, { name: variant }), variant);
    }
    list = await agent()
      .get(terminalsPath(terminalHall.id))
      .query({ q: suffix })
      .set(auth(tokenA))
      .expect(200);
    expect(list.body.meta.total).toBe(1);
    await agent()
      .delete(terminalPath(terminalHall.id, terminal.id))
      .set(auth(tokenA))
      .set('idempotency-key', idemKey())
      .query({ expectedVersion: '1' })
      .expect(204);
    await createTerminal(terminalHall.id, { name: variants[0] }).expect(201);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// AT-17/AT-18 — duplicate-name and source-delete races
// ═══════════════════════════════════════════════════════════════════════════

describe('F1-07 attacks — concurrency', () => {
  it('20 parallel group creates of one name produce exactly one 201', async () => {
    const name = `Parallel Group ${tag()}`;
    const responses = await Promise.all(Array.from({ length: 20 }, () => createGroup({ name })));
    const statuses = responses.map((res) => res.status);
    expect(statuses.filter((status) => status === 201)).toHaveLength(1);
    expect(statuses.filter((status) => status === 409)).toHaveLength(19);
    const winner = responses.find((res) => res.status === 201);
    const id = (winner?.body.data as { id: string }).id;
    expect((await auditRows(tenantA, id)).length).toBe(1);
    const count = await owner.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM loader_type_groups
        WHERE tenant_id = $1 AND name_key = $2 AND deleted_at IS NULL`,
      [tenantA, name.toLowerCase()],
    );
    expect(count.rows[0]?.n).toBe(1);
  }, 60_000);

  it('never leaves a live type in a deleted source group across 50 iterations', async () => {
    for (let i = 0; i < 50; i += 1) {
      const source = await createGroupOk({ name: `Move Source ${i} ${tag()}` });
      const target = await createGroupOk({ name: `Move Target ${i} ${tag()}` });
      const type = await createTypeOk(source.id);
      const deletePromise = agent()
        .delete(groupPath(source.id))
        .set(auth(tokenA))
        .set('idempotency-key', idemKey())
        .query({ expectedVersion: '1' })
        .then((res) => res);
      const movePromise = agent()
        .patch(typePath(type.id))
        .set(auth(tokenA))
        .set('idempotency-key', idemKey())
        .send({ groupId: target.id, expectedVersion: 1 })
        .then((res) => res);

      // Observe the source right after the delete resolves: a 204 means the
      // guard saw no live type, so the move must already have committed.
      const deleted = await deletePromise;
      const liveRightAfterDelete = await liveTypes(source.id);
      const moved = await movePromise;

      expect([204, 409]).toContain(deleted.status);
      expect(moved.status).toBe(200);
      if (deleted.status === 409) {
        expect(deleted.body.error.code).toBe('IN_USE');
      } else {
        expect(liveRightAfterDelete).toBe(0);
      }

      const read = await agent().get(typePath(type.id)).set(auth(tokenA)).expect(200);
      expect(read.body.data).toMatchObject({ groupId: target.id, version: 2 });
      expect(await liveTypes(source.id)).toBe(0);
    }

    const orphans = await owner.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM loader_types t
         JOIN loader_type_groups g ON g.id = t.group_id
        WHERE t.tenant_id = $1 AND t.deleted_at IS NULL AND g.deleted_at IS NOT NULL`,
      [tenantA],
    );
    expect(orphans.rows[0]?.n).toBe(0);
  }, 180_000);

  it('source DELETE answers 409 while a move is blocked on the type row', async () => {
    const source = await createGroupOk();
    const target = await createGroupOk();
    const type = await createTypeOk(source.id);
    const client = await owner.connect();
    let committed = false;
    try {
      await client.query('BEGIN');
      await client.query('SELECT id FROM loader_types WHERE id = $1 FOR UPDATE', [type.id]);

      // Dispatch the move first and wait until it is actually blocked on the
      // held type row. The source delete's guard is a plain read, so it must
      // see the still-live type and refuse. A no-op guard would soft-delete
      // the source and answer 204 here.
      const movePromise = agent()
        .patch(typePath(type.id))
        .set(auth(tokenA))
        .set('idempotency-key', idemKey())
        .send({ groupId: target.id, expectedVersion: 1 })
        .then((res) => res);
      await waitForLockWait('loader_types');
      const deleted = await agent()
        .delete(groupPath(source.id))
        .set(auth(tokenA))
        .set('idempotency-key', idemKey())
        .query({ expectedVersion: '1' });
      expect(deleted.status).toBe(409);
      expect(deleted.body.error.code).toBe('IN_USE');

      await client.query('COMMIT');
      committed = true;
      const moved = await movePromise;
      expect(moved.status).toBe(200);
      expect(moved.body.data).toMatchObject({ groupId: target.id, version: 2 });
    } finally {
      if (!committed) {
        await client.query('ROLLBACK').catch(() => undefined);
      }
      client.release();
    }
    expect(await liveTypes(source.id)).toBe(0);
  }, 60_000);

  it('source DELETE proceeds once the move commits while the delete waits on the group row', async () => {
    const source = await createGroupOk();
    const target = await createGroupOk();
    const type = await createTypeOk(source.id);
    const client = await owner.connect();
    let committed = false;
    try {
      await client.query('BEGIN');
      await client.query('SELECT id FROM loader_type_groups WHERE id = $1 FOR UPDATE', [source.id]);

      // Dispatch the delete first and wait until it is actually blocked on the
      // held source group row. The move does not need that row, so it commits
      // first; once released, the guard sees no live child.
      const deletePromise = agent()
        .delete(groupPath(source.id))
        .set(auth(tokenA))
        .set('idempotency-key', idemKey())
        .query({ expectedVersion: '1' })
        .then((res) => res);
      await waitForLockWait('loader_type_groups');
      const moved = await agent()
        .patch(typePath(type.id))
        .set(auth(tokenA))
        .set('idempotency-key', idemKey())
        .send({ groupId: target.id, expectedVersion: 1 })
        .expect(200);
      expect(moved.body.data).toMatchObject({ groupId: target.id, version: 2 });

      await client.query('COMMIT');
      committed = true;
      const deleted = await deletePromise;
      expect(deleted.status).toBe(204);
    } finally {
      if (!committed) {
        await client.query('ROLLBACK').catch(() => undefined);
      }
      client.release();
    }
    expect(await liveTypes(source.id)).toBe(0);
  }, 60_000);
});

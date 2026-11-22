import { randomBytes } from 'node:crypto';

import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { v7 as uuidv7 } from 'uuid';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb, type Tx } from '../src/db/tenant-db.js';
import { assignRole, createTenant, createUser, makeAppPool, ownerPool } from './setup/db.js';

/**
 * SR-05 database invariant (F1-05, migration 0010). Proves the runtime role
 * cannot write user_roles directly; only the two SECURITY DEFINER functions
 * can, and they enforce tenant/role/live-user/session rules in the caller's
 * transaction.
 */
describe('SR-05 user_roles write invariant (runtime role)', () => {
  const ctx = new TenantContext();
  let app: Pool;
  let tenantDb: TenantDb;
  let tenantA: string;
  let tenantB: string;
  let userA: string;
  let userB: string;
  let assignUser: string;
  let idempotentUser: string;
  let revokeUser: string;
  let rollbackUser: string;
  let softDeletedUser: string;

  beforeAll(async () => {
    const owner = ownerPool();
    tenantA = await createTenant(owner, `sr05-a-${uuidv7().slice(0, 8)}`);
    tenantB = await createTenant(owner, `sr05-b-${uuidv7().slice(0, 8)}`);
    // Phones stay inside the `.gitleaks.toml` synthetic range (0912000000x).
    userA = await createUser(owner, tenantA, { username: 'sr05.a', phone: '09120000001' });
    userB = await createUser(owner, tenantB, { username: 'sr05.b', phone: '09120000002' });
    assignUser = await createUser(owner, tenantA, { username: 'sr05.assign' });
    idempotentUser = await createUser(owner, tenantA, { username: 'sr05.idem' });
    revokeUser = await createUser(owner, tenantA, { username: 'sr05.revoke' });
    rollbackUser = await createUser(owner, tenantA, { username: 'sr05.rollback' });
    softDeletedUser = await createUser(owner, tenantA, { phone: '09120000003' });
    await owner.query('UPDATE users SET deleted_at = now() WHERE id = $1', [softDeletedUser]);
    // B owns a real DRIVER link: a cross-tenant revoke must leave it intact.
    await assignRole(owner, tenantB, userB, 'DRIVER', 'driver');
    // Dedicated fixtures keep each test independent of execution order.
    await assignRole(owner, tenantA, idempotentUser, 'DRIVER', 'driver');
    await assignRole(owner, tenantA, revokeUser, 'DRIVER', 'driver');
    app = makeAppPool();
    tenantDb = new TenantDb(drizzle(app, { schema }));
  });

  afterAll(async () => {
    await app.end();
  });

  function inTenant<T>(tenantId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    return ctx.run({ tenantId }, () => tenantDb.run(fn));
  }

  async function pgCode(promise: Promise<unknown>): Promise<string | undefined> {
    const error = await promise.then(
      () => {
        throw new Error('expected a rejection');
      },
      (reason: unknown) => reason,
    );
    let current: unknown = error;
    for (let i = 0; i < 5 && current !== null && current !== undefined; i += 1) {
      const code = (current as { code?: unknown }).code;
      if (typeof code === 'string') {
        return code;
      }
      current = (current as { cause?: unknown }).cause;
    }
    return undefined;
  }

  async function insertSession(tenantId: string, userId: string, revoked = false): Promise<string> {
    const id = uuidv7();
    await ownerPool().query(
      `INSERT INTO auth_sessions
         (id, tenant_id, user_id, family_id, refresh_hash, expires_at,
          revoked_at, revoke_reason)
       VALUES ($1, $2, $3, $1, $4, now() + interval '30 days', $5, $6)`,
      [
        id,
        tenantId,
        userId,
        randomBytes(32),
        revoked ? new Date() : null,
        revoked ? 'logout' : null,
      ],
    );
    return id;
  }

  async function sessionState(id: string): Promise<{
    revoked_at: Date | null;
    revoke_reason: string | null;
  }> {
    const res = await ownerPool().query<{
      revoked_at: Date | null;
      revoke_reason: string | null;
    }>('SELECT revoked_at, revoke_reason FROM auth_sessions WHERE id = $1', [id]);
    return res.rows[0] as { revoked_at: Date | null; revoke_reason: string | null };
  }

  async function roleRows(userId: string): Promise<{ role_code: string; role_scope: string }[]> {
    const res = await ownerPool().query<{ role_code: string; role_scope: string }>(
      'SELECT role_code, role_scope FROM user_roles WHERE user_id = $1 ORDER BY role_code',
      [userId],
    );
    return res.rows;
  }

  it('denies direct INSERT/UPDATE/DELETE/TRUNCATE to bitabar_app', async () => {
    const attempts = [
      () =>
        inTenant(tenantA, (tx) =>
          tx.execute(
            sql`insert into user_roles (tenant_id, user_id, role_code, role_scope)
                values (${tenantA}, ${userA}, 'DRIVER', 'driver')`,
          ),
        ),
      () =>
        inTenant(tenantA, (tx) =>
          tx.execute(sql`update user_roles set role_scope = 'carrier' where user_id = ${userA}`),
        ),
      () =>
        inTenant(tenantA, (tx) => tx.execute(sql`delete from user_roles where user_id = ${userA}`)),
      () => inTenant(tenantA, (tx) => tx.execute(sql`truncate user_roles`)),
    ];
    for (const attempt of attempts) {
      expect(await pgCode(attempt())).toBe('42501');
    }
  });

  it('assigns through the function, derives scope from roles, and revokes live sessions only', async () => {
    const liveOne = await insertSession(tenantA, assignUser);
    const liveTwo = await insertSession(tenantA, assignUser);
    const alreadyDead = await insertSession(tenantA, assignUser, true);

    const assigned = await inTenant(tenantA, async (tx) => {
      const result = await tx.execute(
        sql`select app.assign_user_role(${assignUser}, 'DRIVER') as assigned`,
      );
      return (result.rows[0] as { assigned: boolean }).assigned;
    });
    expect(assigned).toBe(true);
    expect(await roleRows(assignUser)).toEqual([{ role_code: 'DRIVER', role_scope: 'driver' }]);

    for (const id of [liveOne, liveTwo]) {
      expect(await sessionState(id)).toMatchObject({
        revoke_reason: 'role_change',
      });
      expect((await sessionState(id)).revoked_at).not.toBeNull();
    }
    // An already-revoked session keeps its original reason.
    expect(await sessionState(alreadyDead)).toMatchObject({
      revoke_reason: 'logout',
    });
  });

  it('is idempotent: re-assigning an existing role does not revoke sessions again', async () => {
    const newLive = await insertSession(tenantA, idempotentUser);
    const assigned = await inTenant(tenantA, async (tx) => {
      const result = await tx.execute(
        sql`select app.assign_user_role(${idempotentUser}, 'DRIVER') as assigned`,
      );
      return (result.rows[0] as { assigned: boolean }).assigned;
    });
    expect(assigned).toBe(false);
    expect((await sessionState(newLive)).revoked_at).toBeNull();
  });

  it('revokes only when a link is actually removed', async () => {
    const beforeFirst = await insertSession(tenantA, revokeUser);
    const removed = await inTenant(tenantA, async (tx) => {
      const result = await tx.execute(
        sql`select app.revoke_user_role(${revokeUser}, 'DRIVER') as removed`,
      );
      return (result.rows[0] as { removed: boolean }).removed;
    });
    expect(removed).toBe(true);
    expect((await sessionState(beforeFirst)).revoked_at).not.toBeNull();
    expect(await roleRows(revokeUser)).toEqual([]);

    const beforeSecond = await insertSession(tenantA, revokeUser);
    const removedAgain = await inTenant(tenantA, async (tx) => {
      const result = await tx.execute(
        sql`select app.revoke_user_role(${revokeUser}, 'DRIVER') as removed`,
      );
      return (result.rows[0] as { removed: boolean }).removed;
    });
    expect(removedAgain).toBe(false);
    expect((await sessionState(beforeSecond)).revoked_at).toBeNull();
  });

  it('rolls back the link and the session revocation together', async () => {
    const live = await insertSession(tenantA, rollbackUser);
    const error = await inTenant(tenantA, async (tx) => {
      await tx.execute(sql`select app.assign_user_role(${rollbackUser}, 'CARRIER_ADMIN')`);
      throw new Error('force rollback');
    }).then(
      () => null,
      (reason: unknown) => reason,
    );
    expect(error).toBeInstanceOf(Error);
    expect(await roleRows(rollbackUser)).toEqual([]);
    expect((await sessionState(live)).revoked_at).toBeNull();
  });

  it('rejects other-tenant, soft-deleted and non-catalog users/roles', async () => {
    expect(
      await pgCode(
        inTenant(tenantA, (tx) => tx.execute(sql`select app.assign_user_role(${userB}, 'DRIVER')`)),
      ),
    ).toBe('P0002');
    expect(
      await pgCode(
        inTenant(tenantA, (tx) =>
          tx.execute(sql`select app.assign_user_role(${softDeletedUser}, 'DRIVER')`),
        ),
      ),
    ).toBe('P0002');
    for (const bad of ['PLATFORM_ADMIN', 'AUDITOR', 'NINJA']) {
      expect(
        await pgCode(
          inTenant(tenantA, (tx) => tx.execute(sql`select app.assign_user_role(${userA}, ${bad})`)),
        ),
      ).toBe('22023');
      expect(
        await pgCode(
          inTenant(tenantA, (tx) => tx.execute(sql`select app.revoke_user_role(${userA}, ${bad})`)),
        ),
      ).toBe('22023');
    }

    expect(
      await inTenant(tenantA, async (tx) => {
        const result = await tx.execute(
          sql`select app.revoke_user_role(${userB}, 'DRIVER') as removed`,
        );
        return (result.rows[0] as { removed: boolean }).removed;
      }),
    ).toBe(false);
    // The cross-tenant revoke must not have touched B's real link.
    expect(await roleRows(userB)).toEqual([{ role_code: 'DRIVER', role_scope: 'driver' }]);
  });

  it('fails closed without a tenant context', async () => {
    expect(await pgCode(app.query('select app.assign_user_role($1, $2)', [userA, 'DRIVER']))).toBe(
      '42501',
    );
    expect(await pgCode(app.query('select app.revoke_user_role($1, $2)', [userA, 'DRIVER']))).toBe(
      '42501',
    );
  });
});

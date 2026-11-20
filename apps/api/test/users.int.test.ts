import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { v7 as uuidv7 } from 'uuid';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { DomainError } from '../src/common/errors/domain-error.js';
import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb } from '../src/db/tenant-db.js';
import { UsersRepository } from '../src/modules/users/users.repository.js';
import { createTenant, makeAppPool, ownerPool, testPii } from './setup/db.js';

/** Persian-digit rendering of an ASCII digit string, built from code points (no RTL literals in this file). */
const faDigits = (ascii: string) =>
  String.fromCodePoint(...[...ascii].map((c) => 0x6f0 + Number(c)));

/**
 * UsersRepository against a real PostgreSQL 17 (F1-03 T06). All repository
 * calls run as bitabar_app through TenantDb.run(); owner queries are used only
 * to assert what physically landed in the DB (no plaintext, NULL national IDs).
 */
describe('UsersRepository (integration, runtime role)', () => {
  let app: Pool;
  let repo: UsersRepository;
  let ctx: TenantContext;
  let tenantA: string;
  let tenantB: string;
  let userA: string;

  beforeAll(async () => {
    const owner = ownerPool();
    tenantA = await createTenant(owner, `repo-a-${uuidv7().slice(0, 8)}`);
    tenantB = await createTenant(owner, `repo-b-${uuidv7().slice(0, 8)}`);
    app = makeAppPool();
    const tenantDb = new TenantDb(drizzle(app, { schema }));
    ctx = new TenantContext();
    repo = new UsersRepository(tenantDb, ctx, testPii());
  });

  afterAll(async () => {
    await app.end();
  });

  function asTenant<T>(tenantId: string, fn: () => Promise<T>): Promise<T> {
    return ctx.run({ tenantId }, fn);
  }

  it('create + findById round trip; the DTO carries no PII columns', async () => {
    const created = await asTenant(tenantA, () =>
      repo.create({ username: 'repo.a', displayName: 'Repo A', phone: '09120000001' }),
    );
    userA = created.id;
    expect(created.tenantId).toBe(tenantA);
    expect(created.username).toBe('repo.a');
    expect(created.status).toBe('active');
    expect(Object.keys(created).sort()).toEqual(
      ['createdAt', 'displayName', 'id', 'status', 'tenantId', 'updatedAt', 'username'].sort(),
    );
    await expect(asTenant(tenantA, () => repo.findById(created.id))).resolves.toEqual(created);
    await expect(asTenant(tenantA, () => repo.findByUsername('repo.a'))).resolves.toEqual(created);
  });

  it('stores no plaintext: the raw row holds a GCM blob + 32-byte hash; national_id stays NULL', async () => {
    const res = await ownerPool().query<{
      phone_enc: Buffer;
      phone_hash: Buffer;
      national_id_enc: Buffer | null;
      national_id_hash: Buffer | null;
    }>('select phone_enc, phone_hash, national_id_enc, national_id_hash from users where id = $1', [
      userA,
    ]);
    const row = res.rows[0];
    expect(row).toBeDefined();
    expect(row?.phone_enc[0]).toBe(1); // PII format version
    expect(row?.phone_enc.includes(Buffer.from('09120000001'))).toBe(false);
    expect(row?.phone_hash).toHaveLength(32);
    expect(row?.national_id_enc).toBeNull();
    expect(row?.national_id_hash).toBeNull();
  });

  it('decrypts the phone back to the canonical form; masked by default; null without a phone', async () => {
    await expect(asTenant(tenantA, () => repo.decryptPhonePlaintext(userA))).resolves.toBe(
      '09120000001',
    );
    // PG uuid matching is case-insensitive; the AAD must come from the stored row id.
    await expect(
      asTenant(tenantA, () => repo.decryptPhonePlaintext(userA.toUpperCase())),
    ).resolves.toBe('09120000001');
    await expect(asTenant(tenantA, () => repo.getMaskedPhone(userA))).resolves.toBe('0912***0001');

    const noPhone = await asTenant(tenantA, () =>
      repo.create({ username: 'no.phone', displayName: 'No Phone' }),
    );
    await expect(asTenant(tenantA, () => repo.getMaskedPhone(noPhone.id))).resolves.toBeNull();
    await expect(
      asTenant(tenantA, () => repo.decryptPhonePlaintext(noPhone.id)),
    ).resolves.toBeNull();
  });

  it('findByPhone normalizes input (Persian digits) and uses the blind index only', async () => {
    const u = await asTenant(tenantA, () =>
      repo.create({ displayName: 'Digits', phone: '09120000002' }),
    );
    const found = await asTenant(tenantA, () => repo.findByPhone(faDigits('09120000002')));
    expect(found?.id).toBe(u.id);
    await expect(asTenant(tenantA, () => repo.findByPhone('09120000008'))).resolves.toBeNull();
    await expect(asTenant(tenantA, () => repo.findByPhone('123'))).rejects.toMatchObject({
      code: 'BAD_INPUT',
    });
  });

  it('duplicate phone in the same tenant surfaces as CONFLICT, never a raw PG error', async () => {
    const err = await asTenant(tenantA, () =>
      repo.create({ displayName: 'Dup', phone: '09120000001' }),
    ).then(
      () => {
        throw new Error('expected a conflict');
      },
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(DomainError);
    expect(err).toMatchObject({ code: 'CONFLICT', statusCode: 409 });
  });

  it('duplicate username in the same tenant surfaces as CONFLICT', async () => {
    await expect(
      asTenant(tenantA, () => repo.create({ username: 'repo.a', displayName: 'Dup' })),
    ).rejects.toMatchObject({ code: 'CONFLICT', statusCode: 409 });
  });

  it('the same phone may exist in another tenant; each tenant finds only its own row', async () => {
    const bUser = await asTenant(tenantB, () =>
      repo.create({ displayName: 'B user', phone: '09120000001' }),
    );
    expect(bUser.tenantId).toBe(tenantB);
    const inA = await asTenant(tenantA, () => repo.findByPhone('09120000001'));
    const inB = await asTenant(tenantB, () => repo.findByPhone('09120000001'));
    expect(inA?.id).toBe(userA);
    expect(inB?.id).toBe(bUser.id);
  });

  it('cross-tenant reads return nothing (IDOR blocked at the repository level too)', async () => {
    const onlyA = await asTenant(tenantA, () =>
      repo.create({ username: 'only.a', displayName: 'Only A', phone: '09120000004' }),
    );
    await expect(asTenant(tenantB, () => repo.findById(onlyA.id))).resolves.toBeNull();
    await expect(asTenant(tenantB, () => repo.findByPhone('09120000004'))).resolves.toBeNull();
    await expect(asTenant(tenantB, () => repo.findByUsername('only.a'))).resolves.toBeNull();
    await expect(asTenant(tenantB, () => repo.decryptPhonePlaintext(onlyA.id))).resolves.toBeNull();
  });

  it('softDelete hides the user from all finders; the phone is reusable afterwards', async () => {
    const u = await asTenant(tenantA, () =>
      repo.create({ displayName: 'Temp', phone: '09120000003' }),
    );
    await expect(asTenant(tenantA, () => repo.softDelete(u.id))).resolves.toBe(true);
    await expect(asTenant(tenantA, () => repo.softDelete(u.id))).resolves.toBe(false);
    await expect(asTenant(tenantA, () => repo.findById(u.id))).resolves.toBeNull();
    await expect(asTenant(tenantA, () => repo.findByPhone('09120000003'))).resolves.toBeNull();
    const again = await asTenant(tenantA, () =>
      repo.create({ displayName: 'Temp 2', phone: '09120000003' }),
    );
    expect(again.id).not.toBe(u.id);
  });

  it('assignRole/listRoles/revokeRole: catalog-only, idempotent, cross-tenant link rejected', async () => {
    const u = await asTenant(tenantA, () =>
      repo.create({ displayName: 'Roles', phone: '09120000005' }),
    );
    await asTenant(tenantA, () => repo.assignRole(u.id, 'DRIVER'));
    await asTenant(tenantA, () => repo.assignRole(u.id, 'DRIVER')); // idempotent
    await expect(asTenant(tenantA, () => repo.listRoles(u.id))).resolves.toEqual(['DRIVER']);

    // Unknown and removed roles are rejected before any SQL.
    for (const bad of ['PLATFORM_ADMIN', 'AUDITOR', 'CARRIER_OPERATOR', 'NINJA']) {
      await expect(asTenant(tenantA, () => repo.assignRole(u.id, bad))).rejects.toMatchObject({
        code: 'BAD_INPUT',
      });
    }
    // Linking A's user from tenant B's context: the user is invisible in B
    // (RLS), so the live-user check rejects → BAD_INPUT, not a raw PG error.
    // The composite FK stays as defense in depth (proven raw in rls.int.test.ts).
    await expect(asTenant(tenantB, () => repo.assignRole(u.id, 'DRIVER'))).rejects.toMatchObject({
      code: 'BAD_INPUT',
    });

    // Soft-deleted (hidden) users cannot gain roles (the FK has no deleted_at filter).
    const gone = await asTenant(tenantA, () =>
      repo.create({ displayName: 'Gone', phone: '09120000000' }),
    );
    await asTenant(tenantA, () => repo.softDelete(gone.id));
    await expect(asTenant(tenantA, () => repo.assignRole(gone.id, 'DRIVER'))).rejects.toMatchObject(
      {
        code: 'BAD_INPUT',
      },
    );

    await expect(asTenant(tenantA, () => repo.revokeRole(u.id, 'DRIVER'))).resolves.toBe(true);
    await expect(asTenant(tenantA, () => repo.revokeRole(u.id, 'DRIVER'))).resolves.toBe(false);
    await expect(asTenant(tenantA, () => repo.listRoles(u.id))).resolves.toEqual([]);
  });

  it('rejects mass assignment (status/tenantId in input) and writes nothing', async () => {
    const evil = {
      displayName: 'Evil',
      phone: '09120000006',
      status: 'disabled',
      tenantId: tenantB,
    };
    await expect(asTenant(tenantA, () => repo.create(evil))).rejects.toMatchObject({
      code: 'BAD_INPUT',
    });
    await expect(asTenant(tenantA, () => repo.findByPhone('09120000006'))).resolves.toBeNull();
  });

  it('every method fails closed without a tenant context', async () => {
    const id = uuidv7();
    const calls: (() => Promise<unknown>)[] = [
      () => repo.create({ displayName: 'x', phone: '09120000007' }),
      () => repo.findById(id),
      () => repo.findByUsername('user.a'),
      () => repo.findByPhone('09120000007'),
      () => repo.getMaskedPhone(id),
      () => repo.decryptPhonePlaintext(id),
      () => repo.assignRole(id, 'DRIVER'),
      () => repo.revokeRole(id, 'DRIVER'),
      () => repo.listRoles(id),
      () => repo.softDelete(id),
    ];
    for (const call of calls) {
      await expect(call()).rejects.toMatchObject({ code: 'TENANT_CONTEXT_MISSING' });
    }
  });

  it('national_id columns are still NULL after every repository operation (owner Q3)', async () => {
    const res = await ownerPool().query<{ n: number }>(
      'select count(*)::int as n from users where national_id_enc is not null or national_id_hash is not null',
    );
    expect(res.rows[0]?.n).toBe(0);
  });
});

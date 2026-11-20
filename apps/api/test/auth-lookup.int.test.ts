import { randomBytes } from 'node:crypto';

import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import {
  AUTH_LOOKUP_MAX_PAIRS,
  authLookupPhone,
  authLookupSession,
  authLookupUsername,
  listTenants,
} from '../src/db/auth-lookup.js';
import * as schema from '../src/db/schema/index.js';
import {
  appPool,
  assignRole,
  createTenant,
  createUser,
  makeAppPool,
  ownerPool,
  testPii,
} from './setup/db.js';

/**
 * Owner condition 4 / ADR-007 A17: the SECURITY DEFINER lookups are the only
 * pre-auth crossing of RLS. Every test runs as the runtime role bitabar_app
 * WITHOUT a tenant context; the owner pool is used only for fixtures and
 * catalog asserts. Scenario catalog: subagent draft, T04 checkpoint.
 */

/** Synthetic PHC — the column CHECK only requires the argon2id prefix. */
const PHC = '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA';

const db = () => drizzle(appPool(), { schema });

let owner: Pool;
let tenantA: string;
let tenantB: string;
let tenantCodeA: string;
let tenantCodeB: string;
let suspendedCode: string;
let suspendedTenant: string;
let deletedTenant: string;
let staffA: string;
let disabledA: string;
let twoRolesA: string;
let staffB: string;
let phoneHashA: Buffer;
let currentRefreshHash: Buffer;
let previousRefreshHash: Buffer;
let rotatedSessionId: string;
let revokedRefreshHash: Buffer;
let suspendedRefreshHash: Buffer;

describe('SECURITY DEFINER auth lookups (runtime role, no tenant context)', () => {
  beforeAll(async () => {
    owner = ownerPool();
    const suffix = uuidv7().slice(0, 8);
    tenantCodeA = `al-a-${suffix}`;
    tenantCodeB = `al-b-${suffix}`;
    tenantA = await createTenant(owner, tenantCodeA);
    tenantB = await createTenant(owner, tenantCodeB);
    suspendedCode = `al-susp-${suffix}`;
    suspendedTenant = await createTenant(owner, suspendedCode);
    deletedTenant = await createTenant(owner, `al-del-${suffix}`);
    await owner.query(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, [suspendedTenant]);
    await owner.query(`UPDATE tenants SET deleted_at = now() WHERE id = $1`, [deletedTenant]);

    staffA = await createUser(owner, tenantA, { username: 'staff.a', phone: '09120000001' });
    disabledA = await createUser(owner, tenantA, { username: 'disabled.a' });
    twoRolesA = await createUser(owner, tenantA, { username: 'multi.role' });
    staffB = await createUser(owner, tenantB, { username: 'staff.b' });
    await owner.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [disabledA]);

    await assignRole(owner, tenantA, staffA, 'FACTORY_OPERATOR', 'tenant');
    await assignRole(owner, tenantA, disabledA, 'DRIVER', 'driver');
    await assignRole(owner, tenantA, twoRolesA, 'DRIVER', 'driver');
    await assignRole(owner, tenantA, twoRolesA, 'CARRIER_ADMIN', 'carrier');
    await assignRole(owner, tenantB, staffB, 'CARRIER_ADMIN', 'carrier');

    for (const [tenantId, userId] of [
      [tenantA, staffA],
      [tenantA, disabledA],
      [tenantA, twoRolesA],
      [tenantB, staffB],
    ] as const) {
      await owner.query(
        'INSERT INTO user_credentials (id, tenant_id, user_id, password_hash) VALUES ($1, $2, $3, $4)',
        [uuidv7(), tenantId, userId, PHC],
      );
    }

    phoneHashA = testPii().blindIndex('phone', tenantA, '09120000001');

    // Session fixtures for the refresh-resolution lookup (A8).
    currentRefreshHash = randomBytes(32);
    previousRefreshHash = randomBytes(32);
    revokedRefreshHash = randomBytes(32);
    suspendedRefreshHash = randomBytes(32);
    rotatedSessionId = uuidv7();
    await owner.query(
      `INSERT INTO auth_sessions
         (id, tenant_id, user_id, family_id, refresh_hash, expires_at)
       VALUES ($1, $2, $3, $1, $4, now() + interval '30 days')`,
      [uuidv7(), tenantA, staffA, currentRefreshHash],
    );
    await owner.query(
      `INSERT INTO auth_sessions
         (id, tenant_id, user_id, family_id, refresh_hash, previous_refresh_hash, rotated_at, expires_at)
       VALUES ($1, $2, $3, $1, $4, $5, now(), now() + interval '30 days')`,
      [rotatedSessionId, tenantA, staffA, randomBytes(32), previousRefreshHash],
    );
    await owner.query(
      `INSERT INTO auth_sessions
         (id, tenant_id, user_id, family_id, refresh_hash, revoked_at, expires_at)
       VALUES ($1, $2, $3, $1, $4, now(), now() + interval '30 days')`,
      [uuidv7(), tenantA, staffA, revokedRefreshHash],
    );
    // A suspended tenant's session is still resolvable by the opaque cookie so
    // the refresh flow can revoke it (0008, review M1).
    const suspUser = await createUser(owner, suspendedTenant, { username: 'susp.user' });
    await owner.query(
      `INSERT INTO auth_sessions
         (id, tenant_id, user_id, family_id, refresh_hash, expires_at)
       VALUES ($1, $2, $3, $1, $4, now() + interval '30 days')`,
      [uuidv7(), suspendedTenant, suspUser, suspendedRefreshHash],
    );
  });

  // ---------- 1. Privileges and catalog hardening ----------

  it('PUBLIC has no EXECUTE on any lookup; bitabar_app does; no other grantees', async () => {
    const res = await owner.query<{ proname: string; proacl: string | null }>(
      `SELECT p.proname, p.proacl::text AS proacl
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'app'
         AND p.proname IN ('list_tenants','auth_lookup_username','auth_lookup_phone','auth_lookup_session')`,
    );
    expect(res.rows).toHaveLength(4);
    for (const row of res.rows) {
      const entries = (row.proacl ?? '').replace(/^\{|\}$/g, '').split(',');
      // The PUBLIC grantee renders as an empty name before '=' — it must be gone.
      expect(
        entries.some((e) => e.startsWith('=')),
        `PUBLIC grant on ${row.proname}`,
      ).toBe(false);
      expect(
        entries.some((e) => e.startsWith('bitabar_app=')),
        `bitabar_app grant on ${row.proname}`,
      ).toBe(true);
      // Exactly the owner and bitabar_app.
      expect(entries).toHaveLength(2);
    }
    const checks = await owner.query<{ fn: string; can: boolean }>(
      `SELECT 'bitabar_app' AS fn,
              has_function_privilege('bitabar_app','app.list_tenants()','EXECUTE') AS can
       UNION ALL SELECT 'username',
              has_function_privilege('bitabar_app','app.auth_lookup_username(text,text)','EXECUTE')
       UNION ALL SELECT 'phone',
              has_function_privilege('bitabar_app','app.auth_lookup_phone(jsonb)','EXECUTE')
       UNION ALL SELECT 'session',
              has_function_privilege('bitabar_app','app.auth_lookup_session(text)','EXECUTE')`,
    );
    expect(checks.rows.every((r) => r.can)).toBe(true);
  });

  it('functions are SECURITY DEFINER, owned by the migration owner, STABLE, search_path-pinned, static SQL', async () => {
    const res = await owner.query<{
      proname: string;
      prosecdef: boolean;
      owner: string;
      provolatile: string;
      proconfig: string[] | null;
      def: string;
    }>(
      `SELECT p.proname, p.prosecdef, pg_get_userbyid(p.proowner) AS owner, p.provolatile,
              p.proconfig, pg_get_functiondef(p.oid) AS def
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'app'
         AND p.proname IN ('list_tenants','auth_lookup_username','auth_lookup_phone','auth_lookup_session')`,
    );
    expect(res.rows).toHaveLength(4);
    const migrationOwner = (await owner.query<{ u: string }>('SELECT current_user AS u')).rows[0]
      ?.u;
    for (const f of res.rows) {
      expect(f.prosecdef, `${f.proname} is SECURITY DEFINER`).toBe(true);
      // Owned by the MIGRATION owner specifically (not merely "not the app").
      expect(f.owner, `${f.proname} owner`).toBe(migrationOwner);
      expect(f.provolatile, `${f.proname} volatility`).toBe('s');
      expect(f.proconfig ?? [], `${f.proname} search_path`).toContain(
        'search_path=pg_catalog, pg_temp',
      );
      // No dynamic SQL, and every table reference is schema-qualified.
      expect(/\bEXECUTE\b/i.test(f.def), `${f.proname} dynamic SQL`).toBe(false);
      expect(/format\(/i.test(f.def), `${f.proname} format()`).toBe(false);
      expect(/public\.[a-z_]+/.test(f.def)).toBe(true);
      expect(/(?<!\.)\b(tenants|users|user_credentials|user_roles)\b/.test(f.def)).toBe(false);
    }
  });

  it('the four lookups are the COMPLETE set of SECURITY DEFINER functions in schema app', async () => {
    // Any future definer function — the only way to cross RLS without a
    // context (A17) — must be added here deliberately, with the hardening
    // checklist and a review. A silent fifth fails this test.
    const res = await owner.query<{ proname: string }>(
      `SELECT p.proname
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'app' AND p.prosecdef = true
       ORDER BY p.proname`,
    );
    expect(res.rows.map((r) => r.proname)).toEqual([
      'auth_lookup_phone',
      'auth_lookup_session',
      'auth_lookup_username',
      'list_tenants',
    ]);
  });

  // ---------- 2. list_tenants ----------

  it('list_tenants returns exactly {id, code} for active tenants only', async () => {
    const rows = await listTenants(db());
    expect(Object.keys(rows[0] ?? {}).sort()).toEqual(['code', 'id']);
    const ids = rows.map((r) => r.id);
    expect(ids).toContain(tenantA);
    expect(ids).toContain(tenantB);
    expect(ids).not.toContain(suspendedTenant);
    expect(ids).not.toContain(deletedTenant);
  });

  // ---------- 3. Username lookup ----------

  it('username lookup returns exactly the 9 documented columns — no PII, no username/display_name', async () => {
    const rows = await authLookupUsername(db(), tenantCodeA, 'staff.a');
    expect(rows).toHaveLength(1);
    expect(Object.keys(rows[0] ?? {}).sort()).toEqual(
      [
        'failedAttempts',
        'mustChangePassword',
        'nextAttemptAt',
        'passwordHash',
        'roles',
        'status',
        'temporaryPasswordExpiresAt',
        'tenantId',
        'userId',
      ].sort(),
    );
    expect(rows[0]).toMatchObject({
      tenantId: tenantA,
      userId: staffA,
      passwordHash: PHC,
      status: 'active',
      mustChangePassword: true,
      failedAttempts: 0,
      nextAttemptAt: null,
      temporaryPasswordExpiresAt: null,
      roles: ['FACTORY_OPERATOR'],
    });
  });

  it('roles contain only that user’s role codes, sorted', async () => {
    const rows = await authLookupUsername(db(), tenantCodeA, 'multi.role');
    expect(rows[0]?.roles).toEqual(['CARRIER_ADMIN', 'DRIVER']);
  });

  it('disabled users ARE returned (the flow must answer the generic 401, not an oracle)', async () => {
    const rows = await authLookupUsername(db(), tenantCodeA, 'disabled.a');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe('disabled');
  });

  it('enumeration: unknown tenant, unknown user, wrong tenant and suspended tenant are identical empties', async () => {
    const results = await Promise.all([
      authLookupUsername(db(), 'no-such-tenant', 'staff.a'),
      authLookupUsername(db(), tenantCodeA, 'no.such.user'),
      authLookupUsername(db(), tenantCodeB, 'staff.a'),
      authLookupUsername(db(), suspendedCode, 'staff.a'),
    ]);
    for (const rows of results) {
      expect(rows).toEqual([]);
    }
    // Structural equality: same column metadata on every empty answer.
    const meta = await Promise.all(
      [
        ['no-such-tenant', 'x'],
        [tenantCodeA, 'no.such.user'],
        [tenantCodeB, 'staff.a'],
      ].map(([code, user]) =>
        appPool().query(`SELECT * FROM app.auth_lookup_username($1, $2)`, [code, user]),
      ),
    );
    const fields = meta.map((r) => r.fields.map((f) => f.name).join(','));
    expect(new Set(fields).size).toBe(1);
  });

  it('soft-deleted users disappear (positive control first, then 0 rows)', async () => {
    const id = await createUser(owner, tenantA, { username: 'soon.gone' });
    await owner.query(
      'INSERT INTO user_credentials (id, tenant_id, user_id, password_hash) VALUES ($1, $2, $3, $4)',
      [uuidv7(), tenantA, id, PHC],
    );
    await expect(authLookupUsername(db(), tenantCodeA, 'soon.gone')).resolves.toHaveLength(1);
    await owner.query('UPDATE users SET deleted_at = now() WHERE id = $1', [id]);
    await expect(authLookupUsername(db(), tenantCodeA, 'soon.gone')).resolves.toEqual([]);
  });

  it('wildcard / injection-looking / NULL / oversized inputs are plain misses, and the tables survive', async () => {
    for (const [code, user] of [
      ['%', '%'],
      ['_', '_'],
      [tenantCodeA, '%'],
      [`x' union select * from users --`, 'staff.a'],
      [`${tenantCodeA}' OR '1'='1`, `${tenantCodeA}' OR '1'='1`],
      ['', ''],
      ['x'.repeat(100_000), 'y'.repeat(100_000)],
    ] as const) {
      await expect(authLookupUsername(db(), code, user)).resolves.toEqual([]);
    }
    // NULL args are misses too — no error path that could leak internals.
    const nulls = await appPool().query(`SELECT * FROM app.auth_lookup_username(NULL, NULL)`);
    expect(nulls.rows).toHaveLength(0);
    // Negative control for "no dynamic SQL": the tables still exist.
    const count = await owner.query<{ n: number }>('SELECT count(*)::int AS n FROM users');
    expect(count.rows[0]?.n).toBeGreaterThan(0);
  });

  // ---------- 4. Phone fan-out ----------

  it('phone fan-out matches (tenant, blind-index) conjunctively and returns the same 9 columns', async () => {
    const rows = await authLookupPhone(db(), [{ tenantId: tenantA, phoneHash: phoneHashA }]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ tenantId: tenantA, userId: staffA, status: 'active' });
    expect(Object.keys(rows[0] ?? {})).toHaveLength(9);

    // Same hash under tenant B → no match (per-tenant blind index, A4/U8).
    await expect(
      authLookupPhone(db(), [{ tenantId: tenantB, phoneHash: phoneHashA }]),
    ).resolves.toEqual([]);
    // Unknown hash → empty.
    await expect(
      authLookupPhone(db(), [{ tenantId: tenantA, phoneHash: Buffer.alloc(32, 9) }]),
    ).resolves.toEqual([]);
  });

  it('duplicate pairs collapse to one row (no double counter advance, A5)', async () => {
    const pairs = Array.from({ length: 5 }, () => ({ tenantId: tenantA, phoneHash: phoneHashA }));
    const rows = await authLookupPhone(db(), pairs);
    expect(rows).toHaveLength(1);
  });

  it('jsonb shape abuse yields the same empty result — objects, scalars, bad types, missing keys', async () => {
    const shapes = [
      '{}',
      '"string"',
      '123',
      '[1,2,3]',
      '[["a"]]',
      '[null]',
      '[{"tenant_id":123,"phone_hash":"x"}]',
      '[{"tenant_id":"not-a-uuid","phone_hash":"zz"}]',
      '[{"tenant_id":"' + tenantA + '","phone_hash":null}]',
      '[{"phone_hash":"' + phoneHashA.toString('hex') + '"}]',
      'null',
    ];
    for (const shape of shapes) {
      const res = await appPool().query('SELECT * FROM app.auth_lookup_phone($1::jsonb)', [shape]);
      expect(res.rows, shape).toHaveLength(0);
    }
    // The helper short-circuits bad input before SQL as well.
    await expect(authLookupPhone(db(), [])).resolves.toEqual([]);
  });

  it(`over-cap fan-out (>${AUTH_LOOKUP_MAX_PAIRS} pairs) returns the same empty result`, async () => {
    const filler = Array.from({ length: AUTH_LOOKUP_MAX_PAIRS }, () => ({
      tenant_id: uuidv7(),
      phone_hash: phoneHashA.toString('hex'),
    }));
    const overCap = JSON.stringify([
      ...filler,
      { tenant_id: tenantA, phone_hash: phoneHashA.toString('hex') },
    ]);
    const res = await appPool().query('SELECT * FROM app.auth_lookup_phone($1::jsonb)', [overCap]);
    expect(res.rows).toHaveLength(0);
    // Exactly at the cap the matching pair is found — the boundary is live.
    const atCap = JSON.stringify([
      ...filler.slice(1),
      { tenant_id: tenantA, phone_hash: phoneHashA.toString('hex') },
    ]);
    const ok = await appPool().query('SELECT * FROM app.auth_lookup_phone($1::jsonb)', [atCap]);
    expect(ok.rows).toHaveLength(1);
  });

  // ---------- 5. The crossing is the only crossing ----------

  it('direct SELECT on the auth tables without context still returns 0 rows', async () => {
    const creds = await appPool().query('SELECT id FROM user_credentials');
    const sessions = await appPool().query('SELECT id FROM auth_sessions');
    expect(creds.rows).toHaveLength(0);
    expect(sessions.rows).toHaveLength(0);
    // …while the definer lookup returns rows in the same session.
    await expect(authLookupUsername(db(), tenantCodeA, 'staff.a')).resolves.toHaveLength(1);
  });

  it('results are independent of a caller-set tenant context (no narrowing or widening)', async () => {
    const client = await appPool().connect();
    try {
      await client.query('begin');
      await client.query("select set_config('app.tenant_id', $1, true)", [tenantB]);
      const rows = await client.query('SELECT id FROM app.list_tenants()');
      expect(rows.rows.map((r: { id: string }) => r.id)).toContain(tenantA);
    } finally {
      // Always roll back before releasing, even after a failed assertion — a
      // pooled connection left inside an aborted transaction poisons the next
      // borrower (observed in the first run of this suite).
      await client.query('rollback').catch(() => undefined);
      client.release();
    }
  });

  it('a temp-table shadow on the same connection cannot hijack the lookup', async () => {
    const client = await appPool().connect();
    try {
      await client.query('CREATE TEMP TABLE users (id uuid, tenant_id uuid, username text)');
      await client.query(
        'CREATE TEMP TABLE user_credentials (tenant_id uuid, user_id uuid, password_hash text, must_change_password boolean, failed_attempts int, next_attempt_at timestamptz, temporary_password_expires_at timestamptz)',
      );
      await client.query(`INSERT INTO pg_temp.users VALUES ($1, $2, 'staff.a')`, [
        uuidv7(),
        tenantA,
      ]);
      const res = await client.query('SELECT password_hash FROM app.auth_lookup_username($1, $2)', [
        tenantCodeA,
        'staff.a',
      ]);
      // The REAL row (synthetic PHC), not whatever the temp tables hold.
      expect(res.rows).toEqual([{ password_hash: PHC }]);
    } finally {
      // Temp tables would outlive release on this pooled connection and could
      // shadow `users` for other tests that query it unqualified.
      await client.query('DROP TABLE IF EXISTS pg_temp.user_credentials').catch(() => undefined);
      await client.query('DROP TABLE IF EXISTS pg_temp.users').catch(() => undefined);
      client.release();
    }
  });

  it('bitabar_app cannot replace the functions; lookups run in a READ ONLY transaction', async () => {
    await expect(
      appPool().query(
        `CREATE OR REPLACE FUNCTION app.list_tenants() RETURNS TABLE (id uuid, code varchar) LANGUAGE sql AS $$ SELECT NULL::uuid, NULL::varchar $$`,
      ),
    ).rejects.toMatchObject({ code: '42501' });

    const client = await appPool().connect();
    try {
      await client.query('begin read only');
      const res = await client.query('SELECT id FROM app.list_tenants()');
      expect(res.rows.length).toBeGreaterThan(0);
      await client.query('rollback');
    } finally {
      client.release();
    }
  });

  it('parallel fan-out on a small pool stays per-call isolated', async () => {
    const small = makeAppPool({ max: 5 });
    const smallDb = drizzle(small, { schema });
    try {
      const results = await Promise.all(
        Array.from({ length: 20 }, (_, i) =>
          i % 2 === 0
            ? authLookupPhone(smallDb, [{ tenantId: tenantA, phoneHash: phoneHashA }])
            : authLookupPhone(smallDb, [{ tenantId: tenantB, phoneHash: phoneHashA }]),
        ),
      );
      results.forEach((rows, i) => {
        if (i % 2 === 0) {
          expect(rows).toHaveLength(1);
          expect(rows[0]?.tenantId).toBe(tenantA);
        } else {
          expect(rows).toEqual([]);
        }
      });
    } finally {
      await small.end();
    }
  });

  // ---------- 6. Exact column sets, asserted on the RAW SQL result ----------
  // The typed helper rebuilds objects field-by-field and would silently drop a
  // leaked column — so the minimal-columns contract (A17) is asserted on raw
  // `SELECT *` metadata, not on helper output (review MEDIUM-2 fix).

  it('raw SQL result sets carry EXACTLY the documented columns and no PII', async () => {
    const lookupCols = [
      'failed_attempts',
      'must_change_password',
      'next_attempt_at',
      'password_hash',
      'roles',
      'status',
      'temporary_password_expires_at',
      'tenant_id',
      'user_id',
    ].sort();

    const byName = await appPool().query('SELECT * FROM app.auth_lookup_username($1, $2)', [
      tenantCodeA,
      'staff.a',
    ]);
    expect(byName.fields.map((f) => f.name).sort()).toEqual(lookupCols);

    const byPhone = await appPool().query('SELECT * FROM app.auth_lookup_phone($1::jsonb)', [
      JSON.stringify([{ tenant_id: tenantA, phone_hash: phoneHashA.toString('hex') }]),
    ]);
    expect(byPhone.fields.map((f) => f.name).sort()).toEqual(lookupCols);

    const tenants = await appPool().query('SELECT * FROM app.list_tenants()');
    expect(tenants.fields.map((f) => f.name).sort()).toEqual(['code', 'id']);

    const session = await appPool().query('SELECT * FROM app.auth_lookup_session($1)', [
      currentRefreshHash.toString('hex'),
    ]);
    expect(session.fields.map((f) => f.name).sort()).toEqual(
      [
        'expires_at',
        'family_id',
        'reuse_detected',
        'revoked_at',
        'rotated_at',
        'session_id',
        'tenant_id',
        'user_id',
      ].sort(),
    );

    // Belt and braces: PII columns can never appear in any lookup result.
    for (const fields of [byName, byPhone].map((r) => r.fields.map((f) => f.name))) {
      for (const forbidden of [
        'phone_enc',
        'phone_hash',
        'national_id_enc',
        'national_id_hash',
        'display_name',
        'username',
        'name',
        'created_by',
      ]) {
        expect(fields).not.toContain(forbidden);
      }
    }
  });

  // ---------- 7. Refresh-session resolution (4th lookup, owner-flagged) ----------

  it('session lookup: current hash resolves with reuse=false; previous hash flags REUSE (A8)', async () => {
    const current = await authLookupSession(db(), currentRefreshHash);
    expect(current).toMatchObject({
      tenantId: tenantA,
      userId: staffA,
      reuseDetected: false,
      revokedAt: null,
      rotatedAt: null,
    });
    expect(current?.sessionId).toBeTruthy();

    const reused = await authLookupSession(db(), previousRefreshHash);
    expect(reused).toMatchObject({ sessionId: rotatedSessionId, reuseDetected: true });
  });

  it('session lookup: unknown / malformed / injection-looking hashes are all the same empty answer', async () => {
    for (const bad of [
      randomBytes(32).toString('hex'), // unknown but well-formed
      '',
      'not-hex',
      'zz'.repeat(32),
      currentRefreshHash.toString('hex').slice(0, 63), // one char short
      `' OR '1'='1`,
    ]) {
      const res = await appPool().query('SELECT * FROM app.auth_lookup_session($1)', [bad]);
      expect(res.rows).toHaveLength(0);
    }
    // The typed helper rejects a degenerate (empty) hash the same way.
    await expect(authLookupSession(db(), Buffer.alloc(0))).resolves.toBeNull();
  });

  it('session lookup resolves suspended-tenant sessions so A18 can revoke them', async () => {
    // 0008: the tenant status is enforced in SessionService.rotate(), not here;
    // returning the row is what lets the flow revoke it (review M1).
    const suspended = await authLookupSession(db(), suspendedRefreshHash);
    expect(suspended?.tenantId).toBe(suspendedTenant);
    const revoked = await authLookupSession(db(), revokedRefreshHash);
    expect(revoked?.revokedAt).toBeInstanceOf(Date);
  });
});

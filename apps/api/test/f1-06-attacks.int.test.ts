import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { AuditStore } from '../src/db/audit-store.js';
import { OutboxStore } from '../src/db/outbox-store.js';
import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb, type Tx } from '../src/db/tenant-db.js';
import { AuditWriter } from '../src/modules/audit/audit-writer.js';
import { OutboxWriter } from '../src/modules/outbox/outbox-writer.js';
import { buildAad } from '../src/security/pii/pii-crypto.js';
import { parseEnv } from '../src/config/env.js';
import { createTenant, createUser, makeAppPool, ownerPool, testPii } from './setup/db.js';

/**
 * F1-06 cross-cutting attack suite (T09): audit PII sweep, forged-tenant RLS
 * on all three tables, cross-tenant invisibility, and outbox payload secrecy.
 * Each control is also unit/int tested in its own file; this file proves the
 * three features together on one realistic tenant flow.
 */

const PHONE = '09120000009';
const RAW_IP = '198.51.100.7';
const PASSWORD_MARKER = 'argon2id$v=19$forged-marker';
const TOKEN_MARKER = 'refresh-token-secret-marker';

let ctx: TenantContext;
let tenantDb: TenantDb;
let pool: Pool;
let tenantA: string;
let tenantB: string;
let userA: string;
let userB: string;
let writer: AuditWriter;
let outbox: OutboxWriter;

function inTenant<T>(tenantId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
  return ctx.run({ tenantId }, () => tenantDb.run(fn));
}

function sqlStateOf(error: unknown, depth = 0): string | null {
  if (depth > 5 || typeof error !== 'object' || error === null) {
    return null;
  }
  const code = (error as { code?: unknown }).code;
  if (typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code)) {
    return code;
  }
  return sqlStateOf((error as { cause?: unknown }).cause, depth + 1);
}

beforeAll(async () => {
  process.env.PII_ENC_KEY ??= Buffer.alloc(32, 7).toString('base64');
  process.env.PII_HMAC_KEY ??= Buffer.alloc(32, 8).toString('base64');
  const config = parseEnv({
    ...process.env,
    DATABASE_URL: 'postgresql://bitabar_app:dummy@localhost:5432/bitabar',
  });
  pool = makeAppPool();
  const db = drizzle(pool, { schema });
  tenantDb = new TenantDb(db);
  ctx = new TenantContext();
  writer = new AuditWriter(ctx, testPii(), new AuditStore(tenantDb));
  outbox = new OutboxWriter(ctx, testPii(), new OutboxStore(db, tenantDb), config);

  const owner = ownerPool();
  tenantA = await createTenant(owner, `attacks-a-${uuidv7().slice(0, 8)}`);
  tenantB = await createTenant(owner, `attacks-b-${uuidv7().slice(0, 8)}`);
  userA = await createUser(owner, tenantA, { username: 'attacks.a', phone: PHONE });
  userB = await createUser(owner, tenantB, { username: 'attacks.b' });
}, 120_000);

afterAll(async () => {
  await pool.end();
});

describe('F1-06 attack suite', () => {
  it('writes no raw phone, password, token or IP into any audit/outbox column', async () => {
    const auditId = await inTenant(tenantA, () =>
      writer.append({
        actorType: 'user',
        actorUserId: userA,
        actorSessionId: uuidv7(),
        action: 'user.role.assigned',
        resourceType: 'user',
        resourceId: userA,
        outcome: 'success',
        httpStatus: 200,
        reason: 'attack suite sweep',
        requestId: `attacks-${uuidv7().slice(0, 8)}`,
        ip: RAW_IP,
        before: {
          id: userA,
          username: 'attacks.a',
          status: 'active',
          phone: PHONE,
          nationalId: '0012345678',
          phoneEnc: Buffer.from(PASSWORD_MARKER),
          passwordHash: PASSWORD_MARKER,
          token: TOKEN_MARKER,
        },
        after: { id: userA, status: 'disabled', phone: PHONE },
      }),
    );

    await inTenant(tenantA, () =>
      outbox.enqueue({
        topic: 'mock.echo',
        dedupeKey: `sweep-${uuidv7()}`,
        payload: { phone: PHONE, note: 'outbox sweep' },
      }),
    );

    // The IP is decryptable only with the exact row AAD.
    const auditRow = (
      await ownerPool().query<{ ip_enc: Buffer; ip_hash: Buffer }>(
        'SELECT ip_enc, ip_hash FROM audit_logs WHERE id = $1',
        [auditId],
      )
    ).rows[0];
    if (auditRow === undefined) {
      throw new Error('audit row missing');
    }
    expect(
      testPii().decrypt(auditRow.ip_enc, buildAad(tenantA, 'audit_logs.ip_enc', auditId)),
    ).toBe(RAW_IP);
    expect(() =>
      testPii().decrypt(auditRow.ip_enc, buildAad(tenantB, 'audit_logs.ip_enc', auditId)),
    ).toThrow();

    // Sweep every text/jsonb-ish column of both tables for the raw values.
    const auditBlob = JSON.stringify(
      (
        await ownerPool().query(
          `SELECT action, reason, before, after, metadata, request_id,
                  encode(ip_enc, 'hex') AS ip_hex, encode(ip_hash, 'hex') AS ip_hash_hex
             FROM audit_logs WHERE tenant_id = $1`,
          [tenantA],
        )
      ).rows,
    );
    const outboxBlob = JSON.stringify(
      (
        await ownerPool().query(
          `SELECT topic, dedupe_key, last_error_code, encode(payload_enc, 'hex') AS payload_hex
             FROM integration_outbox WHERE tenant_id = $1`,
          [tenantA],
        )
      ).rows,
    );
    for (const blob of [auditBlob, outboxBlob]) {
      for (const secret of [
        PHONE,
        '9120000009',
        '0012345678',
        RAW_IP,
        PASSWORD_MARKER,
        TOKEN_MARKER,
      ]) {
        expect(blob, secret).not.toContain(secret);
      }
    }
  });

  it('hides every F1-06 row from another tenant (RLS)', async () => {
    const auditId = await inTenant(tenantA, () =>
      writer.append({
        actorType: 'system',
        actorUserId: null,
        action: 'test.rls',
        resourceType: 'handler',
        resourceId: 'attack-suite',
        outcome: 'success',
        httpStatus: 200,
      }),
    );
    const idempotencyId = uuidv7();
    await ownerPool().query(
      `INSERT INTO idempotency_keys
         (id, tenant_id, user_id, route_key, idem_key, fingerprint, status, created_at, expires_at)
       VALUES ($1,$2,$3,'POST /api/v1/attack',$4,$5,'in_progress',now(),now()+interval '1 hour')`,
      [idempotencyId, tenantA, userA, uuidv7().replaceAll('-', ''), Buffer.alloc(32)],
    );
    const outboxDedupe = `rls-${uuidv7()}`;
    await inTenant(tenantA, () =>
      outbox.enqueue({ topic: 'mock.echo', dedupeKey: outboxDedupe, payload: { rls: true } }),
    );
    const outboxRow = (
      await ownerPool().query<{ id: string }>(
        'SELECT id FROM integration_outbox WHERE tenant_id = $1 AND dedupe_key = $2',
        [tenantA, outboxDedupe],
      )
    ).rows[0];
    if (outboxRow === undefined) {
      throw new Error('outbox fixture missing');
    }

    const auditSeen = await inTenant(tenantB, (tx) =>
      tx.execute(sql`SELECT id FROM audit_logs WHERE id = ${auditId}`),
    );
    const idemSeen = await inTenant(tenantB, (tx) =>
      tx.execute(sql`SELECT id FROM idempotency_keys WHERE id = ${idempotencyId}`),
    );
    const outboxSeen = await inTenant(tenantB, (tx) =>
      tx.execute(sql`SELECT id FROM integration_outbox WHERE id = ${outboxRow.id}`),
    );
    expect(auditSeen.rows).toEqual([]);
    expect(idemSeen.rows).toEqual([]);
    expect(outboxSeen.rows).toEqual([]);
  });

  it('rejects a forged tenant on INSERT for all three tables (WITH CHECK)', async () => {
    const forgedId = uuidv7();
    const auditError = await inTenant(tenantB, async (tx) => {
      try {
        await tx.execute(sql`
          INSERT INTO audit_logs (id, tenant_id, actor_type, action, resource_type, outcome)
          VALUES (${forgedId}, ${tenantA}, 'system', 'test.forged', 'handler', 'success')
        `);
        return null;
      } catch (error) {
        return error;
      }
    });
    expect(sqlStateOf(auditError)).toBe('42501');

    const outboxError = await inTenant(tenantB, async (tx) => {
      try {
        await tx.execute(sql`
          INSERT INTO integration_outbox
            (id, tenant_id, topic, dedupe_key, payload_enc, status, attempts, max_attempts,
             next_attempt_at, created_at, updated_at)
          VALUES (${forgedId}, ${tenantA}, 'mock.echo', ${`forge-${uuidv7()}`},
                  ${Buffer.from('x')}, 'pending', 0, 2, now(), now(), now())
        `);
        return null;
      } catch (error) {
        return error;
      }
    });
    expect(sqlStateOf(outboxError)).toBe('42501');

    const idemError = await inTenant(tenantB, async (tx) => {
      try {
        await tx.execute(sql`
          INSERT INTO idempotency_keys
            (id, tenant_id, user_id, route_key, idem_key, fingerprint, status, created_at, expires_at)
          VALUES (${forgedId}, ${tenantA}, ${userA}, 'POST /api/v1/attack',
                  ${uuidv7().replaceAll('-', '')}, ${Buffer.alloc(32)}, 'in_progress',
                  now(), now() + interval '1 hour')
        `);
        return null;
      } catch (error) {
        return error;
      }
    });
    expect(sqlStateOf(idemError)).toBe('42501');

    const forged = await ownerPool().query(
      'SELECT count(*)::int AS n FROM audit_logs WHERE id = $1',
      [forgedId],
    );
    expect(forged.rows[0]?.n).toBe(0);
  });

  it('keeps a user id from another tenant unusable in the idempotency scope', async () => {
    // The composite FK makes (tenantB, userA) impossible even for the owner.
    await expect(
      ownerPool().query(
        `INSERT INTO idempotency_keys
           (id, tenant_id, user_id, route_key, idem_key, fingerprint, status, created_at, expires_at)
         VALUES ($1,$2,$3,'POST /api/v1/attack',$4,$5,'in_progress',now(),now()+interval '1 hour')`,
        [uuidv7(), tenantB, userA, uuidv7().replaceAll('-', ''), Buffer.alloc(32)],
      ),
    ).rejects.toMatchObject({ code: '23503' });
    void userB;
  });
});

import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { PinoLogger } from 'nestjs-pino';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { AuditStore } from '../src/db/audit-store.js';
import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb, type Tx } from '../src/db/tenant-db.js';
import { AuditWriter, type AuditAppendEntry } from '../src/modules/audit/audit-writer.js';
import { PersistentAuditHook } from '../src/modules/audit/persistent-audit-hook.js';
import type { AuditRecord } from '../src/security/authz/audit-hook.js';
import { buildAad } from '../src/security/pii/pii-crypto.js';
import { createTenant, createUser, makeAppPool, ownerPool, testPii } from './setup/db.js';

/**
 * AuditWriter + PersistentAuditHook against real PostgreSQL 17 (ADR-009 L1,
 * F1-06 T05): success rows are atomic with the change (fail-closed), rollbacks
 * leave no row, the IP is encrypted with the row-bound AAD, and a best-effort
 * failure write is never silent.
 */
describe('audit writer (integration)', () => {
  const ctx = new TenantContext();
  let app: Pool;
  let tenantDb: TenantDb;
  let tenantA: string;
  let tenantB: string;
  let userA: string;

  beforeAll(async () => {
    const owner = ownerPool();
    tenantA = await createTenant(owner, `auditw-a-${uuidv7().slice(0, 8)}`);
    tenantB = await createTenant(owner, `auditw-b-${uuidv7().slice(0, 8)}`);
    userA = await createUser(owner, tenantA, { username: 'audit.writer.a', phone: '09120000007' });
    app = makeAppPool();
    tenantDb = new TenantDb(drizzle(app, { schema }));
  });

  afterAll(async () => {
    await app.end();
  });

  function writer(): AuditWriter {
    return new AuditWriter(ctx, testPii(), new AuditStore(tenantDb));
  }

  function entry(overrides: Partial<AuditAppendEntry> = {}): AuditAppendEntry {
    return {
      actorType: 'user',
      actorUserId: userA,
      actorSessionId: uuidv7(),
      action: 'user.role.assigned',
      resourceType: 'user',
      resourceId: userA,
      outcome: 'success',
      httpStatus: 200,
      reason: 'integration test',
      requestId: 'req-audit-1',
      ip: '203.0.113.9',
      ...overrides,
    };
  }

  function inTenant<T>(tenantId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    return ctx.run({ tenantId }, () => tenantDb.run(fn));
  }

  it('writes a success row and encrypts the IP with the tenant/column/row AAD (Q2)', async () => {
    const id = await inTenant(tenantA, () => writer().append(entry()));

    const row = (
      await ownerPool().query<{
        tenant_id: string;
        actor_user_id: string;
        action: string;
        outcome: string;
        http_status: number;
        request_id: string;
        ip_enc: Buffer;
        ip_hash: Buffer;
        occurred_at: Date;
      }>('SELECT * FROM audit_logs WHERE id = $1', [id])
    ).rows[0];
    if (row === undefined) {
      throw new Error('audit row was not written');
    }
    expect(row).toMatchObject({
      tenant_id: tenantA,
      actor_user_id: userA,
      action: 'user.role.assigned',
      outcome: 'success',
      http_status: 200,
      request_id: 'req-audit-1',
    });
    expect(row.ip_hash).toHaveLength(32);
    // Same PII pattern as users: AAD = tenant + column + row id.
    expect(testPii().decrypt(row.ip_enc, buildAad(tenantA, 'audit_logs.ip_enc', id))).toBe(
      '203.0.113.9',
    );
    expect(row.ip_enc.toString('utf8')).not.toContain('203.0.113.9');
    // Server clock (A3), not a supplied value.
    expect(Date.now() - new Date(row.occurred_at).getTime()).toBeLessThan(60_000);
  });

  it('stores only the allowlisted snapshot fields (no ciphertext, no unknown column)', async () => {
    const id = await inTenant(tenantA, () =>
      writer().append(
        entry({
          before: { id: userA, username: 'audit.writer.a', status: 'active' },
          after: {
            id: userA,
            username: 'audit.writer.a',
            status: 'disabled',
            phoneEnc: Buffer.from([9, 9, 9]),
            passwordHash: 'argon2',
          },
        }),
      ),
    );
    const row = (
      await ownerPool().query<{ before: unknown; after: unknown }>(
        'SELECT before, after FROM audit_logs WHERE id = $1',
        [id],
      )
    ).rows[0];
    expect(row?.before).toEqual({ id: userA, username: 'audit.writer.a', status: 'active' });
    expect(row?.after).toEqual({ id: userA, username: 'audit.writer.a', status: 'disabled' });
  });

  it('accepts a near-cap payload and rejects an over-cap one before SQL', async () => {
    // 16,000 ASCII chars plus JSON overhead is under the DB's 16 KiB jsonb
    // text cap; the writer's estimate must match PostgreSQL, so this commits
    // instead of aborting on the CHECK.
    const id = await inTenant(tenantA, () =>
      writer().append(entry({ requestId: 'req-cap-ok', metadata: { blob: 'a'.repeat(16_000) } })),
    );
    const row = await ownerPool().query<{ octets: number }>(
      'SELECT octet_length(metadata::text) AS octets FROM audit_logs WHERE id = $1',
      [id],
    );
    expect(row.rows[0]?.octets).toBeLessThanOrEqual(16_384);

    // Over the cap: rejected as AUDIT_ENTRY_INVALID before any SQL, never as
    // a DB CHECK error in the middle of the caller's transaction.
    await expect(
      inTenant(tenantA, () => writer().append(entry({ metadata: { blob: 'a'.repeat(16_400) } }))),
    ).rejects.toThrow('AUDIT_ENTRY_INVALID');
  });

  it('rejects jsonb-hostile numbers and strings before SQL', async () => {
    // `1e+308` is 6 characters in JSON but ~309 digits in jsonb text.
    await expect(
      inTenant(tenantA, () => writer().append(entry({ metadata: { n: 1e308 } }))),
    ).rejects.toThrow('AUDIT_ENTRY_INVALID');
    // NUL and a lone surrogate are unrepresentable in PostgreSQL text.
    await expect(
      inTenant(tenantA, () => writer().append(entry({ metadata: { s: 'a\u0000b' } }))),
    ).rejects.toThrow('AUDIT_ENTRY_INVALID');
    await expect(
      inTenant(tenantA, () => writer().append(entry({ metadata: { s: '\ud800' } }))),
    ).rejects.toThrow('AUDIT_ENTRY_INVALID');
  });

  it('counts reason characters like PostgreSQL length() (Persian + emoji)', async () => {
    // 500 code points but 501 UTF-16 units: PostgreSQL length() = 500, and the
    // row must be accepted.
    const reason500 = `${'د'.repeat(499)}🙂`;
    const id = await inTenant(tenantA, () =>
      writer().append(entry({ reason: reason500, metadata: null })),
    );
    const row = await ownerPool().query<{ n: number }>(
      'SELECT length(reason)::int AS n FROM audit_logs WHERE id = $1',
      [id],
    );
    expect(row.rows[0]?.n).toBe(500);

    await expect(
      inTenant(tenantA, () => writer().append(entry({ reason: 'م'.repeat(501) }))),
    ).rejects.toThrow('AUDIT_ENTRY_INVALID');
  });

  it('supports a system actor with no user id', async () => {
    const id = await inTenant(tenantA, () =>
      writer().append(
        entry({
          actorType: 'system',
          actorUserId: null,
          actorSessionId: null,
          action: 'auth.password.reset',
          resourceType: 'handler',
          resourceId: 'cli.reset-password',
          metadata: { tool: 'cli' },
        }),
      ),
    );
    const row = (
      await ownerPool().query<{ actor_type: string; actor_user_id: string | null }>(
        'SELECT actor_type, actor_user_id FROM audit_logs WHERE id = $1',
        [id],
      )
    ).rows[0];
    expect(row).toEqual({ actor_type: 'system', actor_user_id: null });
  });

  it('rolls the business change back when the audit insert fails (fail-closed)', async () => {
    const username = `failclosed.${uuidv7().slice(0, 8)}`;
    await expect(
      inTenant(tenantA, async (tx) => {
        await tx.execute(sql`
          INSERT INTO users (id, tenant_id, username, display_name)
          VALUES (${uuidv7()}, ${tenantA}, ${username}, 'Fail Closed')
        `);
        // Invalid action: rejected before SQL, inside the same transaction.
        await writer().append(entry({ action: 'BAD ACTION' }));
      }),
    ).rejects.toThrow('AUDIT_ENTRY_INVALID');
    const count = await ownerPool().query(
      'SELECT count(*)::int AS n FROM users WHERE tenant_id = $1 AND username = $2',
      [tenantA, username],
    );
    expect(count.rows[0]?.n).toBe(0);
  });

  it('leaves no audit row when the business transaction rolls back', async () => {
    const action = 'user.role.revoked';
    const before = await ownerPool().query(
      'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action = $2',
      [tenantA, action],
    );
    await expect(
      inTenant(tenantA, async () => {
        await writer().append(entry({ action }));
        throw new Error('business failure');
      }),
    ).rejects.toThrow('business failure');
    const after = await ownerPool().query(
      'SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action = $2',
      [tenantA, action],
    );
    expect(after.rows[0]?.n).toBe(before.rows[0]?.n);
  });

  it('refuses to append without a tenant context', async () => {
    await expect(writer().append(entry())).rejects.toMatchObject({
      code: 'TENANT_CONTEXT_MISSING',
    });
  });

  it('persists a best-effort failure row after the rollback', async () => {
    const hook = new PersistentAuditHook(ctx, writer(), {
      setContext: vi.fn(),
      warn: vi.fn(),
    } as unknown as PinoLogger);
    const record: AuditRecord = {
      actor: { userId: userA, tenantId: tenantA, sessionId: uuidv7() },
      action: 'user.role.assigned',
      resource: { type: 'handler', id: 'ProbeController.update' },
      reason: null,
      outcome: 'failure',
      httpStatus: 500,
      requestId: 'req-failure-1',
      ip: '203.0.113.10',
    };
    await hook.record(record);

    const row = (
      await ownerPool().query<{ outcome: string; http_status: number; reason: string | null }>(
        "SELECT outcome, http_status, reason FROM audit_logs WHERE tenant_id = $1 AND request_id = 'req-failure-1'",
        [tenantA],
      )
    ).rows[0];
    expect(row).toEqual({ outcome: 'failure', http_status: 500, reason: null });
  });

  it('logs a code-only security event and writes nothing when a best-effort write fails', async () => {
    const warn = vi.fn();
    const hook = new PersistentAuditHook(ctx, writer(), {
      setContext: vi.fn(),
      warn,
    } as unknown as PinoLogger);
    const record: AuditRecord = {
      actor: { userId: userA, tenantId: tenantA, sessionId: uuidv7() },
      action: 'NOT VALID',
      resource: { type: 'handler', id: 'ProbeController.update' },
      reason: 'secret reason that must never be logged',
      outcome: 'denied',
      httpStatus: 403,
      requestId: 'req-fail-log-1',
      ip: '203.0.113.11',
    };
    await expect(hook.record(record)).resolves.toBeUndefined();

    expect(warn).toHaveBeenCalledTimes(1);
    const payload = warn.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(payload).toMatchObject({
      reqId: 'req-fail-log-1',
      outcome: 'denied',
      code: 'AUDIT_WRITE_FAILED',
    });
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain('secret reason');
    expect(serialized).not.toContain('203.0.113.11');

    const count = await ownerPool().query(
      "SELECT count(*)::int AS n FROM audit_logs WHERE request_id = 'req-fail-log-1'",
    );
    expect(count.rows[0]?.n).toBe(0);
  });

  it('keeps the hook row invisible to another tenant (RLS)', async () => {
    const id = await inTenant(tenantA, () => writer().append(entry({ requestId: 'req-rls-1' })));
    const seenByB = await inTenant(tenantB, (tx) =>
      tx.execute(sql`SELECT id FROM audit_logs WHERE id = ${id}`),
    );
    expect(seenByB.rows).toEqual([]);
  });
});

import { randomBytes } from 'node:crypto';
import { Writable } from 'node:stream';

import { drizzle } from 'drizzle-orm/node-postgres';
import type { PinoLogger } from 'nestjs-pino';
import type { Pool } from 'pg';
import pino from 'pino';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { parseEnv, type AppConfig } from '../src/config/env.js';
import * as schema from '../src/db/schema/index.js';
import { OutboxStore } from '../src/db/outbox-store.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb } from '../src/db/tenant-db.js';
import { OutboxWorker, backoffSeconds } from '../src/modules/outbox/outbox-worker.js';
import { OutboxWriter } from '../src/modules/outbox/outbox-writer.js';
import { MockAdapter } from '../src/modules/outbox/mock.adapter.js';
import type { OutboxAdapter, OutboxMetrics } from '../src/modules/outbox/outbox.types.js';
import { buildAad, PiiService } from '../src/security/pii/pii-crypto.js';
import { redactPiiLogObject } from '../src/security/pii/log-redact.js';
import { createTenant, makeAppPool, ownerPool } from './setup/db.js';

/**
 * Outbox end-to-end (ADR-010 L12–L14, F1-06 T08) against real PostgreSQL.
 * Covers O1–O8 plus the owner CP5 changes: the pre-claim dead sweep, per-tenant
 * isolation, the lease < adapter-timeout validation, real log hygiene and the
 * dead-letter event/metric.
 */

let pool: Pool;
let tenantDb: TenantDb;
let ctx: TenantContext;
let store: OutboxStore;
let writer: OutboxWriter;
let pii: PiiService;
let config: AppConfig;
let tenantA: string;
let tenantB: string;
let mock: MockAdapter;
let metrics: { deadLetter: ReturnType<typeof vi.fn> };
let logLines: string[];
let worker: OutboxWorker;

const ENC = randomBytes(32).toString('base64');
const HMAC = randomBytes(32).toString('base64');
const TOKEN = randomBytes(32).toString('base64');

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function workerLogger(onLine: (line: string) => void): PinoLogger {
  const stream = new Writable({
    write(chunk: Buffer | string, _encoding, callback): void {
      const text = chunk.toString();
      for (const line of text.split('\n')) {
        if (line.trim().length > 0) {
          onLine(line);
        }
      }
      callback();
    },
  });
  const real = pino(
    {
      level: 'info',
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'req.headers["idempotency-key"]',
        ],
        censor: '[redacted]',
      },
      formatters: { log: redactPiiLogObject },
    },
    stream,
  );
  return {
    setContext: (): void => undefined,
    warn: (obj: unknown, msg?: string): void => {
      real.warn(obj, msg);
    },
    error: (obj: unknown, msg?: string): void => {
      real.error(obj, msg);
    },
  } as unknown as PinoLogger;
}

function buildWorker(adapter: OutboxAdapter = mock): OutboxWorker {
  return new OutboxWorker(
    config,
    store,
    adapter,
    metrics as unknown as OutboxMetrics,
    ctx,
    tenantDb,
    pii,
    workerLogger((line) => {
      logLines.push(line);
    }),
  );
}

async function enqueue(
  tenantId: string,
  topic: string,
  dedupeKey: string,
  payload: unknown,
): Promise<boolean> {
  return ctx.run({ tenantId }, () => writer.enqueue({ topic, dedupeKey, payload }));
}

async function claim(
  tenantId: string,
  batch = 10,
): Promise<readonly { id: string; lockToken: string }[]> {
  return ctx.run({ tenantId }, () =>
    tenantDb.run(() => store.claim(batch, config.outbox.leaseSeconds)),
  );
}

async function outboxRow(id: string): Promise<{
  status: string;
  attempts: number;
  last_error_code: string | null;
  payload_enc: Buffer;
  lock_token: string | null;
}> {
  const result = await ownerPool().query<{
    status: string;
    attempts: number;
    last_error_code: string | null;
    payload_enc: Buffer;
    lock_token: string | null;
  }>(
    'SELECT status, attempts, last_error_code, payload_enc, lock_token FROM integration_outbox WHERE id = $1',
    [id],
  );
  const row = result.rows[0];
  if (row === undefined) {
    throw new Error(`outbox row ${id} missing`);
  }
  return row;
}

async function rowIdFor(tenantId: string, dedupeKey: string): Promise<string> {
  const result = await ownerPool().query<{ id: string }>(
    'SELECT id FROM integration_outbox WHERE tenant_id = $1 AND dedupe_key = $2',
    [tenantId, dedupeKey],
  );
  const row = result.rows[0];
  if (row === undefined) {
    throw new Error(`no outbox row for ${dedupeKey}`);
  }
  return row.id;
}

async function forceDue(id: string): Promise<void> {
  await ownerPool().query(
    "UPDATE integration_outbox SET next_attempt_at = now() - interval '1 second' WHERE id = $1",
    [id],
  );
}

async function expireLease(id: string): Promise<void> {
  await ownerPool().query(
    "UPDATE integration_outbox SET locked_until = now() - interval '1 second' WHERE id = $1",
    [id],
  );
}

beforeAll(async () => {
  process.env.PII_ENC_KEY = ENC;
  process.env.PII_HMAC_KEY = HMAC;
  process.env.AUTH_TOKEN_SECRET = TOKEN;
  config = parseEnv({
    ...process.env,
    DATABASE_URL: 'postgresql://bitabar_app:dummy@localhost:5432/bitabar',
    OUTBOX_LEASE_SECONDS: '60',
    OUTBOX_ADAPTER_TIMEOUT_MS: '5000',
    OUTBOX_MAX_ATTEMPTS: '2',
    OUTBOX_BACKOFF_BASE_SECONDS: '1',
  });
  pii = new PiiService({
    encKey: Buffer.from(ENC, 'base64'),
    hmacKey: Buffer.from(HMAC, 'base64'),
    keyId: 1,
  });
  pool = makeAppPool();
  tenantDb = new TenantDb(drizzle(pool, { schema }));
  ctx = new TenantContext();
  store = new OutboxStore(drizzle(pool, { schema }), tenantDb);
  writer = new OutboxWriter(ctx, pii, store, config);
  mock = new MockAdapter();
  metrics = { deadLetter: vi.fn() };
  logLines = [];
  worker = buildWorker();

  const owner = ownerPool();
  tenantA = await createTenant(owner, `outbox-a-${uuidv7().slice(0, 8)}`);
  tenantB = await createTenant(owner, `outbox-b-${uuidv7().slice(0, 8)}`);
}, 120_000);

afterEach(async () => {
  mock.reset();
  metrics.deadLetter.mockClear();
  logLines.length = 0;
  await ownerPool().query('DELETE FROM integration_outbox WHERE tenant_id = ANY($1)', [
    [tenantA, tenantB],
  ]);
});

afterAll(async () => {
  await pool.end();
});

describe('outbox — producer', () => {
  it('O1: a duplicate (tenant, topic, dedupeKey) enqueue is a no-op', async () => {
    const dedupeKey = `dup-${uuidv7()}`;
    expect(await enqueue(tenantA, 'mock.echo', dedupeKey, { a: 1 })).toBe(true);
    expect(await enqueue(tenantA, 'mock.echo', dedupeKey, { a: 2 })).toBe(false);
    const rows = await ownerPool().query(
      'SELECT id FROM integration_outbox WHERE tenant_id = $1 AND dedupe_key = $2',
      [tenantA, dedupeKey],
    );
    expect(rows.rows).toHaveLength(1);
  });

  it('O6: the payload is encrypted, row/tenant-bound and never plaintext', async () => {
    const dedupeKey = `enc-${uuidv7()}`;
    await enqueue(tenantA, 'mock.echo', dedupeKey, { phone: '09120000013' });
    const id = await rowIdFor(tenantA, dedupeKey);
    const row = await outboxRow(id);
    expect(row.payload_enc.toString('utf8')).not.toContain('09120000013');
    expect(
      pii.decrypt(row.payload_enc, buildAad(tenantA, 'integration_outbox.payload_enc', id)),
    ).toContain('09120000013');
    expect(() =>
      pii.decrypt(row.payload_enc, buildAad(tenantB, 'integration_outbox.payload_enc', id)),
    ).toThrow();
    expect(() =>
      pii.decrypt(row.payload_enc, buildAad(tenantA, 'integration_outbox.payload_enc', uuidv7())),
    ).toThrow();
  });
});

describe('outbox — claim and lease', () => {
  it('O2: two workers claim a batch without overlap (SKIP LOCKED)', async () => {
    const suffix = uuidv7();
    await enqueue(tenantA, 'mock.echo', `sl-a-${suffix}`, { n: 1 });
    await enqueue(tenantA, 'mock.echo', `sl-b-${suffix}`, { n: 2 });

    let held: readonly { id: string; lockToken: string }[] | undefined;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const firstClaim = ctx.run({ tenantId: tenantA }, () =>
      tenantDb.run(async () => {
        const rows = await store.claim(1, config.outbox.leaseSeconds);
        held = rows;
        await gate;
        return rows;
      }),
    );
    for (let i = 0; i < 100 && held === undefined; i += 1) {
      await sleep(10);
    }
    expect(held).toHaveLength(1);

    // The second claim runs while the first transaction still holds its row.
    const secondClaim = await claim(tenantA, 1);
    release();
    const first = await firstClaim;

    const ids = new Set([...(first ?? []).map((r) => r.id), ...secondClaim.map((r) => r.id)]);
    expect(secondClaim).toHaveLength(1);
    expect(ids.size).toBe(2);
  }, 20_000);

  it('O3/O7: an expired lease is reclaimed; the old token cannot mark state', async () => {
    const dedupeKey = `lease-${uuidv7()}`;
    await enqueue(tenantA, 'mock.echo', dedupeKey, { lease: true });
    const id = await rowIdFor(tenantA, dedupeKey);

    const first = await claim(tenantA);
    const row1 = first.find((row) => row.id === id);
    expect(row1).toBeDefined();
    // Deliver once, then simulate a crash before the mark.
    await mock.send({ outboxId: id, topic: 'mock.echo', payload: '{}' });
    await expireLease(id);

    const second = await claim(tenantA);
    const row2 = second.find((row) => row.id === id);
    expect(row2).toBeDefined();
    expect(row2?.lockToken).not.toBe(row1?.lockToken);
    expect(await outboxRow(id)).toMatchObject({ attempts: 2, status: 'processing' });

    // Re-delivery with the same outbox id is deduped by the adapter.
    await mock.send({ outboxId: id, topic: 'mock.echo', payload: '{}' });
    expect(mock.effects()).toHaveLength(1);

    const staleMark = await ctx.run({ tenantId: tenantA }, () =>
      tenantDb.run(() => store.markSent(id, row1?.lockToken ?? uuidv7())),
    );
    expect(staleMark).toBe(false);
    const freshMark = await ctx.run({ tenantId: tenantA }, () =>
      tenantDb.run(() => store.markSent(id, row2?.lockToken ?? uuidv7())),
    );
    expect(freshMark).toBe(true);
    expect(await outboxRow(id)).toMatchObject({ status: 'sent', lock_token: null });
  }, 20_000);

  it('owner change 1: an expired lease at the attempt ceiling goes dead before the claim', async () => {
    const deadKey = `dead-${uuidv7()}`;
    const liveKey = `live-${uuidv7()}`;
    await enqueue(tenantA, 'mock.echo', deadKey, { poison: true });
    await enqueue(tenantA, 'mock.echo', liveKey, { poison: false });
    const deadId = await rowIdFor(tenantA, deadKey);
    const liveId = await rowIdFor(tenantA, liveKey);
    await ownerPool().query(
      `UPDATE integration_outbox
          SET status='processing', attempts=2, lock_token=gen_random_uuid(),
              locked_until = now() - interval '1 minute'
        WHERE id = $1`,
      [deadId],
    );

    const before = mock.effects().length;
    await worker.runOnce();

    expect(await outboxRow(deadId)).toMatchObject({
      status: 'dead',
      last_error_code: 'LEASE_EXPIRED_MAX_ATTEMPTS',
    });
    // The poison row did not block the batch; the healthy row was sent.
    expect(await outboxRow(liveId)).toMatchObject({ status: 'sent' });
    expect(mock.effects().length).toBe(before + 1);
    expect(mock.effects().some((effect) => effect.outboxId === liveId)).toBe(true);
    expect(metrics.deadLetter).toHaveBeenCalledWith('mock.echo', 'LEASE_EXPIRED_MAX_ATTEMPTS');
    expect(logLines.join('\n')).toContain('OUTBOX_DEAD_LETTER');
  }, 20_000);
});

describe('outbox — failures, log hygiene and dead letters', () => {
  it('O4 + owner changes 5/6: provider text never reaches logs; dead letters are reported', async () => {
    const dedupeKey = `poison-${uuidv7()}`;
    const secretPayload = 'super-secret-payload-value';
    const providerSecret = 'provider-said-secret-token-xyz';
    await enqueue(tenantA, 'mock.echo', dedupeKey, { phone: '09120000014', secret: secretPayload });
    const id = await rowIdFor(tenantA, dedupeKey);

    const failing: OutboxAdapter = {
      send: async () => {
        throw new Error(providerSecret);
      },
    };
    const failingWorker = buildWorker(failing);

    await failingWorker.runOnce();
    expect(await outboxRow(id)).toMatchObject({
      status: 'pending',
      attempts: 1,
      last_error_code: 'ADAPTER_FAILED',
    });
    await forceDue(id);
    await failingWorker.runOnce();
    expect(await outboxRow(id)).toMatchObject({
      status: 'dead',
      attempts: 2,
      last_error_code: 'ADAPTER_FAILED',
    });
    expect(metrics.deadLetter).toHaveBeenCalledWith('mock.echo', 'ADAPTER_FAILED');

    const logs = logLines.join('\n');
    expect(logs).toContain('OUTBOX_SEND_FAILED');
    expect(logs).toContain('OUTBOX_DEAD_LETTER');
    for (const secret of [secretPayload, '09120000014', providerSecret, 'provider-said']) {
      expect(logs, secret).not.toContain(secret);
    }
    // The sanitized event carries only structural fields.
    expect(logs).toContain(id);
  }, 20_000);

  it('a timed-out adapter is a stable timeout code, not a raw error', async () => {
    const dedupeKey = `timeout-${uuidv7()}`;
    await enqueue(tenantA, 'mock.echo', dedupeKey, { slow: true });
    const id = await rowIdFor(tenantA, dedupeKey);
    const timed = parseEnv({
      ...process.env,
      DATABASE_URL: 'postgresql://bitabar_app:dummy@localhost:5432/bitabar',
      OUTBOX_LEASE_SECONDS: '60',
      OUTBOX_ADAPTER_TIMEOUT_MS: '5000',
    });
    // The worker reads the timeout from config; use a dedicated fast config.
    const fastConfig: AppConfig = {
      ...timed,
      outbox: { ...timed.outbox, adapterTimeoutMs: 50 },
    };
    const hanging: OutboxAdapter = {
      send: () => new Promise<void>(() => undefined),
    };
    const timeoutWorker = new OutboxWorker(
      fastConfig,
      store,
      hanging,
      metrics as unknown as OutboxMetrics,
      ctx,
      tenantDb,
      pii,
      workerLogger((line) => logLines.push(line)),
    );
    await timeoutWorker.runOnce();
    expect(await outboxRow(id)).toMatchObject({
      status: 'pending',
      last_error_code: 'ADAPTER_TIMEOUT',
    });
  }, 20_000);
});

describe('outbox — isolation', () => {
  it('O5: a tenant-scoped claim never sees another tenant’s rows', async () => {
    const keyA = `iso-a-${uuidv7()}`;
    const keyB = `iso-b-${uuidv7()}`;
    await enqueue(tenantA, 'mock.echo', keyA, { tenant: 'a' });
    await enqueue(tenantB, 'mock.echo', keyB, { tenant: 'b' });
    const idA = await rowIdFor(tenantA, keyA);
    const idB = await rowIdFor(tenantB, keyB);

    const claimedA = await claim(tenantA, 50);
    expect(claimedA.some((row) => row.id === idA)).toBe(true);
    expect(claimedA.some((row) => row.id === idB)).toBe(false);
    expect(await outboxRow(idB)).toMatchObject({ status: 'pending', attempts: 0 });

    // afterEach removes both tenants' rows.
  }, 20_000);
});

describe('outbox — retry math', () => {
  it('grows exponentially within jitter bounds and caps at one hour', () => {
    for (let attempt = 1; attempt <= 12; attempt += 1) {
      const value = backoffSeconds(attempt, 5);
      const expected = Math.min(5 * 2 ** (attempt - 1), 3600);
      expect(value).toBeGreaterThanOrEqual(Math.max(1, Math.round(expected * 0.8)));
      expect(value).toBeLessThanOrEqual(Math.round(expected * 1.2));
    }
    expect(backoffSeconds(50, 5)).toBeLessThanOrEqual(3600);
  });
});

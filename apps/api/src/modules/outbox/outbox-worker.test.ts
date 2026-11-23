import type { PinoLogger } from 'nestjs-pino';
import { describe, expect, it, vi } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import type { AppConfig } from '../../config/env.js';
import type { ClaimedOutboxRow, DeadOutboxRow, OutboxStore } from '../../db/outbox-store.js';
import type { TenantContext } from '../../db/tenant-context.js';
import type { TenantDb } from '../../db/tenant-db.js';
import { PiiService, buildAad } from '../../security/pii/pii-crypto.js';
import { DisabledAdapter } from './disabled.adapter.js';
import { MockAdapter } from './mock.adapter.js';
import { OutboxBootCheck } from './outbox-boot.check.js';
import { OutboxWorker } from './outbox-worker.js';
import { OutboxAdapterError, type OutboxAdapter, type OutboxMetrics } from './outbox.types.js';

/**
 * Worker loop behavior that is easier to prove without a database:
 * per-tenant isolation (owner CP5 change 2), the overlap guard, the disabled
 * flag and the production adapter refusal. The DB paths live in
 * test/outbox.int.test.ts.
 */

const keys = { encKey: Buffer.alloc(32, 1), hmacKey: Buffer.alloc(32, 2), keyId: 1 };
const pii = new PiiService(keys);

function config(outbox: Partial<AppConfig['outbox']> = {}): AppConfig {
  return {
    nodeEnv: 'test',
    outbox: {
      workerEnabled: false,
      mockEnabled: false,
      pollMs: 1000,
      batchSize: 10,
      leaseSeconds: 60,
      maxAttempts: 2,
      adapterTimeoutMs: 5000,
      backoffBaseSeconds: 1,
      ...outbox,
    },
  } as AppConfig;
}

function logger(): {
  logger: PinoLogger;
  warn: ReturnType<typeof vi.fn>;
  error: ReturnType<typeof vi.fn>;
} {
  const warn = vi.fn();
  const error = vi.fn();
  return {
    warn,
    error,
    logger: { setContext: (): void => undefined, warn, error } as unknown as PinoLogger,
  };
}

function encryptedRow(tenantId: string, payload: string): ClaimedOutboxRow {
  const id = uuidv7();
  return {
    id,
    topic: 'mock.echo',
    payloadEnc: pii.encrypt(payload, buildAad(tenantId, 'integration_outbox.payload_enc', id)),
    attempts: 2,
    maxAttempts: 2,
    lockToken: uuidv7(),
  };
}

function storeStub(overrides: Partial<OutboxStore>): OutboxStore {
  return {
    listActiveTenants: async () => [],
    sweepExpiredMaxAttempts: async (): Promise<readonly DeadOutboxRow[]> => [],
    claim: async (): Promise<readonly ClaimedOutboxRow[]> => [],
    markSent: async () => true,
    markFailure: async () => 'pending',
    enqueue: async () => true,
    ...overrides,
  } as unknown as OutboxStore;
}

const tenantContext = {
  run: async <T>(_scope: unknown, fn: () => Promise<T>): Promise<T> => fn(),
} as unknown as TenantContext;
const tenantDb = {
  run: async <T>(fn: () => Promise<T>): Promise<T> => fn(),
} as unknown as TenantDb;
const metrics = (): { deadLetter: ReturnType<typeof vi.fn> } => ({
  deadLetter: vi.fn(),
});

function worker(
  store: OutboxStore,
  adapter: OutboxAdapter,
  settings: AppConfig,
  log = logger(),
  m = metrics(),
): OutboxWorker {
  return new OutboxWorker(
    settings,
    store,
    adapter,
    m as unknown as OutboxMetrics,
    tenantContext,
    tenantDb,
    pii,
    log.logger,
  );
}

describe('outbox worker', () => {
  it('isolates a failing tenant: the others still run and the log is code-only', async () => {
    const tenantA = uuidv7();
    const tenantB = uuidv7();
    const claim = vi.fn(async () => []);
    const store = storeStub({
      listActiveTenants: async () => [
        { id: tenantA, code: 'a' },
        { id: tenantB, code: 'b' },
      ],
      claim,
      sweepExpiredMaxAttempts: async (): Promise<readonly DeadOutboxRow[]> => {
        // The second tenant's transaction fails before its claim.
        if (claim.mock.calls.length > 0) {
          throw new OutboxAdapterError('ADAPTER_UNAVAILABLE');
        }
        return [];
      },
    });
    const log = logger();
    await worker(store, new MockAdapter(), config(), log).runOnce();

    // Both tenants were attempted; the failure was logged with a code only.
    expect(log.error).toHaveBeenCalledTimes(1);
    const payload = log.error.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(payload).toMatchObject({ eventCode: 'OUTBOX_TENANT_FAILED', tenantId: tenantB });
    expect(JSON.stringify(payload)).not.toContain('payload');
  });

  it('skips a tick while one is still in flight', async () => {
    const tenantId = uuidv7();
    const row = encryptedRow(tenantId, '{"x":1}');
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const claim = vi.fn(async () => [row]);
    const store = storeStub({
      listActiveTenants: async () => [{ id: tenantId, code: 'a' }],
      claim,
      markSent: async () => true,
    });
    const slow: OutboxAdapter = {
      send: async () => {
        await gate;
      },
    };
    const w = worker(store, slow, config());
    const first = w.runOnce();
    const second = w.runOnce();
    await second; // returns immediately, before the first finishes
    release();
    await first;

    expect(claim).toHaveBeenCalledTimes(1);
  });

  it('reports a dead letter once with sanitized fields and no payload', async () => {
    const tenantId = uuidv7();
    const row = encryptedRow(tenantId, '{"phone":"09120000003"}');
    const store = storeStub({
      listActiveTenants: async () => [{ id: tenantId, code: 'a' }],
      claim: async () => [row],
      markFailure: async () => 'dead',
    });
    const log = logger();
    const m = metrics();
    const failing: OutboxAdapter = {
      send: async () => {
        throw new Error('provider-secret-text');
      },
    };
    await worker(store, failing, config(), log, m).runOnce();

    expect(m.deadLetter).toHaveBeenCalledTimes(1);
    expect(m.deadLetter).toHaveBeenCalledWith('mock.echo', 'ADAPTER_FAILED');
    const deadEvent = log.warn.mock.calls
      .map((call) => call[0] as Record<string, unknown>)
      .find((payload) => payload.eventCode === 'OUTBOX_DEAD_LETTER');
    expect(deadEvent).toMatchObject({
      outboxId: row.id,
      topic: 'mock.echo',
      errorCode: 'ADAPTER_FAILED',
    });
    expect(JSON.stringify(deadEvent)).not.toContain('09120000003');
    expect(JSON.stringify(log.warn.mock.calls)).not.toContain('provider-secret-text');
  });

  it('keeps the dead-letter log when the metrics hook throws', async () => {
    const tenantId = uuidv7();
    const row = encryptedRow(tenantId, '{"x":1}');
    const store = storeStub({
      listActiveTenants: async () => [{ id: tenantId, code: 'a' }],
      claim: async () => [row],
      markFailure: async () => 'dead',
    });
    const log = logger();
    const m = metrics();
    m.deadLetter.mockImplementation(() => {
      throw new Error('metrics down');
    });
    const failing: OutboxAdapter = {
      send: async () => {
        throw new OutboxAdapterError('ADAPTER_REJECTED');
      },
    };
    await expect(worker(store, failing, config(), log, m).runOnce()).resolves.toBeUndefined();
    const events = log.warn.mock.calls.map((call) => call[0] as Record<string, unknown>);
    expect(events.some((event) => event.eventCode === 'OUTBOX_DEAD_LETTER')).toBe(true);
    expect(events.some((event) => event.eventCode === 'OUTBOX_METRICS_FAILED')).toBe(true);
  });

  it('never trusts a forged adapter error code (runtime allowlist)', async () => {
    const tenantId = uuidv7();
    const row = encryptedRow(tenantId, '{"x":1}');
    const markFailure = vi.fn(async () => 'pending' as const);
    const store = storeStub({
      listActiveTenants: async () => [{ id: tenantId, code: 'a' }],
      claim: async () => [row],
      markFailure,
    });
    // Casting exercises a future adapter that smuggles text into `code`.
    const forged = new OutboxAdapterError('provider-secret-text' as never);
    const failing: OutboxAdapter = {
      send: async () => {
        throw forged;
      },
    };
    await worker(store, failing, config()).runOnce();
    expect(markFailure).toHaveBeenCalledWith(
      row.id,
      row.lockToken,
      'ADAPTER_FAILED',
      expect.any(Number),
    );
  });

  it('does not start a timer when the worker flag is off', () => {
    vi.useFakeTimers();
    try {
      const off = worker(storeStub({}), new MockAdapter(), config());
      off.onModuleInit();
      expect(vi.getTimerCount()).toBe(0);

      const on = worker(storeStub({}), new MockAdapter(), config({ workerEnabled: true }));
      on.onModuleInit();
      expect(vi.getTimerCount()).toBe(1);
      on.onModuleDestroy();
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('outbox production boot refusal', () => {
  it('refuses the mock adapter and the worker in production', () => {
    const production = config({ workerEnabled: false });
    production.nodeEnv = 'production';
    expect(() => new OutboxBootCheck(production, new MockAdapter()).onModuleInit()).toThrow(
      /OUTBOX_BOOT_MOCK_IN_PRODUCTION/,
    );
    const workerOn = config({ workerEnabled: true });
    workerOn.nodeEnv = 'production';
    expect(() => new OutboxBootCheck(workerOn, new DisabledAdapter()).onModuleInit()).toThrow(
      /OUTBOX_BOOT_WORKER_IN_PRODUCTION/,
    );
    expect(() =>
      new OutboxBootCheck(production, new DisabledAdapter()).onModuleInit(),
    ).not.toThrow();
    // Outside production the mock is allowed.
    expect(() => new OutboxBootCheck(config(), new MockAdapter()).onModuleInit()).not.toThrow();
  });
});

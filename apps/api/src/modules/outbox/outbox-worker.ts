import {
  Inject,
  Injectable,
  type OnApplicationShutdown,
  type OnModuleDestroy,
  type OnModuleInit,
} from '@nestjs/common';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits PinoLogger as the constructor param type for DI
import { PinoLogger } from 'nestjs-pino';

import { sanitizeErrorForLog } from '../../common/logging/sanitize-error.js';
import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';
import { OutboxStore, type ClaimedOutboxRow } from '../../db/outbox-store.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantContext as the constructor param type for DI
import { TenantContext } from '../../db/tenant-context.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantDb as the constructor param type for DI
import { TenantDb } from '../../db/tenant-db.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits PiiService as the constructor param type for DI
import { buildAad, PiiService } from '../../security/pii/pii-crypto.js';
import {
  OUTBOX_ADAPTER,
  OUTBOX_METRICS,
  OutboxAdapterError,
  type OutboxAdapter,
  type OutboxMetrics,
} from './outbox.types.js';

/**
 * Postgres outbox poller (ADR-010 L13/L14, F1-06 T08).
 *
 * One tick = for each active tenant, in its own transaction: sweep expired
 * leases that already hit the attempt ceiling to `dead`, then claim due rows
 * with `FOR UPDATE SKIP LOCKED`. The claim commits BEFORE any external call;
 * the adapter is called outside every transaction with a timeout and receives
 * `outbox.id` as its idempotency key. Success/failure is written back with a
 * `(id, lock_token)` CAS, so a worker whose lease expired can never overwrite
 * the new holder's state.
 *
 * Owner CP5 changes:
 *  1. the pre-claim sweep means `attempts` never increments past `max_attempts`
 *     and one poison row cannot break the tenant's batch;
 *  2. each tenant is wrapped in try/catch — a failing or suspended tenant
 *     never stops the others (the log carries a structural code only);
 *  6. every transition to `dead` emits a sanitized event and increments the
 *     metrics seam, so dead letters are never silent.
 *
 * Delivery is at-least-once with NO global ordering guarantee (ADR-010).
 */

const PAYLOAD_COLUMN = 'integration_outbox.payload_enc';

@Injectable()
export class OutboxWorker implements OnModuleInit, OnModuleDestroy, OnApplicationShutdown {
  private timer: ReturnType<typeof setInterval> | undefined;
  private inFlight = false;

  constructor(
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    @Inject(OutboxStore) private readonly store: OutboxStore,
    @Inject(OUTBOX_ADAPTER) private readonly adapter: OutboxAdapter,
    @Inject(OUTBOX_METRICS) private readonly metrics: OutboxMetrics,
    private readonly tenantContext: TenantContext,
    private readonly tenantDb: TenantDb,
    private readonly pii: PiiService,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(OutboxWorker.name);
  }

  onModuleInit(): void {
    if (!this.config.outbox.workerEnabled) {
      return;
    }
    this.timer = setInterval(() => {
      void this.runOnce();
    }, this.config.outbox.pollMs);
  }

  onModuleDestroy(): void {
    if (this.timer !== undefined) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /**
   * Shutdown ordering: the pool closes on application shutdown, so a tick in
   * flight must get a bounded chance to finish its CAS writes first (T08
   * review LOW 6).
   */
  async onApplicationShutdown(): Promise<void> {
    this.onModuleDestroy();
    const deadline = Date.now() + 10_000;
    while (this.inFlight && Date.now() < deadline) {
      await new Promise<void>((resolve) => {
        setTimeout(resolve, 25);
      });
    }
  }

  /** Public for tests; the interval calls it and an in-flight guard skips overlap. */
  async runOnce(): Promise<void> {
    if (this.inFlight) {
      return;
    }
    this.inFlight = true;
    try {
      const tenants = await this.store.listActiveTenants();
      for (const tenant of tenants) {
        try {
          await this.processTenant(tenant.id);
        } catch (error) {
          // Owner CP5 change 2: one bad tenant must not stop the others.
          this.logger.error(
            {
              eventCode: 'OUTBOX_TENANT_FAILED',
              tenantId: tenant.id,
              err: sanitizeErrorForLog(error),
            },
            'outbox tenant tick failed',
          );
        }
      }
    } catch (error) {
      // listActiveTenants itself failed (DB down): one sanitized event.
      this.logger.error(
        { eventCode: 'OUTBOX_TICK_FAILED', err: sanitizeErrorForLog(error) },
        'outbox tick failed',
      );
    } finally {
      this.inFlight = false;
    }
  }

  private async processTenant(tenantId: string): Promise<void> {
    const { dead, claimed } = await this.tenantContext.run({ tenantId }, () =>
      this.tenantDb.run(async () => {
        const sweptDead = await this.store.sweepExpiredMaxAttempts();
        const rows = await this.store.claim(
          this.config.outbox.batchSize,
          this.config.outbox.leaseSeconds,
        );
        return { dead: sweptDead, claimed: rows };
      }),
    );

    // Logged after the sweep committed: a rolled-back sweep never produces an
    // event. The dead row already carries the sanitized code.
    for (const row of dead) {
      this.reportDead(tenantId, row.topic, row.id, 'LEASE_EXPIRED_MAX_ATTEMPTS');
    }
    for (const row of claimed) {
      await this.deliver(tenantId, row);
    }
  }

  private async deliver(tenantId: string, row: ClaimedOutboxRow): Promise<void> {
    let payload: string;
    try {
      payload = this.pii.decrypt(row.payloadEnc, buildAad(tenantId, PAYLOAD_COLUMN, row.id));
    } catch {
      await this.fail(tenantId, row, 'PAYLOAD_DECRYPT_FAILED');
      return;
    }

    try {
      await withTimeout(
        this.adapter.send({ outboxId: row.id, topic: row.topic, payload }),
        this.config.outbox.adapterTimeoutMs,
      );
    } catch (error) {
      await this.fail(tenantId, row, adapterErrorCode(error));
      return;
    }

    try {
      const sent = await this.tenantContext.run({ tenantId }, () =>
        this.tenantDb.run(() => this.store.markSent(row.id, row.lockToken)),
      );
      if (!sent) {
        this.logger.warn(
          { eventCode: 'OUTBOX_LEASE_LOST', outboxId: row.id, topic: row.topic },
          'outbox lease was lost before mark-sent',
        );
      }
    } catch (error) {
      // One bad write must not starve the rest of the tenant's batch (T08
      // review LOW 5); the row stays processing and is recovered by lease.
      this.logger.error(
        {
          eventCode: 'OUTBOX_ROW_FAILED',
          outboxId: row.id,
          topic: row.topic,
          err: sanitizeErrorForLog(error),
        },
        'outbox mark-sent failed',
      );
    }
  }

  private async fail(tenantId: string, row: ClaimedOutboxRow, errorCode: string): Promise<void> {
    this.logger.warn(
      {
        eventCode: 'OUTBOX_SEND_FAILED',
        outboxId: row.id,
        topic: row.topic,
        attempts: row.attempts,
        errorCode,
      },
      'outbox send failed',
    );
    const delay = backoffSeconds(row.attempts, this.config.outbox.backoffBaseSeconds);
    let status: 'pending' | 'dead' | null;
    try {
      status = await this.tenantContext.run({ tenantId }, () =>
        this.tenantDb.run(() => this.store.markFailure(row.id, row.lockToken, errorCode, delay)),
      );
    } catch (error) {
      this.logger.error(
        {
          eventCode: 'OUTBOX_ROW_FAILED',
          outboxId: row.id,
          topic: row.topic,
          err: sanitizeErrorForLog(error),
        },
        'outbox mark-failed failed',
      );
      return;
    }
    if (status === 'dead') {
      this.reportDead(tenantId, row.topic, row.id, errorCode);
    } else if (status === null) {
      this.logger.warn(
        { eventCode: 'OUTBOX_LEASE_LOST', outboxId: row.id, topic: row.topic },
        'outbox lease was lost before mark-failed',
      );
    }
  }

  /**
   * Owner CP5 change 6: sanitized dead-letter event + metrics seam. This is
   * best-effort after the state commit (a crash in the gap loses the event),
   * and the log comes first so a throwing metrics hook cannot suppress it.
   */
  private reportDead(tenantId: string, topic: string, outboxId: string, errorCode: string): void {
    this.logger.warn(
      { eventCode: 'OUTBOX_DEAD_LETTER', outboxId, topic, errorCode, tenantId },
      'outbox message moved to dead',
    );
    try {
      this.metrics.deadLetter(topic, errorCode);
    } catch {
      this.logger.warn(
        { eventCode: 'OUTBOX_METRICS_FAILED', outboxId, topic },
        'outbox metrics hook failed',
      );
    }
  }
}

const ADAPTER_CODES = new Set<string>([
  'ADAPTER_TIMEOUT',
  'ADAPTER_REJECTED',
  'ADAPTER_UNAVAILABLE',
]);

/** Runtime allowlist: a future adapter cannot smuggle provider text via `code`. */
function adapterErrorCode(error: unknown): string {
  if (error instanceof OutboxAdapterError && ADAPTER_CODES.has(error.code)) {
    return error.code;
  }
  return 'ADAPTER_FAILED';
}

/** Exponential backoff with jitter; the final value never exceeds one hour. */
export function backoffSeconds(attempts: number, baseSeconds: number): number {
  const exponential = Math.min(baseSeconds * 2 ** Math.max(0, attempts - 1), 3600);
  const jitter = 0.8 + Math.random() * 0.4;
  return Math.max(1, Math.min(Math.round(exponential * jitter), 3600));
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new OutboxAdapterError('ADAPTER_TIMEOUT')), timeoutMs);
  });
  // A timed-out adapter may settle later; never let that become unhandled.
  promise.catch(() => undefined);
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

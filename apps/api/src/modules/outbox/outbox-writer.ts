import { Inject, Injectable } from '@nestjs/common';
import { v7 as uuidv7 } from 'uuid';

// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits PiiService as the constructor param type for DI
import { buildAad, PiiService } from '../../security/pii/pii-crypto.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits OutboxStore as the constructor param type for DI
import { OutboxStore } from '../../db/outbox-store.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantContext as the constructor param type for DI
import { TenantContext } from '../../db/tenant-context.js';
import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';

/**
 * Transactional outbox producer (ADR-010 L12, F1-06 T08).
 *
 * `enqueue()` runs inside the caller's `TenantDb.run` transaction (nested
 * reuse), so the business change and its outgoing message commit or roll back
 * together. The payload is encrypted with the PII service (AAD
 * `tenant:integration_outbox.payload_enc:<rowId>`): it may carry a phone
 * number, and the row outlives the request. A duplicate
 * `(tenant, topic, dedupeKey)` is a no-op.
 *
 * Never call a provider directly from a handler; enqueue here instead.
 */

const TOPIC_PATTERN = /^[a-z][a-z0-9_.]{2,63}$/;
const DEDUPE_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const MAX_PAYLOAD_BYTES = 65_536;

export interface EnqueueInput {
  readonly topic: string;
  readonly dedupeKey: string;
  readonly payload: unknown;
}

@Injectable()
export class OutboxWriter {
  constructor(
    private readonly tenantContext: TenantContext,
    private readonly pii: PiiService,
    private readonly store: OutboxStore,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  /** Returns true when a new row was inserted; false for a duplicate. */
  async enqueue(input: EnqueueInput): Promise<boolean> {
    const { tenantId } = this.tenantContext.require();
    if (!TOPIC_PATTERN.test(input.topic) || !DEDUPE_PATTERN.test(input.dedupeKey)) {
      throw new Error('OUTBOX_ENTRY_INVALID');
    }
    let payload: string;
    try {
      const json = JSON.stringify(input.payload);
      if (typeof json !== 'string') {
        throw new Error('not serializable');
      }
      payload = json;
    } catch {
      throw new Error('OUTBOX_ENTRY_INVALID');
    }
    if (Buffer.byteLength(payload, 'utf8') > MAX_PAYLOAD_BYTES) {
      throw new Error('OUTBOX_ENTRY_INVALID');
    }

    const id = uuidv7();
    const payloadEnc = this.pii.encrypt(
      payload,
      buildAad(tenantId, 'integration_outbox.payload_enc', id),
    );
    return this.store.enqueue({
      id,
      tenantId,
      topic: input.topic,
      dedupeKey: input.dedupeKey,
      payloadEnc,
      maxAttempts: this.config.outbox.maxAttempts,
    });
  }
}

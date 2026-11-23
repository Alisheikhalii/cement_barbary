import { Module } from '@nestjs/common';

import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';
import { OutboxStore } from '../../db/outbox-store.js';
import { PiiModule } from '../../security/pii/pii.module.js';
import { DisabledAdapter } from './disabled.adapter.js';
import { MockAdapter } from './mock.adapter.js';
import { OutboxBootCheck } from './outbox-boot.check.js';
import { OutboxWorker } from './outbox-worker.js';
import { OutboxWriter } from './outbox-writer.js';
import { OUTBOX_ADAPTER, OUTBOX_METRICS, type OutboxMetrics } from './outbox.types.js';

const noopMetrics: OutboxMetrics = { deadLetter: (): void => undefined };

/**
 * Transactional outbox module (ADR-010 L12–L14, F1-06 T08). Exposes the
 * producer; the poller starts only with `OUTBOX_WORKER_ENABLED` and the mock
 * provider only with `ADAPTER_MOCK_ENABLED` (both refused in production).
 */
@Module({
  imports: [PiiModule],
  providers: [
    OutboxStore,
    OutboxWriter,
    MockAdapter,
    DisabledAdapter,
    {
      provide: OUTBOX_ADAPTER,
      inject: [APP_CONFIG, MockAdapter, DisabledAdapter],
      useFactory: (config: AppConfig, mock: MockAdapter, disabled: DisabledAdapter) =>
        config.outbox.mockEnabled ? mock : disabled,
    },
    { provide: OUTBOX_METRICS, useValue: noopMetrics },
    OutboxWorker,
    OutboxBootCheck,
  ],
  exports: [OutboxWriter, OutboxStore],
})
export class OutboxModule {}

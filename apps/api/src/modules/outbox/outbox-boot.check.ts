import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';

import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';
import { MockAdapter } from './mock.adapter.js';
import { OUTBOX_ADAPTER, type OutboxAdapter } from './outbox.types.js';

/**
 * Production boot assertion for the outbox adapters (owner CP5).
 *
 * The env schema already refuses `ADAPTER_MOCK_ENABLED`/`OUTBOX_WORKER_ENABLED`
 * in production; this is defense in depth against a provider graph that binds
 * the mock through some other path (the same pattern as the audit-hook check).
 */
@Injectable()
export class OutboxBootCheck implements OnModuleInit {
  constructor(
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    @Inject(OUTBOX_ADAPTER) private readonly adapter: OutboxAdapter,
  ) {}

  onModuleInit(): void {
    if (this.config.nodeEnv !== 'production') {
      return;
    }
    if (this.adapter instanceof MockAdapter) {
      throw new Error('OUTBOX_BOOT_MOCK_IN_PRODUCTION');
    }
    if (this.config.outbox.workerEnabled) {
      throw new Error('OUTBOX_BOOT_WORKER_IN_PRODUCTION');
    }
  }
}

import { Module } from '@nestjs/common';

import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';
import { PiiService } from './pii-crypto.js';

/** Wires the PII service to the validated env keys (ADR-006 U10). */
@Module({
  providers: [
    {
      provide: PiiService,
      useFactory: (config: AppConfig) => new PiiService(config.pii),
      inject: [APP_CONFIG],
    },
  ],
  exports: [PiiService],
})
export class PiiModule {}

import { Module } from '@nestjs/common';

import { DestinationsModule } from './destinations/destinations.module.js';
import { HallsModule } from './halls/halls.module.js';

/**
 * Base-data aggregate (F1-07, ADR-011 B11). T06 adds the loader-type module
 * here; each is self-contained and reviewed on its own.
 */
@Module({
  imports: [DestinationsModule, HallsModule],
})
export class BaseDataModule {}

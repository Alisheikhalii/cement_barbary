import { Module } from '@nestjs/common';

import { DestinationsModule } from './destinations/destinations.module.js';

/**
 * Base-data aggregate (F1-07, ADR-011 B11). T05 adds HallsModule and T06 adds
 * the loader-type module here; each is self-contained and reviewed on its own.
 */
@Module({
  imports: [DestinationsModule],
})
export class BaseDataModule {}

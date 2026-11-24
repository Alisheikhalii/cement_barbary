import { Module } from '@nestjs/common';

import { DestinationsModule } from './destinations/destinations.module.js';
import { HallsModule } from './halls/halls.module.js';
import { LoaderTypesModule } from './loader-types/loader-types.module.js';

/**
 * Base-data aggregate (F1-07, ADR-011 B11). Each resource is self-contained
 * and reviewed on its own; the import order fixes the route discovery order
 * the permission-matrix script renders.
 */
@Module({
  imports: [DestinationsModule, HallsModule, LoaderTypesModule],
})
export class BaseDataModule {}

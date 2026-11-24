import { Module } from '@nestjs/common';

import { AuditModule } from '../../audit/audit.module.js';
import { DestinationsController } from './destinations.controller.js';
import { DestinationsRepository } from './destinations.repository.js';
import { DestinationsService } from './destinations.service.js';

/**
 * Destinations endpoint (F1-07 T04). DatabaseModule is global
 * (TenantContext/TenantDb); AuditModule supplies the transactional writer used
 * for `destination.*` rows.
 */
@Module({
  imports: [AuditModule],
  controllers: [DestinationsController],
  providers: [DestinationsRepository, DestinationsService],
})
export class DestinationsModule {}

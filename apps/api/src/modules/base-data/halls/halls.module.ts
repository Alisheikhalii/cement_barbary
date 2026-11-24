import { Module } from '@nestjs/common';

import { AuditModule } from '../../audit/audit.module.js';
import { HallTerminalReferences } from './hall-terminal-references.js';
import { HallsController } from './halls.controller.js';
import { HallsRepository } from './halls.repository.js';
import { HallsService } from './halls.service.js';
import { TerminalsRepository } from './terminals.repository.js';

/**
 * Halls + nested terminals (F1-07 T05). DatabaseModule is global;
 * AuditModule supplies the transactional writer for `hall.*` / `terminal.*`.
 */
@Module({
  imports: [AuditModule],
  controllers: [HallsController],
  providers: [HallsRepository, TerminalsRepository, HallTerminalReferences, HallsService],
})
export class HallsModule {}

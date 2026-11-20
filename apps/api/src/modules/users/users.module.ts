import { Module } from '@nestjs/common';

import { PiiModule } from '../../security/pii/pii.module.js';
import { UsersRepository } from './users.repository.js';

/**
 * Users module (F1-03 T06): repository only, no HTTP — endpoints wait for the
 * RBAC guards of F1-05 (ADR-006 U15). DatabaseModule is global (TenantDb,
 * TenantContext); PiiModule is imported for PiiService.
 */
@Module({
  imports: [PiiModule],
  providers: [UsersRepository],
  exports: [UsersRepository],
})
export class UsersModule {}

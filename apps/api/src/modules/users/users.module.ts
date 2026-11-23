import { Module } from '@nestjs/common';

import { PiiModule } from '../../security/pii/pii.module.js';
import { AuditModule } from '../audit/audit.module.js';
import { UserRoleService } from './user-role.service.js';
import { UsersRepository } from './users.repository.js';

/**
 * Users module (F1-03 T06): repository plus the role-change service (F1-06
 * T06), no HTTP — endpoints wait for the RBAC guards of F1-05 (ADR-006 U15).
 * DatabaseModule is global (TenantDb, TenantContext); PiiModule is imported for
 * PiiService; AuditModule supplies the transactional writer.
 */
@Module({
  imports: [PiiModule, AuditModule],
  providers: [UsersRepository, UserRoleService],
  exports: [UsersRepository, UserRoleService],
})
export class UsersModule {}

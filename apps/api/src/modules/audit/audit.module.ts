import { Module } from '@nestjs/common';

import { AuditStore } from '../../db/audit-store.js';
import { AUDIT_HOOK } from '../../security/authz/audit-hook.js';
import { PiiModule } from '../../security/pii/pii.module.js';
import { AuditWriter } from './audit-writer.js';
import { PersistentAuditHook } from './persistent-audit-hook.js';

/**
 * Audit persistence wiring (F1-06 T05). Binds the AUDIT_HOOK token to the
 * persistent implementation — the no-op provider is gone from production.
 * DatabaseModule is global (TenantContext/TenantDb); PiiModule supplies the
 * encryption keys for the IP column.
 */
@Module({
  imports: [PiiModule],
  providers: [
    AuditStore,
    AuditWriter,
    PersistentAuditHook,
    { provide: AUDIT_HOOK, useExisting: PersistentAuditHook },
  ],
  exports: [AUDIT_HOOK, AuditWriter, PersistentAuditHook],
})
export class AuditModule {}

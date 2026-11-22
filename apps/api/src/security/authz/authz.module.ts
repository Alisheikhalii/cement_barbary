import { Module } from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR, DiscoveryModule } from '@nestjs/core';

import { AuditModule } from '../../modules/audit/audit.module.js';
import { AuthorizationGuard } from './authorization.guard.js';
import { AuthzBootCheck } from './authz-boot.check.js';
import { AuthzRouteDiscovery } from './route-discovery.js';
import { SensitiveAuditInterceptor } from './sensitive-audit.interceptor.js';

/**
 * Authorization module (F1-05 T03). Registers the second global guard AFTER
 * AuthModule's AuthGuard (module import order in AppModule) and the boot
 * assertion over the real route surface. No controllers of its own.
 *
 * F1-06 T05: AuditModule binds AUDIT_HOOK to the persistent hook; the no-op
 * implementation is no longer provided anywhere.
 */
@Module({
  imports: [DiscoveryModule, AuditModule],
  providers: [
    AuthzRouteDiscovery,
    AuthzBootCheck,
    { provide: APP_GUARD, useClass: AuthorizationGuard },
    { provide: APP_INTERCEPTOR, useClass: SensitiveAuditInterceptor },
  ],
  exports: [AuthzRouteDiscovery, AuditModule],
})
export class AuthzModule {}

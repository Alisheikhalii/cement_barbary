import { Module } from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR, DiscoveryModule } from '@nestjs/core';

import { AUDIT_HOOK, NoopAuditHook } from './audit-hook.js';
import { AuthorizationGuard } from './authorization.guard.js';
import { AuthzBootCheck } from './authz-boot.check.js';
import { AuthzRouteDiscovery } from './route-discovery.js';
import { SensitiveAuditInterceptor } from './sensitive-audit.interceptor.js';

/**
 * Authorization module (F1-05 T03). Registers the second global guard AFTER
 * AuthModule's AuthGuard (module import order in AppModule) and the boot
 * assertion over the real route surface. No controllers of its own.
 */
@Module({
  imports: [DiscoveryModule],
  providers: [
    AuthzRouteDiscovery,
    AuthzBootCheck,
    { provide: APP_GUARD, useClass: AuthorizationGuard },
    // F1-05 T06: the no-op hook records nothing; F1-06 replaces this provider.
    { provide: AUDIT_HOOK, useClass: NoopAuditHook },
    { provide: APP_INTERCEPTOR, useClass: SensitiveAuditInterceptor },
  ],
  exports: [AuthzRouteDiscovery, AUDIT_HOOK],
})
export class AuthzModule {}

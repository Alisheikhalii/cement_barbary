import { Module } from '@nestjs/common';
import { APP_GUARD, DiscoveryModule } from '@nestjs/core';

import { AuthorizationGuard } from './authorization.guard.js';
import { AuthzBootCheck } from './authz-boot.check.js';
import { AuthzRouteDiscovery } from './route-discovery.js';

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
  ],
  exports: [AuthzRouteDiscovery],
})
export class AuthzModule {}

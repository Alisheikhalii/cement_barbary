import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';

import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';
import { AuthzRouteDiscovery } from './route-discovery.js';
import { scanControllers, scanRoutes } from './route-scan.js';

/**
 * Boot assertion (ADR-008 Z3, owner C5/C6, CP1 RD-03). Runs after every module
 * is initialized and before the app accepts traffic. Any marker, public-route,
 * sensitive-reason or production-surface violation makes startup fail.
 */
@Injectable()
export class AuthzBootCheck implements OnModuleInit {
  constructor(
    @Inject(AuthzRouteDiscovery) private readonly discovery: AuthzRouteDiscovery,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onModuleInit(): void {
    const routes = this.discovery.collect();
    const issues = [
      ...scanRoutes(routes, this.config.nodeEnv),
      ...scanControllers(this.discovery.collectControllers(), routes, this.config.nodeEnv),
    ];
    if (issues.length > 0) {
      const summary = issues.map((issue) => `${issue.code}@${issue.route}`).join(', ');
      // Server-side only: the process refuses to start. No client ever sees this.
      throw new Error(`Authorization surface check failed: ${summary}`);
    }
  }
}

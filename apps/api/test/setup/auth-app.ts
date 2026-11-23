import { RequestMethod, type Type } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { API_PREFIX } from '@bitabar/shared';
import helmet from 'helmet';
import { inject } from 'vitest';

import { AppModule } from '../../src/app.module.js';
import {
  PASSWORD_METHOD_CLOCK,
  type PasswordMethodClock,
} from '../../src/modules/auth/password-method.js';
import { RATE_LIMITER, type RateLimiter } from '../../src/modules/auth/rate-limiter.js';

/**
 * Boots the real AppModule against the shared integration container, with the
 * same global prefix and Helmet as main.ts. `env` overrides (rate limits, …)
 * are applied BEFORE the config module parses process.env. Extra modules are
 * for test-only probe controllers (e.g. the sensitive-authorization route).
 */
export interface AuthAppOverride {
  readonly provide: unknown;
  readonly useValue: unknown;
}

export async function buildAuthApp(
  env: Record<string, string> = {},
  extraModules: readonly Type[] = [],
  options: { passwordMethodClock?: PasswordMethodClock; rateLimiter?: RateLimiter } = {},
  overrides: readonly AuthAppOverride[] = [],
): Promise<NestExpressApplication> {
  Object.assign(process.env, {
    DATABASE_URL: inject('appUrl'),
    NODE_ENV: 'test',
    ...env,
  });
  const builder = Test.createTestingModule({
    imports: [AppModule, ...extraModules],
  });
  if (options.passwordMethodClock !== undefined) {
    builder.overrideProvider(PASSWORD_METHOD_CLOCK).useValue(options.passwordMethodClock);
  }
  if (options.rateLimiter !== undefined) {
    builder.overrideProvider(RATE_LIMITER).useValue(options.rateLimiter);
  }
  for (const override of overrides) {
    builder.overrideProvider(override.provide as never).useValue(override.useValue);
  }
  const moduleRef = await builder.compile();
  const app = moduleRef.createNestApplication<NestExpressApplication>();
  app.use(helmet());
  app.setGlobalPrefix(API_PREFIX, {
    exclude: [
      { path: 'health', method: RequestMethod.ALL },
      { path: 'health/{*splat}', method: RequestMethod.ALL },
    ],
  });
  await app.init();
  return app;
}

/** Header pair required by the CSRF guard on cookie endpoints. */
export const CSRF_HEADERS = { 'x-bitabar-csrf': '1' };

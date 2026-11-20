import { RequestMethod } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { API_PREFIX } from '@bitabar/shared';
import helmet from 'helmet';
import { inject } from 'vitest';

import { AppModule } from '../../src/app.module.js';

/**
 * Boots the real AppModule against the shared integration container, with the
 * same global prefix and Helmet as main.ts. `env` overrides (rate limits, …)
 * are applied BEFORE the config module parses process.env.
 */
export async function buildAuthApp(
  env: Record<string, string> = {},
): Promise<NestExpressApplication> {
  Object.assign(process.env, {
    DATABASE_URL: inject('appUrl'),
    NODE_ENV: 'test',
    ...env,
  });
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
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

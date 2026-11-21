import 'reflect-metadata';

import { RequestMethod } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { API_PREFIX } from '@bitabar/shared';
import helmet from 'helmet';
import { Logger } from 'nestjs-pino';

import { AppModule } from './app.module.js';
import { APP_CONFIG } from './config/config.module.js';
import type { AppConfig } from './config/env.js';
import { loadEnvFiles } from './config/load-env.js';
import { setupSwagger } from './swagger.js';

async function bootstrap(): Promise<void> {
  loadEnvFiles();
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bufferLogs: true });
  app.useLogger(app.get(Logger));

  const config = app.get<AppConfig>(APP_CONFIG);

  // Security headers + environment-driven CORS allowlist (GUIDELINES §6.3).
  app.use(helmet());
  app.enableCors({ origin: config.corsOrigins, credentials: true });

  // Health probes stay unprefixed so orchestrators can use stable paths (GUIDELINES §10).
  app.setGlobalPrefix(API_PREFIX, {
    exclude: [
      { path: 'health', method: RequestMethod.ALL },
      { path: 'health/{*splat}', method: RequestMethod.ALL },
    ],
  });

  // C1/Z13: production must not expose Swagger at all.
  setupSwagger(app, config);

  app.enableShutdownHooks();
  await app.listen(config.port);
  app.get(Logger).log(`API listening on port ${config.port}`);
}

void bootstrap();

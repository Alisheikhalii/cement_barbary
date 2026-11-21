import type { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

import type { AppConfig } from './config/env.js';

/**
 * Swagger is environment-gated (ADR-008 Z13, owner C1): production never
 * registers `/api/docs` or `/api/docs-json`; development and test keep both.
 * Kept as a small function so a test can boot the real module and assert the
 * production surface is absent.
 *
 * @returns true when Swagger was registered.
 */
export function setupSwagger(app: INestApplication, config: Pick<AppConfig, 'nodeEnv'>): boolean {
  if (config.nodeEnv === 'production') {
    return false;
  }
  const swaggerConfig = new DocumentBuilder()
    .setTitle('BitaBar API')
    .setDescription('Load announcement and driver queueing system')
    .setVersion('0.1.0')
    .build();
  SwaggerModule.setup('api/docs', app, SwaggerModule.createDocument(app, swaggerConfig));
  return true;
}

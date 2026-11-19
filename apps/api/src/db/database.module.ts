import { Global, Module } from '@nestjs/common';

import { databaseProviders, DB, PG_POOL } from './database.providers.js';
import { DbHealth } from './db-health.js';

/** Global so every module can inject DB/DbHealth without imports (D11 keeps usage inside src/db). */
@Global()
@Module({
  providers: [...databaseProviders, DbHealth],
  exports: [PG_POOL, DB, DbHealth],
})
export class DatabaseModule {}

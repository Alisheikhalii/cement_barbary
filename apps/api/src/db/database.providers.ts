import { Inject, Injectable, type OnApplicationShutdown, type Provider } from '@nestjs/common';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';

import { APP_CONFIG } from '../config/config.module.js';
import type { AppConfig } from '../config/env.js';
import * as schema from './schema/index.js';

/**
 * The single pool + Drizzle instance for the whole app (ADR-005 D10/D11).
 * The pool connects as the runtime role (DATABASE_URL) and is lazy: the app
 * boots even if the DB is briefly down; /health/ready reports the outage.
 * Raw access tokens stay inside src/db/** (enforced by lint, T09).
 */
export const PG_POOL = Symbol('PG_POOL');
export const DB = Symbol('DB');
export type Db = NodePgDatabase<typeof schema>;

export const pgPoolProvider: Provider = {
  provide: PG_POOL,
  inject: [APP_CONFIG],
  useFactory: (config: AppConfig): Pool =>
    new Pool({
      connectionString: config.database.url,
      max: config.database.poolMax,
      statement_timeout: config.database.statementTimeoutMs,
      application_name: 'bitabar-api',
    }),
};

export const dbProvider: Provider = {
  provide: DB,
  inject: [PG_POOL],
  useFactory: (pool: Pool): Db => drizzle(pool, { schema }),
};

/** Closes the pool when Nest shuts down so the process exits cleanly. */
@Injectable()
export class PoolLifecycle implements OnApplicationShutdown {
  constructor(@Inject(PG_POOL) private readonly pool: Pool) {}

  async onApplicationShutdown(): Promise<void> {
    await this.pool.end();
  }
}

export const databaseProviders: Provider[] = [pgPoolProvider, dbProvider, PoolLifecycle];

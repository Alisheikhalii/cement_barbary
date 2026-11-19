import { Inject, Injectable } from '@nestjs/common';
import type { Pool } from 'pg';

import { PG_POOL } from './database.providers.js';

const PING_TIMEOUT_MS = 2000;

/** Readiness probe for the database: a bounded SELECT 1 against the runtime pool. */
@Injectable()
export class DbHealth {
  constructor(@Inject(PG_POOL) private readonly pool: Pool) {}

  /** Resolves when the DB answers; rejects on error or after 2 seconds. */
  async ping(): Promise<void> {
    const timeout = new Promise<never>((_resolve, reject) => {
      setTimeout(() => reject(new Error(`db ping timed out after ${PING_TIMEOUT_MS}ms`)), 2000);
    });
    await Promise.race([this.pool.query('SELECT 1'), timeout]);
  }
}

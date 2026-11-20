import {
  Inject,
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import type { Pool } from 'pg';

import { PG_POOL } from './tokens.js';

/**
 * Startup guard (phase review M2): the API must connect as the RLS-bound
 * runtime role. Table owners bypass RLS unless FORCE is set (it is not), and
 * `BYPASSRLS`/superusers ignore it entirely — a DATABASE_URL accidentally set
 * to the migration owner would silently disable tenant isolation.
 *
 * The pool is lazy by design: if the database is unreachable at boot this
 * check is skipped and /health/ready reports the outage. Once a connection
 * succeeds, a privileged role is a hard configuration defect and boot fails.
 */
export class RuntimeRoleError extends Error {}

const RETRY_INTERVAL_MS = 30_000;

@Injectable()
export class RuntimeRoleCheck implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger(RuntimeRoleCheck.name);
  private retryTimer: NodeJS.Timeout | undefined;

  constructor(@Inject(PG_POOL) private readonly pool: Pool) {}

  async onApplicationBootstrap(): Promise<void> {
    if (await this.verify()) {
      return;
    }
    // The lazy-pool design allows booting during a database outage. Keep
    // checking until it is reachable, so a misconfigured role cannot run
    // unverified for the whole process lifetime (review R2).
    this.logger.warn('runtime role not verified yet (database unreachable); retrying');
    this.retryTimer = setInterval(() => {
      void this.retry();
    }, RETRY_INTERVAL_MS);
    this.retryTimer.unref();
  }

  /** One retry: stop polling on success; a privileged role is fatal. */
  private async retry(): Promise<void> {
    try {
      if (await this.verify()) {
        this.stopRetry();
      }
    } catch (error) {
      this.logger.error(
        `runtime role verification failed: ${error instanceof Error ? error.message : 'unknown'}`,
      );
      process.exit(1);
    }
  }

  private stopRetry(): void {
    if (this.retryTimer !== undefined) {
      clearInterval(this.retryTimer);
      this.retryTimer = undefined;
    }
  }

  onApplicationShutdown(): void {
    if (this.retryTimer !== undefined) {
      clearInterval(this.retryTimer);
      this.retryTimer = undefined;
    }
  }

  /** true = verified, false = database still unreachable; throws on a bad role. */
  private async verify(): Promise<boolean> {
    let row:
      | { role: string; rolsuper: boolean; rolbypassrls: boolean; owns_auth_tables: boolean }
      | undefined;
    try {
      const result = await this.pool.query<{
        role: string;
        rolsuper: boolean;
        rolbypassrls: boolean;
        owns_auth_tables: boolean;
      }>(
        `SELECT current_user AS role, r.rolsuper, r.rolbypassrls,
                EXISTS (
                  SELECT 1 FROM pg_class c
                   WHERE c.relname IN ('users', 'tenants', 'user_credentials', 'auth_sessions')
                     AND pg_has_role(current_user, pg_get_userbyid(c.relowner), 'MEMBER')
                ) AS owns_auth_tables
           FROM pg_roles r WHERE r.rolname = current_user`,
      );
      row = result.rows[0];
    } catch {
      return false;
    }
    if (row === undefined || row.rolsuper || row.rolbypassrls || row.owns_auth_tables) {
      throw new RuntimeRoleError(
        'refused to start: DATABASE_URL must point at the RLS-bound runtime role',
      );
    }
    this.logger.log('runtime role verified (RLS-bound)');
    return true;
  }
}

import { randomBytes } from 'node:crypto';

import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { Pool } from 'pg';

import { runMigrations } from '../../src/db/migrate.js';

/**
 * Shared integration-test database (ADR-005 D12): one PostgreSQL 17 container
 * per `pnpm test:int` run. Migrations run as the container superuser (the
 * schema owner), then the runtime role gets a random per-run password that is
 * never printed. Tests receive both URLs through Vitest's provided context.
 */
declare module 'vitest' {
  interface ProvidedContext {
    /** Schema-owner connection (superuser in the test container). */
    ownerUrl: string;
    /** Runtime-role connection (bitabar_app; RLS applies). */
    appUrl: string;
  }
}

/** Structural type of the TestProject argument Vitest 5 passes to globalSetup. */
interface GlobalSetupProject {
  provide(key: string, value: unknown): void;
}

let container: StartedPostgreSqlContainer | undefined;

export async function setup(project: GlobalSetupProject): Promise<void> {
  container = await new PostgreSqlContainer('postgres:17-alpine').start();
  const ownerUrl = container.getConnectionUri();

  await runMigrations(ownerUrl);

  // Enable the runtime login with a random per-run password. The password is
  // bound as a parameter to set_config and only then read back by format('%L')
  // inside the DO block — it is never concatenated into SQL and never logged.
  const password = randomBytes(24).toString('hex');
  const pool = new Pool({ connectionString: ownerUrl });
  const client = await pool.connect();
  try {
    await client.query(`SELECT set_config('vars.app_pw', $1, false)`, [password]);
    await client.query(
      `DO $$ BEGIN
         EXECUTE format('ALTER ROLE bitabar_app LOGIN PASSWORD %L', current_setting('vars.app_pw'));
       END $$;`,
    );
  } finally {
    client.release();
    await pool.end();
  }

  const appUrl = new URL(ownerUrl);
  appUrl.username = 'bitabar_app';
  appUrl.password = password;

  project.provide('ownerUrl', ownerUrl);
  project.provide('appUrl', appUrl.toString());
}

export async function teardown(): Promise<void> {
  await container?.stop();
}

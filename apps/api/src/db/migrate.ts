import { fileURLToPath, pathToFileURL } from 'node:url';

import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { Pool } from 'pg';
import { z } from 'zod';

import { loadEnvFiles } from '../config/load-env.js';

/**
 * Explicit, forward-only migration runner (ADR-005 D2). Migrations never run
 * at app startup; they run through this command (db:migrate / db:migrate:prod)
 * or the test harness (T06 imports runMigrations). Only this file reads
 * DATABASE_MIGRATION_URL — the app itself never sees the owner credentials.
 */

/** Resolved relative to this file, so it works from src (tsx) and dist (node). */
const MIGRATIONS_FOLDER = fileURLToPath(new URL('../../drizzle', import.meta.url));

const migrationEnvSchema = z.object({
  DATABASE_MIGRATION_URL: z
    .url()
    .refine(
      (u) => u.startsWith('postgres://') || u.startsWith('postgresql://'),
      'must be a postgres URL',
    ),
});

/** Applies all pending migrations using the schema-owner connection. */
export async function runMigrations(ownerUrl: string): Promise<void> {
  const pool = new Pool({ connectionString: ownerUrl });
  try {
    await migrate(drizzle(pool), { migrationsFolder: MIGRATIONS_FOLDER });
  } finally {
    await pool.end();
  }
}

async function main(): Promise<void> {
  loadEnvFiles();
  const parsed = migrationEnvSchema.safeParse(process.env);
  if (!parsed.success) {
    // Never print the value — only the variable name and the issue.
    console.error('DATABASE_MIGRATION_URL is missing or is not a postgres URL');
    process.exit(1);
  }
  try {
    await runMigrations(parsed.data.DATABASE_MIGRATION_URL);
    // stdout write instead of console.log (lint: no-console).
    process.stdout.write('migrations applied/ok\n');
  } catch (error) {
    // pg error messages never contain the password; log message/code only.
    const err = error as NodeJS.ErrnoException & { code?: string };
    console.error(`migration failed: ${err.code ? `${err.code} ` : ''}${err.message}`);
    process.exit(1);
  }
}

const invokedAsCli = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedAsCli) {
  void main();
}

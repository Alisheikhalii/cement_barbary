import { defineConfig } from 'drizzle-kit';

/**
 * drizzle-kit CLI config only (generate/check/push). Never imported at runtime.
 * The URL is the schema owner (DATABASE_MIGRATION_URL); generate/check do not
 * open a connection, so the value may be absent locally.
 */
export default defineConfig({
  dialect: 'postgresql',
  schema: './src/db/schema/index.ts',
  out: './drizzle',
  dbCredentials: {
    url: process.env.DATABASE_MIGRATION_URL ?? '',
  },
});

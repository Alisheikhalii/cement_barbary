import baseConfig from '@bitabar/config/eslint';

export default [
  ...baseConfig,
  {
    rules: {
      // NestJS modules are decorator-driven empty classes by design.
      '@typescript-eslint/no-extraneous-class': ['error', { allowWithDecorator: true }],
    },
  },
  {
    // ADR-005 D11: raw database access (pg, drizzle-orm, the DB tokens) lives
    // only in src/db/** — every other module must go through TenantDb.
    files: ['src/**/*.ts'],
    ignores: ['src/db/**'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'pg', message: 'Use TenantDb (src/db) — ADR-005' },
            { name: 'drizzle-orm', message: 'Use TenantDb (src/db) — ADR-005' },
            {
              name: 'drizzle-orm/node-postgres',
              message: 'Use TenantDb (src/db) — ADR-005',
            },
          ],
          patterns: [
            {
              group: ['pg/**', 'drizzle-orm/**'],
              message: 'Use TenantDb (src/db) — ADR-005',
            },
            {
              group: ['**/db/database.providers', '**/db/database.providers.js'],
              importNames: ['PG_POOL', 'DB'],
              message: 'Use TenantDb (src/db) — ADR-005',
            },
          ],
        },
      ],
    },
  },
];

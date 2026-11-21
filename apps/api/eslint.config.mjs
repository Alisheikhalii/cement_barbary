import baseConfig from '@bitabar/config/eslint';

/**
 * ADR-005 D11 + ADR-008 Z5 boundaries. Kept as data so both restricted-import
 * blocks below carry the full D11 rule (a later `no-restricted-imports`
 * config replaces earlier options instead of merging them).
 */
const DB_RESTRICTED_IMPORTS = {
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
};

/**
 * Role constants belong to the authorization layer (ADR-008 Z5). The users
 * module owns the role data and the operator CLI must validate role flags, so
 * both are explicit allowlists with the reason recorded here.
 */
const ROLE_RESTRICTED_IMPORTS = {
  patterns: [
    {
      group: ['**/security/authz/**'],
      importNames: [
        'ROLE_CODES',
        'ROLE_PERMISSIONS',
        'roleHasPermission',
        'permissionsForRole',
        'isRoleCode',
      ],
      message: 'Role checks belong in security/authz/** (ADR-008 Z5).',
    },
    {
      group: ['**/modules/users/users.types*', '**/users/users.types*'],
      importNames: ['ASSIGNABLE_ROLES', 'ROLE_SCOPE'],
      message:
        'Role constants are owned by the users module; operator-cli.ts is the only allowlisted consumer (ADR-008 Z5).',
    },
  ],
};

export default [
  ...baseConfig,
  {
    rules: {
      // NestJS modules are decorator-driven empty classes by design.
      '@typescript-eslint/no-extraneous-class': ['error', { allowWithDecorator: true }],
    },
  },
  {
    // Controllers never inspect roles themselves; the access marker decides.
    files: ['src/**/*.controller.ts'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector: "MemberExpression[property.name='roles']",
          message: 'Controllers must not inspect roles; use @RequirePermission() (ADR-008 Z5).',
        },
        {
          selector: "MemberExpression[computed=true][property.value='roles']",
          message: 'Controllers must not inspect roles; use @RequirePermission() (ADR-008 Z5).',
        },
        {
          selector: "ObjectPattern > Property[key.name='roles']",
          message: 'Controllers must not destructure roles; use @RequirePermission() (ADR-008 Z5).',
        },
        {
          selector: "ObjectPattern > Property[computed=true][key.value='roles']",
          message: 'Controllers must not destructure roles; use @RequirePermission() (ADR-008 Z5).',
        },
      ],
    },
  },
  {
    // ADR-005 D11: raw database access (pg, drizzle-orm, the DB tokens) lives
    // only in src/db/** — every other module must go through TenantDb.
    files: ['src/**/*.ts'],
    ignores: ['src/db/**'],
    rules: {
      'no-restricted-imports': ['error', DB_RESTRICTED_IMPORTS],
    },
  },
  {
    // ADR-008 Z5: same files as D11 minus the role-layer allowlists. Carries
    // the D11 options too because this rule replaces, not merges, earlier ones.
    files: ['src/**/*.ts'],
    ignores: [
      'src/db/**',
      'src/security/authz/**',
      'src/modules/users/**',
      'src/cli/operator-cli.ts',
    ],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: DB_RESTRICTED_IMPORTS.paths,
          patterns: [...DB_RESTRICTED_IMPORTS.patterns, ...ROLE_RESTRICTED_IMPORTS.patterns],
        },
      ],
    },
  },
];

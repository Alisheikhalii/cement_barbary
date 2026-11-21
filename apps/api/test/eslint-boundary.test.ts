import { fileURLToPath } from 'node:url';

import { ESLint } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * Proves the two import/role boundaries in eslint.config.mjs actually fire:
 * (1) ADR-005 D11 — raw pg / drizzle-orm / DB tokens only in src/db/**;
 * (2) ADR-008 Z5 — controllers never inspect roles and role constants stay in
 * security/authz/** (with the users module and operator CLI allowlisted).
 * Docker-free; runs the project's real flat config.
 */
const apiRoot = fileURLToPath(new URL('..', import.meta.url));

// One shared ESLint instance, created and WARMED in beforeAll: flat-config and
// plugin resolution is lazy, so the first lintText call pays the full load
// cost. Doing it here (with a generous hook timeout) keeps that one-time cost
// out of individual test timeouts — the cause of this suite's past flakes
// under parallel worker load (T08, root-caused by investigation subagent).
let eslint: ESLint;

beforeAll(async () => {
  eslint = new ESLint({ cwd: apiRoot });
  // Warm-up: force the one-time flat-config/plugin load inside the hook.
  await eslint.lintText('export {};\n', { filePath: 'src/db/probe.ts' });
}, 60000);

async function lintRules(code: string, filePath: string): Promise<(string | null)[]> {
  const [result] = await eslint.lintText(code, { filePath });
  return result ? result.messages.map((m) => m.ruleId) : [];
}

const FORBIDDEN_IMPORTS = [
  "import { Pool } from 'pg';\nexport const probe = Pool;\n",
  "import { drizzle } from 'drizzle-orm/node-postgres';\nexport const probe = drizzle;\n",
  "import { sql } from 'drizzle-orm';\nexport const probe = sql;\n",
  "import { pgTable } from 'drizzle-orm/pg-core';\nexport const probe = pgTable;\n",
  "import { PG_POOL } from '../../db/database.providers.js';\nexport const probe = PG_POOL;\n",
  "import { DB } from '../../db/database.providers.js';\nexport const probe = DB;\n",
];

// Programmatic ESLint is slow on contended machines; give it room.
describe('ESLint D11 boundary (no-restricted-imports)', { timeout: 30000 }, () => {
  it.each(FORBIDDEN_IMPORTS)('rejects raw DB imports outside src/db/**: %s', async (code) => {
    const rules = await lintRules(code, 'src/modules/probe/probe.ts');
    expect(rules).toContain('no-restricted-imports');
  });

  it('allows the same imports inside src/db/**', async () => {
    const code = "import { Pool } from 'pg';\nexport const probe = Pool;\n";
    const rules = await lintRules(code, 'src/db/probe.ts');
    expect(rules).not.toContain('no-restricted-imports');
  });

  it('allows the sanctioned expression re-export (src/db/sql) outside src/db/**', async () => {
    const code = "import { eq } from '../../db/sql.js';\nexport const probe = eq;\n";
    const rules = await lintRules(code, 'src/modules/probe/probe.ts');
    expect(rules).not.toContain('no-restricted-imports');
  });
});

describe('ESLint Z5 boundary (roles)', { timeout: 30000 }, () => {
  const ROLE_READ_CONTROLLER = [
    "import { Controller, Get } from '@nestjs/common';",
    "@Controller('probe')",
    'export class ProbeController {',
    '  @Get()',
    '  read(request: { auth?: { roles: string[] } }): string {',
    "    return request.auth?.roles.join(',') ?? '';",
    '  }',
    '}',
    '',
  ].join('\n');

  const COMPUTED_ROLE_READ_CONTROLLER = [
    "import { Controller, Get } from '@nestjs/common';",
    "@Controller('probe')",
    'export class ProbeController {',
    '  @Get()',
    '  read(request: { auth?: { roles: string[] } }): number {',
    "    return request.auth?.['roles'].length ?? 0;",
    '  }',
    '}',
    '',
  ].join('\n');

  const DESTRUCTURED_ROLE_READ_CONTROLLER = [
    "import { Controller, Get } from '@nestjs/common';",
    "@Controller('probe')",
    'export class ProbeController {',
    '  @Get()',
    '  read(request: { auth?: { roles: string[] } }): number {',
    '    const { roles } = request.auth ?? {};',
    '    return roles.length;',
    '  }',
    '}',
    '',
  ].join('\n');

  const MARKED_CONTROLLER = [
    "import { Controller, Get } from '@nestjs/common';",
    "import { RequirePermission } from '../../security/authz/decorators.js';",
    "@Controller('probe')",
    'export class ProbeController {',
    "  @RequirePermission('destination.read')",
    '  @Get()',
    '  read(): { ok: true } {',
    '    return { ok: true };',
    '  }',
    '}',
    '',
  ].join('\n');

  const ROLE_CONSTANT_IMPORT = [
    "import { ROLE_PERMISSIONS } from '../../security/authz/role-permissions.js';",
    'export const probe = ROLE_PERMISSIONS;',
    '',
  ].join('\n');

  it('rejects reading principal roles in a controller', async () => {
    const rules = await lintRules(ROLE_READ_CONTROLLER, 'src/modules/probe/probe.controller.ts');
    expect(rules).toContain('no-restricted-syntax');
  });

  it('rejects computed role access in a controller', async () => {
    const rules = await lintRules(
      COMPUTED_ROLE_READ_CONTROLLER,
      'src/modules/probe/probe.controller.ts',
    );
    expect(rules).toContain('no-restricted-syntax');
  });

  it('rejects destructuring roles in a controller', async () => {
    const rules = await lintRules(
      DESTRUCTURED_ROLE_READ_CONTROLLER,
      'src/modules/probe/probe.controller.ts',
    );
    expect(rules).toContain('no-restricted-syntax');
  });

  it('allows a controller that uses @RequirePermission without reading roles', async () => {
    const rules = await lintRules(MARKED_CONTROLLER, 'src/modules/probe/probe.controller.ts');
    expect(rules).not.toContain('no-restricted-syntax');
    expect(rules).not.toContain('no-restricted-imports');
  });

  it('rejects role constants imported outside the authz layer', async () => {
    const rules = await lintRules(ROLE_CONSTANT_IMPORT, 'src/modules/probe/probe.ts');
    expect(rules).toContain('no-restricted-imports');
  });

  it('rejects role constants from the users module outside its allowlists', async () => {
    const code = [
      "import { ASSIGNABLE_ROLES } from '../users/users.types.js';",
      'export const probe = ASSIGNABLE_ROLES;',
      '',
    ].join('\n');
    const rules = await lintRules(code, 'src/modules/probe/probe.ts');
    expect(rules).toContain('no-restricted-imports');
  });

  it('allows the same import inside security/authz/**', async () => {
    const rules = await lintRules(ROLE_CONSTANT_IMPORT, 'src/security/authz/role-probe.ts');
    expect(rules).not.toContain('no-restricted-imports');
  });

  it('allows role constants in the allowlisted operator CLI', async () => {
    const code = [
      "import { ASSIGNABLE_ROLES } from '../modules/users/users.types.js';",
      'export const probe = ASSIGNABLE_ROLES;',
      '',
    ].join('\n');
    const rules = await lintRules(code, 'src/cli/operator-cli.ts');
    expect(rules).not.toContain('no-restricted-imports');
  });

  it('allows role constants in the users module (role data owner)', async () => {
    const code = [
      "import { ROLE_SCOPE } from './users.types.js';",
      'export const probe = ROLE_SCOPE;',
      '',
    ].join('\n');
    const rules = await lintRules(code, 'src/modules/users/users.repository.ts');
    expect(rules).not.toContain('no-restricted-imports');
  });
});

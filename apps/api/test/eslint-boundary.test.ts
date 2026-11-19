import { fileURLToPath } from 'node:url';

import { ESLint } from 'eslint';
import { describe, expect, it } from 'vitest';

/**
 * Proves the ADR-005 D11 boundary rule in eslint.config.mjs actually fires:
 * raw pg / drizzle-orm / DB-token imports are rejected outside src/db/** and
 * allowed inside it. Docker-free; runs the project's real flat config.
 */
const apiRoot = fileURLToPath(new URL('..', import.meta.url));

// One shared ESLint instance: constructing it per assertion made this suite
// time out under parallel worker load.
const eslint = new ESLint({ cwd: apiRoot });

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
});

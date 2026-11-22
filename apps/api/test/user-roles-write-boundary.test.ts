import { readFile, readdir } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

/**
 * SR-05 source boundary (ADR-008 Z7): `user_roles` is written ONLY through the
 * two SECURITY DEFINER functions, and those calls live ONLY in
 * UsersRepository. The database grants (migration 0010) are the real
 * invariant; this scan catches a future direct-drizzle/raw-SQL write before it
 * reaches review.
 */
const srcRoot = fileURLToPath(new URL('../src', import.meta.url));

const DIRECT_DRIZZLE_WRITE = /\b(?:insert|update|delete)\(\s*userRoles\s*\)/;
const RAW_SQL_WRITE =
  /\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?|COPY|MERGE\s+INTO)\s+(?:public\.)?user_roles\b/i;
const FUNCTION_CALL = /\bapp\.(?:assign_user_role|revoke_user_role)\s*\(/g;

async function sourceFiles(): Promise<string[]> {
  const entries = await readdir(srcRoot, { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.ts'))
    .filter((entry) => !entry.name.endsWith('.test.ts'))
    .map((entry) => join(entry.parentPath, entry.name));
}

async function filesMatching(pattern: RegExp): Promise<string[]> {
  const matches: string[] = [];
  for (const file of await sourceFiles()) {
    const text = await readFile(file, 'utf8');
    // A fresh lastIndex per file: the pattern is global so matchAll stays simple.
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      matches.push(relative(srcRoot, file).split(sep).join('/'));
    }
  }
  return matches.sort();
}

describe('user_roles write boundary (SR-05)', () => {
  it('never writes user_roles directly through Drizzle', async () => {
    expect(await filesMatching(DIRECT_DRIZZLE_WRITE)).toEqual([]);
  });

  it('never writes user_roles through raw SQL in source', async () => {
    expect(await filesMatching(RAW_SQL_WRITE)).toEqual([]);
  });

  it('calls the two SECURITY DEFINER functions only from UsersRepository', async () => {
    expect(await filesMatching(FUNCTION_CALL)).toEqual(['modules/users/users.repository.ts']);
  });

  it('uses both functions, so assign and revoke are covered', async () => {
    const text = await readFile(join(srcRoot, 'modules', 'users', 'users.repository.ts'), 'utf8');
    expect(text).toMatch(/app\.assign_user_role\s*\(/);
    expect(text).toMatch(/app\.revoke_user_role\s*\(/);
  });
});

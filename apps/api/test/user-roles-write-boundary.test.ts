import { readFile, readdir } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

/**
 * SR-05 groundwork (ADR-008 Z7): `user_roles` is written ONLY by
 * UsersRepository. This is a source scan today; T07 extends the same idea to
 * the mass-assignment and BFLA suites.
 */
const srcRoot = fileURLToPath(new URL('../src', import.meta.url));

const WRITE_PATTERN = /\b(?:insert|update|delete)\(\s*userRoles\s*\)/;
const RAW_SQL_PATTERN =
  /\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?|COPY|MERGE\s+INTO)\s+(?:public\.)?user_roles\b/i;

async function sourceFiles(): Promise<string[]> {
  const entries = await readdir(srcRoot, { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.ts'))
    .filter((entry) => !entry.name.endsWith('.test.ts'))
    .map((entry) => join(entry.parentPath, entry.name));
}

describe('user_roles write boundary (SR-05)', () => {
  it('has at least one known write path', async () => {
    const files = await sourceFiles();
    const matches = (
      await Promise.all(
        files.map(async (file) => ({
          file,
          text: await readFile(file, 'utf8'),
        })),
      )
    ).filter(({ text }) => WRITE_PATTERN.test(text));
    expect(matches.map(({ file }) => relative(srcRoot, file).split(sep).join('/'))).toEqual([
      'modules/users/users.repository.ts',
    ]);
  });

  it('never writes user_roles through raw SQL in source', async () => {
    for (const file of await sourceFiles()) {
      const text = await readFile(file, 'utf8');
      expect(RAW_SQL_PATTERN.test(text), relative(srcRoot, file)).toBe(false);
    }
  });
});

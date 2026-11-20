import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { inject } from 'vitest';
import { describe, expect, it } from 'vitest';

import {
  assertDevSeedAllowed,
  DEV_SEED_TENANT,
  DEV_SEED_USERS,
  runDevSeed,
} from '../src/db/seed/dev-seed.js';
import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb } from '../src/db/tenant-db.js';
import { UsersRepository } from '../src/modules/users/users.repository.js';
import { buildAad } from '../src/security/pii/pii-crypto.js';
import { ownerPool, testPii } from './setup/db.js';

/**
 * Dev seed (U16 / owner T07 rules): refusal guard, idempotency, synthetic-data
 * guarantees, and proof that seeded rows go through the real app path (RLS +
 * PII). Static packaging checks (build/Docker/CI exclusions) live here too.
 */

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const API_ROOT = fileURLToPath(new URL('..', import.meta.url));

function seedDeps() {
  return {
    nodeEnv: 'development' as const,
    ownerUrl: inject('ownerUrl'),
    appUrl: inject('appUrl'),
    pii: testPii(),
  };
}

describe('dev seed guard (refusal)', () => {
  it('refuses when NODE_ENV is not development — including unset', () => {
    expect(() =>
      assertDevSeedAllowed('production', 'postgres://localhost:5432/db', 'postgres://localhost/db'),
    ).toThrow(/NODE_ENV/);
    expect(() =>
      assertDevSeedAllowed('test', 'postgres://localhost:5432/db', 'postgres://localhost/db'),
    ).toThrow(/NODE_ENV/);
    expect(() =>
      assertDevSeedAllowed(undefined, 'postgres://localhost:5432/db', 'postgres://localhost/db'),
    ).toThrow(/NODE_ENV/);
  });

  it('refuses when EITHER database URL host is not local (owner or runtime)', () => {
    expect(() =>
      assertDevSeedAllowed(
        'development',
        'postgres://db.internal:5432/db',
        'postgres://localhost/db',
      ),
    ).toThrow(/localhost/);
    expect(() =>
      assertDevSeedAllowed(
        'development',
        'postgres://localhost:5432/db',
        'postgres://db.internal/db',
      ),
    ).toThrow(/localhost/);
    expect(() =>
      assertDevSeedAllowed('development', 'not-a-url', 'postgres://localhost/db'),
    ).toThrow(/refused/);
  });

  it('allows development + local hosts only', () => {
    expect(() =>
      assertDevSeedAllowed(
        'development',
        'postgres://localhost:5432/db',
        'postgres://127.0.0.1/db',
      ),
    ).not.toThrow();
  });

  it('runDevSeed itself is guarded — refuses before opening any connection', async () => {
    // Port 1 is unreachable; a pass here proves the guard throws first.
    await expect(
      runDevSeed({
        nodeEnv: 'production',
        ownerUrl: 'postgres://127.0.0.1:1/db',
        appUrl: 'postgres://127.0.0.1:1/db',
        pii: testPii(),
      }),
    ).rejects.toThrow(/NODE_ENV/);
    await expect(
      runDevSeed({
        nodeEnv: undefined,
        ownerUrl: 'postgres://127.0.0.1:1/db',
        appUrl: 'postgres://127.0.0.1:1/db',
        pii: testPii(),
      }),
    ).rejects.toThrow(/NODE_ENV/);
  });
});

describe('dev seed data rules', () => {
  it('uses only gitleaks-allowlisted synthetic phones and no national IDs or passwords', () => {
    // The allowlisted synthetic range in .gitleaks.toml is 0912000000x.
    for (const user of DEV_SEED_USERS) {
      expect(user.phone).toMatch(/^0912000000[0-9]$/);
      expect(user).not.toHaveProperty('nationalId');
      expect(user).not.toHaveProperty('password');
    }
    expect(DEV_SEED_TENANT.code).toBe('dev-factory');
  });

  it('is excluded from the production build and from Docker build inputs', () => {
    const tsconfigBuild = JSON.parse(readFileSync(`${API_ROOT}tsconfig.build.json`, 'utf8')) as {
      exclude?: string[];
    };
    expect(tsconfigBuild.exclude?.some((p) => p.includes('src/db/seed'))).toBe(true);

    const dockerignore = readFileSync(`${API_ROOT}.dockerignore`, 'utf8');
    expect(dockerignore).toMatch(/src\/db\/seed/);
  });

  it('is never invoked by any CI workflow', () => {
    const workflowsDir = `${REPO_ROOT}/.github/workflows`;
    for (const file of readdirSync(workflowsDir)) {
      const content = readFileSync(`${workflowsDir}/${file}`, 'utf8');
      expect(content, `workflow ${file} must not run the dev seed`).not.toContain('db:seed:dev');
    }
  });
});

describe('dev seed against a real database', () => {
  it('seeds 1 tenant + 3 users + 3 role links, and a second run creates nothing', async () => {
    const first = await runDevSeed(seedDeps());
    expect(first.created).toBe(3);
    expect(first.skipped).toBe(0);

    const second = await runDevSeed(seedDeps());
    expect(second.tenantId).toBe(first.tenantId);
    expect(second.created).toBe(0);
    expect(second.skipped).toBe(3);

    const { rows: userRows } = await ownerPool().query<{ count: string }>(
      'SELECT count(*)::text AS count FROM users WHERE tenant_id = $1',
      [first.tenantId],
    );
    const { rows: linkRows } = await ownerPool().query<{ count: string }>(
      'SELECT count(*)::text AS count FROM user_roles WHERE tenant_id = $1',
      [first.tenantId],
    );
    expect(userRows[0]?.count).toBe('3');
    expect(linkRows[0]?.count).toBe('3');
  });

  it('stores phones encrypted (never plaintext), national_id columns stay NULL', async () => {
    const { tenantId } = await runDevSeed(seedDeps());
    const { rows } = await ownerPool().query<{
      id: string;
      phone_enc: Buffer | null;
      phone_hash: Buffer | null;
      national_id_enc: Buffer | null;
      national_id_hash: Buffer | null;
    }>(
      'SELECT id, phone_enc, phone_hash, national_id_enc, national_id_hash FROM users WHERE tenant_id = $1',
      [tenantId],
    );

    expect(rows).toHaveLength(3);
    for (const row of rows) {
      // Owner Q3: nothing may be written to national-id columns in F1-03.
      expect(row.national_id_enc).toBeNull();
      expect(row.national_id_hash).toBeNull();
      expect(row.phone_enc).not.toBeNull();
      expect(row.phone_hash).not.toBeNull();
      // Ciphertext must not contain any plaintext phone digit sequence.
      expect(row.phone_enc?.toString('utf8')).not.toMatch(/0912000000/);
      // ...and it decrypts back through the real PII path (AAD-bound).
      if (row.phone_enc === null) {
        throw new Error('seeded row is missing phone_enc');
      }
      const plain = testPii().decrypt(row.phone_enc, buildAad(tenantId, 'users.phone_enc', row.id));
      expect(plain).toMatch(/^0912000000[0-9]$/);
    }
  });

  it('seeded users are readable through UsersRepository as the runtime role (RLS)', async () => {
    const { tenantId } = await runDevSeed(seedDeps());
    const pool = new Pool({ connectionString: inject('appUrl') });
    try {
      const tenantContext = new TenantContext();
      const users = new UsersRepository(
        new TenantDb(drizzle(pool, { schema })),
        tenantContext,
        testPii(),
      );
      await tenantContext.run({ tenantId }, async () => {
        const operator = await users.findByUsername('dev.operator');
        if (!operator) {
          throw new Error('seeded operator not found');
        }
        expect(operator.displayName).toBe('اپراتور توسعه');
        expect(await users.getMaskedPhone(operator.id)).toBe('0912***0001');

        // Persian-digit input finds the same row through the blind index.
        const driver = await users.findByPhone('۰۹۱۲۰۰۰۰۰۰۳');
        if (!driver) {
          throw new Error('seeded driver not found');
        }
        expect(driver.username).toBeNull();
        expect(await users.listRoles(driver.id)).toEqual(['DRIVER']);

        const carrier = await users.findByUsername('dev.carrier');
        if (!carrier) {
          throw new Error('seeded carrier admin not found');
        }
        expect(await users.listRoles(carrier.id)).toEqual(['CARRIER_ADMIN']);
      });
    } finally {
      await pool.end();
    }
  });
});

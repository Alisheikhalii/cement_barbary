import { randomBytes, randomInt } from 'node:crypto';
import { pathToFileURL } from 'node:url';

import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { v7 as uuidv7 } from 'uuid';
import { z } from 'zod';

import { parseEnv } from '../../config/env.js';
import { loadEnvFiles } from '../../config/load-env.js';
import { AuditWriter } from '../../modules/audit/audit-writer.js';
import { AuthRepository } from '../../modules/auth/auth.repository.js';
import { UserRoleService } from '../../modules/users/user-role.service.js';
import { PasswordService } from '../../modules/auth/password.service.js';
import { checkPasswordPolicy, passwordKindForRoles } from '../../modules/auth/password-policy.js';
import { UsersRepository } from '../../modules/users/users.repository.js';
import type { AssignableRole } from '../../modules/users/users.types.js';
import { PiiService } from '../../security/pii/pii-crypto.js';
import { AuditStore } from '../audit-store.js';
import * as schema from '../schema/index.js';
import { TenantContext } from '../tenant-context.js';
import { TenantDb } from '../tenant-db.js';

/**
 * DEV-ONLY synthetic seed (ADR-006 U16). Hard rules:
 * - Refuses to run unless NODE_ENV=development AND the database host is local
 *   (assertDevSeedAllowed — tested in test/seed.int.test.ts).
 * - Never in CI, never in the production build (tsconfig.build.json excludes
 *   src/db/seed/**), never in any Docker image (apps/api/.dockerignore).
 * - Synthetic data only: one fake tenant, one user per role of the 3-role
 *   catalog, phones only from the gitleaks-allowlisted range, NO national IDs
 *   (owner Q3). F1-04 T08: every seeded account gets a crypto-random
 *   one-time password with `must_change_password = true` and the configured
 *   expiry; it is printed once on stdout and never stored in plaintext.
 * - Idempotent: a second run creates nothing (upsert by tenant code, lookup by
 *   username/phone before create, role assignment is a no-op on conflict);
 *   credentials are created only when absent, so a re-run cannot rotate them.
 * - Tenant row is created by the MIGRATION OWNER (INSERT on tenants is revoked
 *   from the runtime role, U4); every USERS write goes through UsersRepository
 *   under TenantContext as the runtime role — never raw SQL (owner T07 rule).
 */

export const DEV_SEED_TENANT = { code: 'dev-factory', name: 'کارخانه توسعه (تستی)' } as const;

export interface DevSeedUser {
  readonly role: AssignableRole;
  /** Staff log in with a username; the driver is phone-only (U12). */
  readonly username?: string;
  /** Synthetic number from the gitleaks allowlist range 0912000000x only. */
  readonly phone: string;
  readonly displayName: string;
}

export const DEV_SEED_USERS: readonly DevSeedUser[] = [
  {
    role: 'FACTORY_OPERATOR',
    username: 'dev.operator',
    phone: '09120000001',
    displayName: 'اپراتور توسعه',
  },
  {
    role: 'CARRIER_ADMIN',
    username: 'dev.carrier',
    phone: '09120000002',
    displayName: 'مدیر باربری توسعه',
  },
  { role: 'DRIVER', phone: '09120000003', displayName: 'راننده توسعه' },
];

const LOCAL_DB_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * The environment guard (change (e) / U16 + T07 hardening). Throws BEFORE any
 * connection is opened; messages carry no secrets. Called inside runDevSeed so
 * EVERY caller is protected, and directly by tests in-process. NODE_ENV unset
 * is a refusal (never silently treated as development), and BOTH the owner URL
 * and the runtime app URL must point at a local database.
 */
export function assertDevSeedAllowed(
  nodeEnv: string | undefined,
  ownerUrl: string,
  appUrl: string,
): void {
  if (nodeEnv !== 'development') {
    throw new Error('dev seed refused: NODE_ENV must be "development"');
  }
  for (const url of [ownerUrl, appUrl]) {
    let host: string;
    try {
      host = new URL(url).hostname;
    } catch {
      throw new Error('dev seed refused: database URL is not a valid URL');
    }
    if (!LOCAL_DB_HOSTS.has(host)) {
      throw new Error('dev seed refused: database host must be localhost');
    }
  }
}

export interface DevSeedDeps {
  /** Raw process.env.NODE_ENV — unset means refusal, never a silent default. */
  readonly nodeEnv: string | undefined;
  /** Migration-owner connection: creates the tenant row only (U4). */
  readonly ownerUrl: string;
  /** Runtime-role connection (bitabar_app): every users write via UsersRepository. */
  readonly appUrl: string;
  readonly pii: PiiService;
  readonly passwords: PasswordService;
  /** A19 TTL for the generated one-time passwords. */
  readonly tempPasswordTtlHours: number;
}

export interface DevSeedResult {
  readonly tenantId: string;
  readonly created: number;
  readonly skipped: number;
  /** Newly created credentials only — printed once by main(); never persisted. */
  readonly credentials: readonly { login: string; role: AssignableRole; password: string }[];
}

/** Crypto-random one-time password that satisfies the role's A20 policy. */
function generateOneTimePassword(role: AssignableRole, identifier: string): string {
  const kind = passwordKindForRoles([role]);
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const candidate =
      kind === 'driver-pin'
        ? Array.from({ length: 10 }, () => randomInt(0, 10)).join('')
        : randomBytes(15).toString('base64url');
    if (checkPasswordPolicy(kind, candidate, identifier) === null) {
      return candidate;
    }
  }
  throw new Error('dev seed failed: could not generate a policy-compliant password');
}

/** Runs the seed. Idempotent: re-running creates no duplicates. Guarded: refuses before opening any connection. */
export async function runDevSeed(deps: DevSeedDeps): Promise<DevSeedResult> {
  assertDevSeedAllowed(deps.nodeEnv, deps.ownerUrl, deps.appUrl);
  const ownerPool = new Pool({ connectionString: deps.ownerUrl });
  const appPool = new Pool({ connectionString: deps.appUrl, application_name: 'bitabar-dev-seed' });
  try {
    // Tenant upsert as owner (arbiter = the partial unique index on code).
    await ownerPool.query(
      `INSERT INTO tenants (id, code, name) VALUES ($1, $2, $3)
       ON CONFLICT (code) WHERE deleted_at IS NULL DO NOTHING`,
      [uuidv7(), DEV_SEED_TENANT.code, DEV_SEED_TENANT.name],
    );
    const found = await ownerPool.query<{ id: string }>(
      'SELECT id FROM tenants WHERE code = $1 AND deleted_at IS NULL',
      [DEV_SEED_TENANT.code],
    );
    const tenantId = found.rows[0]?.id;
    if (!tenantId) {
      throw new Error('dev seed failed: tenant row not visible after upsert');
    }

    // The real app path: TenantContext + TenantDb + UsersRepository + PiiService.
    const tenantContext = new TenantContext();
    const tenantDb = new TenantDb(drizzle(appPool, { schema }));
    const users = new UsersRepository(tenantDb, tenantContext, deps.pii);
    const credentials = new AuthRepository(tenantDb, tenantContext, deps.pii);
    const audit = new AuditWriter(tenantContext, deps.pii, new AuditStore(tenantDb));
    const userRoles = new UserRoleService(tenantDb, users, audit);

    let created = 0;
    let skipped = 0;
    const issued: { login: string; role: AssignableRole; password: string }[] = [];
    for (const entry of DEV_SEED_USERS) {
      // One transaction per user: user + role + first credential land together
      // (an interruption must not strand an account without credentials).
      await tenantContext.run({ tenantId }, () =>
        tenantDb.run(async () => {
          const existing =
            entry.username !== undefined
              ? await users.findByUsername(entry.username)
              : await users.findByPhone(entry.phone);
          let userId: string;
          if (existing) {
            skipped += 1;
            userId = existing.id;
          } else {
            const dto = await users.create(
              entry.username !== undefined
                ? { username: entry.username, displayName: entry.displayName, phone: entry.phone }
                : { displayName: entry.displayName, phone: entry.phone },
            );
            created += 1;
            userId = dto.id;
          }
          // The only role-write path (F1-06 D2): idempotent, and a real
          // assignment writes its system audit row in this transaction.
          await userRoles.assign(userId, entry.role, { type: 'system', tool: 'seed:dev' });

          // A19: first credentials only; a re-run never rotates an existing one.
          if ((await credentials.getCredentials(userId)) === null) {
            const login =
              entry.username !== undefined
                ? `${entry.username}@${DEV_SEED_TENANT.code}`
                : entry.phone;
            const password = generateOneTimePassword(entry.role, login);
            const passwordHash = await deps.passwords.hash(password);
            const expiresAt = new Date(Date.now() + deps.tempPasswordTtlHours * 3_600_000);
            await credentials.createCredentials(userId, passwordHash, expiresAt);
            issued.push({ login, role: entry.role, password });
          }
        }),
      );
    }
    return { tenantId, created, skipped, credentials: issued };
  } finally {
    await appPool.end();
    await ownerPool.end();
  }
}

const ownerUrlSchema = z.object({
  DATABASE_MIGRATION_URL: z
    .url()
    .refine(
      (u) => u.startsWith('postgres://') || u.startsWith('postgresql://'),
      'must be a postgres URL',
    ),
});

async function main(): Promise<void> {
  loadEnvFiles();
  const ownerEnv = ownerUrlSchema.safeParse(process.env);
  if (!ownerEnv.success) {
    process.stderr.write('DATABASE_MIGRATION_URL is missing or is not a postgres URL\n');
    process.exit(1);
  }
  let config;
  try {
    config = parseEnv(process.env);
  } catch (error) {
    process.stderr.write(`${(error as Error).message}\n`);
    process.exit(1);
  }
  try {
    const result = await runDevSeed({
      // Raw NODE_ENV: unset must refuse, not silently default to development.
      nodeEnv: process.env.NODE_ENV,
      ownerUrl: ownerEnv.data.DATABASE_MIGRATION_URL,
      appUrl: config.database.url,
      pii: new PiiService(config.pii),
      passwords: new PasswordService(config),
      tempPasswordTtlHours: config.auth.tempPasswordTtlHours,
    });
    process.stdout.write(
      `dev seed ok: tenant=${DEV_SEED_TENANT.code} created=${result.created} skipped=${result.skipped}\n`,
    );
    if (result.credentials.length > 0) {
      process.stdout.write('One-time passwords (shown once, never stored in plaintext):\n');
      for (const entry of result.credentials) {
        process.stdout.write(`  ${entry.role} ${entry.login}: ${entry.password}\n`);
      }
      process.stdout.write('Each account must change its password at first login.\n');
    }
  } catch (error) {
    process.stderr.write(`dev seed failed: ${(error as Error).message}\n`);
    process.exit(1);
  }
}

const invokedAsCli = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedAsCli) {
  void main();
}

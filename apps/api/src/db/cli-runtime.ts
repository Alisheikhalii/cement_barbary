import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';

import type { AppConfig } from '../config/env.js';
import { AuthRepository } from '../modules/auth/auth.repository.js';
import { PasswordService } from '../modules/auth/password.service.js';
import type { AssignableRole } from '../modules/users/users.types.js';
import { UsersRepository } from '../modules/users/users.repository.js';
import { PiiService } from '../security/pii/pii-crypto.js';
import { listTenants } from './auth-lookup.js';
import type { Db } from './database.providers.js';
import * as schema from './schema/index.js';
import { TenantContext } from './tenant-context.js';
import { TenantDb } from './tenant-db.js';

/**
 * Operator CLI runtime (F1-04 T08). Lives inside the src/db/** boundary because
 * it constructs the pg Pool and the Drizzle instance (ADR-005 D11). The CLI
 * itself never opens a connection, never writes SQL, and never receives a
 * tenant id from the command line: tenant codes are resolved here against the
 * active-tenant lookup and every write runs under TenantContext + TenantDb, so
 * RLS and the repository rules apply exactly as they do in the API.
 */

export interface OperatorRuntime {
  readonly passwords: PasswordService;
  readonly tempPasswordTtlHours: number;
  listTenantCodes(): Promise<string[]>;
  findTenant(code: string): Promise<{ id: string; code: string } | null>;
  createUserAndCredentials(input: {
    tenantId: string;
    username?: string;
    displayName: string;
    phone?: string;
    role: AssignableRole;
    passwordHash: string;
    expiresAt: Date;
  }): Promise<string>; // userId
  findUser(
    tenantId: string,
    lookup: { username?: string; phone?: string },
  ): Promise<{ id: string; roles: AssignableRole[] } | null>;
  hasCredentials(tenantId: string, userId: string): Promise<boolean>;
  resetPassword(
    tenantId: string,
    userId: string,
    passwordHash: string,
    expiresAt: Date,
  ): Promise<'ok' | 'missing' | 'stale'>;
  close(): Promise<void>;
}

/** Refuses to operate with a role that bypasses RLS (e.g. the owner URL). */
async function assertRuntimeRole(pool: Pool): Promise<void> {
  const result = await pool.query<{
    role: string;
    rolsuper: boolean;
    rolbypassrls: boolean;
    owns_auth_tables: boolean;
  }>(
    // A plain table owner also bypasses RLS (no FORCE ROW LEVEL SECURITY), and
    // the migration-owner role sits in the same .env — reject it too.
    `SELECT current_user AS role, r.rolsuper, r.rolbypassrls,
            EXISTS (
              SELECT 1 FROM pg_class c
               WHERE c.relname IN ('users', 'tenants', 'user_credentials', 'auth_sessions')
                 AND pg_has_role(current_user, pg_get_userbyid(c.relowner), 'MEMBER')
            ) AS owns_auth_tables
       FROM pg_roles r WHERE r.rolname = current_user`,
  );
  const row = result.rows[0];
  if (row === undefined || row.rolsuper || row.rolbypassrls || row.owns_auth_tables) {
    throw new Error('refused: DATABASE_URL must point at the RLS-bound runtime role');
  }
}

export async function createOperatorRuntime(config: AppConfig): Promise<OperatorRuntime> {
  const pool = new Pool({
    connectionString: config.database.url,
    application_name: 'bitabar-operator-cli',
  });
  try {
    await assertRuntimeRole(pool);
  } catch (error) {
    await pool.end();
    throw error;
  }
  const db: Db = drizzle(pool, { schema });
  const tenantContext = new TenantContext();
  const tenantDb = new TenantDb(db);
  const pii = new PiiService(config.pii);
  const users = new UsersRepository(tenantDb, tenantContext, pii);
  const authRepository = new AuthRepository(tenantDb, tenantContext, pii);
  const passwords = new PasswordService(config);

  return {
    passwords,
    tempPasswordTtlHours: config.auth.tempPasswordTtlHours,

    async listTenantCodes(): Promise<string[]> {
      return (await listTenants(db)).map((tenant) => tenant.code);
    },

    async findTenant(code: string): Promise<{ id: string; code: string } | null> {
      // Active tenants only (app.list_tenants), matched exactly.
      const match = (await listTenants(db)).find((tenant) => tenant.code === code);
      return match ?? null;
    },

    async createUserAndCredentials(input): Promise<string> {
      return tenantContext.run({ tenantId: input.tenantId }, () =>
        // One transaction for user + role + credential: an interrupted run can
        // never leave an account that has no credentials and no CLI recovery
        // path (T08 review M1). Nested TenantDb.run calls reuse this tx.
        tenantDb.run(async () => {
          const user = await users.create({
            ...(input.username !== undefined ? { username: input.username } : {}),
            displayName: input.displayName,
            ...(input.phone !== undefined ? { phone: input.phone } : {}),
          });
          await users.assignRole(user.id, input.role);
          await authRepository.createCredentials(user.id, input.passwordHash, input.expiresAt);
          return user.id;
        }),
      );
    },

    async findUser(tenantId, lookup): Promise<{ id: string; roles: AssignableRole[] } | null> {
      return tenantContext.run({ tenantId }, async () => {
        const user =
          lookup.username !== undefined
            ? await users.findByUsername(lookup.username)
            : lookup.phone !== undefined
              ? await users.findByPhone(lookup.phone)
              : null;
        if (user === null) {
          return null;
        }
        // The role decides which password policy (staff vs driver PIN) applies
        // on reset — a phone lookup may still be a staff account.
        return { id: user.id, roles: await users.listRoles(user.id) };
      });
    },

    async hasCredentials(tenantId, userId): Promise<boolean> {
      return tenantContext.run({ tenantId }, async () => {
        return (await authRepository.getCredentials(userId)) !== null;
      });
    },

    async resetPassword(tenantId, userId, passwordHash, expiresAt) {
      return tenantContext.run({ tenantId }, async (): Promise<'ok' | 'missing' | 'stale'> => {
        const current = await authRepository.getCredentials(userId);
        if (current === null) {
          return 'missing';
        }
        const changed = await authRepository.setOneTimePassword(
          userId,
          current.passwordHash,
          passwordHash,
          expiresAt,
        );
        return changed ? 'ok' : 'stale';
      });
    },

    async close(): Promise<void> {
      await pool.end();
    },
  };
}

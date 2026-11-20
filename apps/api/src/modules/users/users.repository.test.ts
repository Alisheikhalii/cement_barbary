import { v7 as uuidv7 } from 'uuid';
import { describe, expect, it } from 'vitest';

import { DomainError } from '../../common/errors/domain-error.js';
import type { TenantContext } from '../../db/tenant-context.js';
import type { TenantDb } from '../../db/tenant-db.js';
import { PiiService } from '../../security/pii/pii-crypto.js';
import { UsersRepository } from './users.repository.js';

/**
 * Docker-free unit tests for UsersRepository's error translation (F1-03 T06,
 * security-review MEDIUM fix). Behavior against a real DB is covered by
 * test/users.int.test.ts.
 */
describe('UsersRepository error translation', () => {
  const pii = new PiiService({
    encKey: Buffer.alloc(32, 1),
    hmacKey: Buffer.alloc(32, 2),
    keyId: 1,
  });

  function repoWithFailingDb(pgErrCode: string): UsersRepository {
    // Simulates drizzle's wrapper: message embeds SQL text and parameter
    // values (this is what must NEVER reach the caller or the logs).
    const failing = {
      run: async () => {
        throw new Error(
          'Failed query: insert into "users" ... params: 09120000001, secret-display-name',
          { cause: { code: pgErrCode } },
        );
      },
    };
    // Minimal TenantContext stub: an active scope, so methods reach tenantDb.
    const tenantContext = {
      require: () => ({ tenantId: uuidv7() }),
    } as unknown as TenantContext;
    return new UsersRepository(failing as unknown as TenantDb, tenantContext, pii);
  }

  it('an untranslated PG error becomes a generic INTERNAL with no SQL/params in it', async () => {
    const repo = repoWithFailingDb('57014'); // e.g. statement timeout
    const err = await repo.findById(uuidv7()).then(
      () => {
        throw new Error('expected a rejection');
      },
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(DomainError);
    expect(err).toMatchObject({ code: 'INTERNAL', statusCode: 500 });
    expect(JSON.stringify(err)).not.toContain('09120000001');
    expect(JSON.stringify(err)).not.toContain('secret-display-name');
    expect(JSON.stringify(err)).not.toContain('insert into');
  });

  it('a translated PG error (23505) becomes CONFLICT, still with no SQL/params', async () => {
    const repo = repoWithFailingDb('23505');
    const err = await repo.create({ displayName: 'x', phone: '09120000001' }).then(
      () => {
        throw new Error('expected a rejection');
      },
      (e: unknown) => e,
    );
    expect(err).toMatchObject({ code: 'CONFLICT', statusCode: 409 });
    expect(JSON.stringify(err)).not.toContain('09120000001');
  });
});

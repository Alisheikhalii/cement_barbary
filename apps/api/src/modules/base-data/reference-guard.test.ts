import { describe, expect, it, vi } from 'vitest';

import { DomainError } from '../../common/errors/domain-error.js';
import type { Tx } from '../../db/tenant-db.js';
import type { AccessScope } from '../../security/authz/access-scope.js';
import { assertNotReferenced, type ReferenceGuard } from './reference-guard.js';

const tx = null as unknown as Tx;
const scope = null as unknown as AccessScope;
const ROW_ID = '0192f0aa-0000-7000-8000-000000000001';

describe('ReferenceGuard (R3)', () => {
  it('passes the transaction, scope and id to the guard and resolves when unused', async () => {
    const isReferenced = vi.fn(async () => false);
    const guard: ReferenceGuard = { isReferenced };

    await expect(assertNotReferenced(guard, tx, scope, ROW_ID)).resolves.toBeUndefined();
    expect(isReferenced).toHaveBeenCalledTimes(1);
    expect(isReferenced).toHaveBeenCalledWith(tx, scope, ROW_ID);
  });

  it('throws the generic 409 IN_USE when a live child still references the row', async () => {
    const guard: ReferenceGuard = { isReferenced: async () => true };

    let caught: unknown;
    try {
      await assertNotReferenced(guard, tx, scope, ROW_ID);
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(DomainError);
    const error = caught as DomainError;
    expect(error.code).toBe('IN_USE');
    expect(error.statusCode).toBe(409);
    expect(error.details).toBeUndefined();
    expect(error.message).not.toContain(ROW_ID);
  });
});

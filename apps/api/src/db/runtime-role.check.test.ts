import type { Pool } from 'pg';
import { describe, expect, it, vi } from 'vitest';

import { RuntimeRoleCheck, RuntimeRoleError } from './runtime-role.check.js';

function runWith(row: unknown): Promise<void> {
  const pool = {
    query: vi.fn().mockResolvedValue({ rows: [row] }),
  } as unknown as Pool;
  return new RuntimeRoleCheck(pool).onApplicationBootstrap();
}

const runtimeRow = {
  role: 'bitabar_app',
  rolsuper: false,
  rolbypassrls: false,
  owns_auth_tables: false,
};

describe('RuntimeRoleCheck (startup)', () => {
  it('accepts the ordinary RLS-bound runtime role', async () => {
    await expect(runWith(runtimeRow)).resolves.toBeUndefined();
  });

  it.each([
    { label: 'superuser', row: { ...runtimeRow, rolsuper: true } },
    { label: 'BYPASSRLS', row: { ...runtimeRow, rolbypassrls: true } },
    { label: 'table owner', row: { ...runtimeRow, owns_auth_tables: true } },
  ])('refuses a $label connection', async ({ row }) => {
    await expect(runWith(row)).rejects.toBeInstanceOf(RuntimeRoleError);
  });

  it('skips the check when the database is unreachable at boot', async () => {
    const pool = {
      query: vi.fn().mockRejectedValue(new Error('connect ECONNREFUSED')),
    } as unknown as Pool;
    const check = new RuntimeRoleCheck(pool);
    await expect(check.onApplicationBootstrap()).resolves.toBeUndefined();
    check.onApplicationShutdown();
  });

  it('retries after boot and stops polling once the role is verified', async () => {
    vi.useFakeTimers();
    try {
      const query = vi
        .fn()
        .mockRejectedValueOnce(new Error('connect ECONNREFUSED'))
        .mockResolvedValue({ rows: [runtimeRow] });
      const check = new RuntimeRoleCheck({ query } as unknown as Pool);
      await check.onApplicationBootstrap();
      expect(query).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(30_000);
      expect(query).toHaveBeenCalledTimes(2);

      // Verified: the timer is gone, so no further queries.
      await vi.advanceTimersByTimeAsync(90_000);
      expect(query).toHaveBeenCalledTimes(2);
      check.onApplicationShutdown();
    } finally {
      vi.useRealTimers();
    }
  });

  it('exits when a retry finds a privileged role', async () => {
    vi.useFakeTimers();
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never);
    try {
      const query = vi
        .fn()
        .mockRejectedValueOnce(new Error('connect ECONNREFUSED'))
        .mockResolvedValue({ rows: [{ ...runtimeRow, rolsuper: true }] });
      const check = new RuntimeRoleCheck({ query } as unknown as Pool);
      await check.onApplicationBootstrap();

      await vi.advanceTimersByTimeAsync(30_000);
      expect(exit).toHaveBeenCalledWith(1);
      expect(query).toHaveBeenCalledTimes(2);
      check.onApplicationShutdown();
    } finally {
      exit.mockRestore();
      vi.useRealTimers();
    }
  });
});

import type { PinoLogger } from 'nestjs-pino';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { TenantContext } from '../../db/tenant-context.js';
import type { AuditRecord } from '../../security/authz/audit-hook.js';
import type { AuditAppendEntry, AuditWriter } from './audit-writer.js';
import { PersistentAuditHook } from './persistent-audit-hook.js';

const TENANT_ID = '00000000-0000-4000-8000-000000000002';
const REASON = 'دلیل محرمانه برای تست';
const IP = '203.0.113.7';

const record: AuditRecord = {
  actor: {
    userId: '00000000-0000-4000-8000-000000000001',
    tenantId: TENANT_ID,
    sessionId: '00000000-0000-4000-8000-000000000003',
  },
  action: 'carrier_membership.write',
  resource: { type: 'handler', id: 'ProbeController.update' },
  reason: REASON,
  outcome: 'success',
  httpStatus: 200,
  requestId: 'req-1',
  ip: IP,
  changes: [
    {
      resourceType: 'user',
      resourceId: '00000000-0000-4000-8000-000000000004',
      before: { status: 'active' },
      after: { status: 'disabled' },
    },
  ],
};

function build(writerAppend: (entry: AuditAppendEntry) => Promise<string>) {
  const warn = vi.fn();
  const logger = { setContext: vi.fn(), warn } as unknown as PinoLogger;
  const tenantContext = {
    current: () => undefined,
    run: async <T>(_scope: unknown, fn: () => Promise<T>): Promise<T> => fn(),
  } as unknown as TenantContext;
  const writer = { append: vi.fn(writerAppend) } as unknown as AuditWriter;
  return { hook: new PersistentAuditHook(tenantContext, writer, logger), warn, writer };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('PersistentAuditHook', () => {
  it('maps the record and the last collected change into an append entry', async () => {
    const { hook, writer } = build(async () => 'row-id');

    await hook.record(record);

    expect(writer.append).toHaveBeenCalledTimes(1);
    expect(writer.append).toHaveBeenCalledWith({
      actorType: 'user',
      actorUserId: record.actor.userId,
      actorSessionId: record.actor.sessionId,
      action: record.action,
      // The row describes the changed resource, not the handler (T05 review
      // HIGH): the snapshot allowlist is keyed by this entity.
      resourceType: 'user',
      resourceId: '00000000-0000-4000-8000-000000000004',
      outcome: 'success',
      httpStatus: 200,
      reason: REASON,
      before: { status: 'active' },
      after: { status: 'disabled' },
      metadata: { handler: 'ProbeController.update' },
      ip: IP,
      requestId: 'req-1',
    });
  });

  it('propagates a success write failure so the business transaction rolls back', async () => {
    const failure = Object.assign(new Error(`insert failed for ${REASON}`), {
      code: '23514',
    });
    const { hook } = build(async () => {
      throw failure;
    });

    await expect(hook.record(record)).rejects.toBe(failure);
  });

  it('never throws and logs only sanitized structural fields for a failed best-effort write', async () => {
    const failure = Object.assign(new Error(`insert failed for ${REASON}`), {
      code: '42501',
      detail: `reason=${REASON}`,
    });
    const { hook, warn } = build(async () => {
      throw failure;
    });

    await expect(
      hook.record({ ...record, outcome: 'failure', httpStatus: 500 }),
    ).resolves.toBeUndefined();

    expect(warn).toHaveBeenCalledTimes(1);
    const payload = warn.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(payload).toMatchObject({
      reqId: 'req-1',
      outcome: 'failure',
      code: 'AUDIT_WRITE_FAILED',
      err: { name: 'Error', sqlState: '42501' },
    });
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain(REASON);
    expect(serialized).not.toContain(IP);
    expect(serialized).not.toContain('detail');
  });

  it('does not wait forever on a best-effort failure row', async () => {
    vi.useFakeTimers();
    const { hook, warn } = build(() => new Promise<string>(() => undefined));

    const pending = hook.record({ ...record, outcome: 'failure', httpStatus: 500 });
    await vi.advanceTimersByTimeAsync(2_000);
    await pending;

    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]?.[0]).toMatchObject({ code: 'AUDIT_WRITE_FAILED' });
  });
});

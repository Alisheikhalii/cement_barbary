import { describe, expect, it } from 'vitest';

import { auditChange, currentAuditChanges, runWithAuditChanges } from './audit-context.js';

const change = {
  resourceType: 'user',
  resourceId: '00000000-0000-4000-8000-000000000001',
  before: { status: 'active' },
  after: { status: 'disabled' },
} as const;

describe('audit context', () => {
  it('collects changes made inside the scope, in order', async () => {
    const result = await runWithAuditChanges(async () => {
      auditChange(change);
      auditChange({ ...change, resourceId: '00000000-0000-4000-8000-000000000002' });
      return 42;
    });
    expect(result.result).toBe(42);
    expect(result.changes).toHaveLength(2);
    expect(result.changes[0]).toMatchObject({
      resourceType: 'user',
      after: { status: 'disabled' },
    });
    // Outside the scope nothing leaks: the store lives only for the callback.
    expect(currentAuditChanges()).toEqual([]);
  });

  it('throws outside a scope instead of silently dropping an audit change', () => {
    expect(() => auditChange(change)).toThrow('AUDIT_CONTEXT_MISSING');
  });

  it('rejects an invalid resource kind or id', async () => {
    await runWithAuditChanges(async () => {
      expect(() => auditChange({ ...change, resourceType: 'User' })).toThrow(
        'AUDIT_CHANGE_INVALID',
      );
      expect(() => auditChange({ ...change, resourceId: 'x'.repeat(129) })).toThrow(
        'AUDIT_CHANGE_INVALID',
      );
    });
  });

  it('caps the number of changes in one audit row', async () => {
    await runWithAuditChanges(async () => {
      for (let index = 0; index < 10; index += 1) {
        auditChange(change);
      }
      expect(currentAuditChanges()).toHaveLength(10);
      expect(() => auditChange(change)).toThrow('AUDIT_CHANGE_LIMIT');
    });
  });
});

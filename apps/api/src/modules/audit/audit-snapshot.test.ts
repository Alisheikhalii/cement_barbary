import { describe, expect, it } from 'vitest';

import { projectAuditSnapshot, toAuditSnapshot } from './audit-snapshot.js';

describe('audit snapshots', () => {
  it('keeps only allowlisted fields and drops unknown ones', () => {
    const snapshot = toAuditSnapshot('user', {
      id: '00000000-0000-4000-8000-000000000001',
      username: 'audit.user',
      displayName: 'Audit User',
      status: 'active',
      updatedAt: new Date('2026-01-02T03:04:05.000Z'),
      // Not allowlisted, and encrypted/ciphertext columns must never appear.
      phoneEnc: Buffer.from([1, 2, 3]),
      phoneHash: Buffer.from([4, 5, 6]),
      nationalIdEnc: Buffer.from([7, 8, 9]),
      passwordHash: 'argon2-hash',
      internalNote: 'not audited',
    });

    expect(snapshot).toEqual({
      id: '00000000-0000-4000-8000-000000000001',
      username: 'audit.user',
      displayName: 'Audit User',
      status: 'active',
      updatedAt: '2026-01-02T03:04:05.000Z',
    });
  });

  it('returns null for an unknown entity, a non-object or an empty projection', () => {
    expect(toAuditSnapshot('unknown_entity', { id: 'x' })).toBeNull();
    expect(toAuditSnapshot('user', 'not-a-row')).toBeNull();
    expect(toAuditSnapshot('user', null)).toBeNull();
    expect(toAuditSnapshot('user', ['a'])).toBeNull();
    expect(toAuditSnapshot('user', { phoneEnc: Buffer.from([1]) })).toBeNull();
  });

  it('drops nested objects and arrays (nothing unreviewed inside)', () => {
    const snapshot = toAuditSnapshot('user_role', {
      userId: '00000000-0000-4000-8000-000000000001',
      roleCode: 'FACTORY_OPERATOR',
      metadata: { admin: true },
      tags: ['a', 'b'],
    });
    expect(snapshot).toEqual({
      userId: '00000000-0000-4000-8000-000000000001',
      roleCode: 'FACTORY_OPERATOR',
    });
  });

  it('re-projection is idempotent', () => {
    const row = { id: '00000000-0000-4000-8000-000000000001', username: 'a.b', status: 'active' };
    expect(projectAuditSnapshot('user', toAuditSnapshot('user', row))).toEqual(
      toAuditSnapshot('user', row),
    );
  });
});

import { describe, expect, it } from 'vitest';

import { DomainError } from './domain-error.js';

const UUID_LIKE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

describe('base-data conflict errors (B5/B6)', () => {
  it('STALE_VERSION is a generic 409 with no details or ids', () => {
    const error = DomainError.staleVersion();
    expect(error.code).toBe('STALE_VERSION');
    expect(error.statusCode).toBe(409);
    expect(error.details).toBeUndefined();
    expect(error.message).not.toMatch(UUID_LIKE);
    expect(error.message).not.toMatch(/\d/);
  });

  it('IN_USE is a generic 409 with no details or child ids', () => {
    const error = DomainError.inUse();
    expect(error.code).toBe('IN_USE');
    expect(error.statusCode).toBe(409);
    expect(error.details).toBeUndefined();
    expect(error.message).not.toMatch(UUID_LIKE);
    expect(error.message).not.toMatch(/\d/);
  });
});

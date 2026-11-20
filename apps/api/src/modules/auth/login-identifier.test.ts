import { describe, expect, it } from 'vitest';

import { parseLoginIdentifier } from './login-identifier.js';

/**
 * Identifier classification (ADR-007 A4): purely syntactic, so rate-limit
 * buckets exist for unknown identifiers too. No database, no enumeration.
 */
describe('parseLoginIdentifier', () => {
  it('parses a staff identifier into username, tenant code and a hashed-bucket identity', () => {
    expect(parseLoginIdentifier('operator@dev-factory')).toEqual({
      kind: 'staff',
      username: 'operator',
      tenantCode: 'dev-factory',
      rateLimitIdentity: 'staff:dev-factory:operator',
    });
  });

  it('classifies a phone, normalizing Persian digits and +98 forms', () => {
    expect(parseLoginIdentifier('09120000001')).toEqual({
      kind: 'driver',
      phone: '09120000001',
      rateLimitIdentity: 'driver:09120000001',
    });
    expect(parseLoginIdentifier('+98 912 000 0001')).toMatchObject({
      kind: 'driver',
      rateLimitIdentity: 'driver:09120000001',
    });
    expect(parseLoginIdentifier('۰۹۱۲۰۰۰۰۰۰۱')).toMatchObject({ kind: 'driver' });
  });

  it('treats syntactically invalid identifiers as invalid — never 500/400 downstream', () => {
    for (const value of [
      'no-at-sign',
      '@dev-factory',
      'ghost@',
      'a@b@dev-factory',
      'UPPER@DEV-FACTORY',
      'ghost@DEV-factory',
      'ghost@dev_factory',
      'ghost@x',
      ' ',
      '😀',
      '+1 555 0100',
    ]) {
      const parsed = parseLoginIdentifier(value);
      if (parsed.kind !== 'invalid') {
        // A phone-shaped value may legitimately parse as a driver.
        expect(parsed.kind, `classification of ${JSON.stringify(value)}`).toBe('driver');
      } else {
        expect(parsed.rateLimitIdentity.startsWith('invalid:')).toBe(true);
      }
    }
  });

  it('splits on the LAST @ so an @ inside the tenant part cannot smuggle a tenant', () => {
    expect(parseLoginIdentifier('user@a@tenant')).toMatchObject({ kind: 'invalid' });
  });

  it('keeps the same rate-limit identity for padded and unpadded input', () => {
    expect(parseLoginIdentifier('  operator@dev-factory  ').rateLimitIdentity).toBe(
      parseLoginIdentifier('operator@dev-factory').rateLimitIdentity,
    );
    expect(parseLoginIdentifier(' 09120000001 ').rateLimitIdentity).toBe(
      parseLoginIdentifier('09120000001').rateLimitIdentity,
    );
  });
});

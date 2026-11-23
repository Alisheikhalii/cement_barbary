import { describe, expect, it } from 'vitest';

import { fingerprintOf } from './fingerprint.js';

/**
 * Fingerprint contract (ADR-010 L9, owner CP4 change 4): covers params + query
 * + body only, canonicalises object key order, keeps array order, and never
 * mixes in headers, the route or the principal (those live in the scope key).
 */
describe('idempotency fingerprint', () => {
  it('is stable across object key order', () => {
    const a = fingerprintOf({ params: {}, query: { b: '2', a: '1' }, body: { z: 1, y: [1, 2] } });
    const b = fingerprintOf({ params: {}, query: { a: '1', b: '2' }, body: { y: [1, 2], z: 1 } });
    expect(a).toEqual(b);
    expect(a).toHaveLength(32);
  });

  it('keeps array order significant', () => {
    const a = fingerprintOf({ params: {}, query: {}, body: { ids: [1, 2, 3] } });
    const b = fingerprintOf({ params: {}, query: {}, body: { ids: [3, 2, 1] } });
    expect(a.equals(b)).toBe(false);
  });

  it('separates params, query and body surfaces', () => {
    const base = fingerprintOf({ params: {}, query: {}, body: { v: 'x' } });
    expect(fingerprintOf({ params: { v: 'x' }, query: {}, body: {} }).equals(base)).toBe(false);
    expect(fingerprintOf({ params: {}, query: { v: 'x' }, body: {} }).equals(base)).toBe(false);
  });

  it('treats a missing body as null but a different value as different', () => {
    const missing = fingerprintOf({ params: {}, query: {}, body: undefined });
    const explicitNull = fingerprintOf({ params: {}, query: {}, body: null });
    expect(missing).toEqual(explicitNull);
    expect(fingerprintOf({ params: {}, query: {}, body: 'x' }).equals(missing)).toBe(false);
  });

  it('does not drop an own __proto__ key (no collision, no pollution)', () => {
    const plain = fingerprintOf({ params: {}, query: {}, body: { value: 'x' } });
    const withProto = fingerprintOf({
      params: {},
      query: {},
      body: JSON.parse('{"value":"x","__proto__":{"a":1}}'),
    });
    expect(withProto.equals(plain)).toBe(false);
    // And the canonicaliser did not pollute Object.prototype.
    expect(({} as { a?: unknown }).a).toBeUndefined();
  });

  it('does not depend on anything outside the payload', () => {
    // Same payload, different key/route/principal → same fingerprint: those
    // are scope-key dimensions, not fingerprint dimensions.
    const payload = { params: { id: '1' }, query: { page: '2' }, body: { v: 'x' } };
    expect(fingerprintOf(payload)).toEqual(fingerprintOf({ ...payload }));
  });
});

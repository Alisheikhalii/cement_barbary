import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  constantTimeEquals,
  generateRefreshToken,
  hashRefreshToken,
  isRefreshTokenShape,
} from './refresh-token.js';

/** Opaque refresh tokens (ADR-007 A8): 256 random bits, hash-at-rest only. */
describe('refresh tokens', () => {
  it('generates 43-char base64url tokens of 32 bytes for a 1000-token sample', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i += 1) {
      const token = generateRefreshToken();
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(Buffer.from(token, 'base64url')).toHaveLength(32);
      seen.add(token);
    }
    expect(seen.size).toBe(1000);
  });

  it('hashes to a deterministic 32-byte SHA-256 and never to the token itself', () => {
    const token = generateRefreshToken();
    const hash = hashRefreshToken(token);
    expect(hash).toHaveLength(32);
    expect(hash.equals(createHash('sha256').update(token, 'utf8').digest())).toBe(true);
    expect(hash.toString('base64url')).not.toBe(token);
    expect(hashRefreshToken(token).equals(hash)).toBe(true);
    expect(hashRefreshToken(generateRefreshToken()).equals(hash)).toBe(false);
  });

  it('accepts only the exact 43-char base64url shape', () => {
    expect(isRefreshTokenShape(generateRefreshToken())).toBe(true);
    for (const bad of [
      '',
      'short',
      'a'.repeat(42),
      'a'.repeat(44),
      '='.repeat(43),
      `${'a'.repeat(42)}+`,
      ' '.repeat(43),
      generateRefreshToken().slice(1),
      `${generateRefreshToken()}=`,
    ]) {
      expect(isRefreshTokenShape(bad), `shape of ${JSON.stringify(bad)}`).toBe(false);
    }
  });

  it('compares hashes in constant time and treats a length mismatch as unequal', () => {
    const hash = hashRefreshToken(generateRefreshToken());
    expect(constantTimeEquals(hash, Buffer.from(hash))).toBe(true);
    expect(constantTimeEquals(hash, hashRefreshToken(generateRefreshToken()))).toBe(false);
    expect(constantTimeEquals(hash, hash.subarray(0, 31))).toBe(false);
    // Empty "hashes" are never equal — a missing value cannot match.
    expect(constantTimeEquals(Buffer.alloc(0), Buffer.alloc(0))).toBe(false);
  });
});

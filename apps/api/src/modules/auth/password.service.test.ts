import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { ARGON2_FLOOR, parseEnv, type AppConfig } from '../../config/env.js';
import { DUMMY_HASH, PasswordService, storedParamsWithinBounds } from './password.service.js';

/** Minimal valid env → AppConfig with the auth defaults (the OWASP floor). */
function makeConfig(overrides: Record<string, string> = {}): AppConfig {
  return parseEnv({
    DATABASE_URL: 'postgresql://bitabar_app:x@localhost:5432/bitabar',
    PII_ENC_KEY: randomBytes(32).toString('base64'),
    PII_HMAC_KEY: randomBytes(32).toString('base64'),
    ...overrides,
  });
}

describe('PasswordService (ADR-007 A1–A3)', () => {
  const service = new PasswordService(makeConfig());

  it('hashes to an Argon2id PHC string embedding the configured parameters', async () => {
    const phc = await service.hash('correct horse battery staple');
    expect(phc.startsWith('$argon2id$v=19$')).toBe(true);
    expect(phc).toContain('m=19456,t=2,p=1'); // the env defaults
  });

  it('round-trips: the right password verifies', async () => {
    const phc = await service.hash('S3cure! passphrase 42');
    await expect(service.verify(phc, 'S3cure! passphrase 42')).resolves.toBe(true);
  });

  it('rejects a wrong password', async () => {
    const phc = await service.hash('S3cure! passphrase 42');
    await expect(service.verify(phc, 'S3cure! passphrase 43')).resolves.toBe(false);
  });

  it('never throws on a malformed stored hash — just false (A3)', async () => {
    await expect(service.verify('not-a-phc-string', 'whatever')).resolves.toBe(false);
    await expect(service.verify('', 'whatever')).resolves.toBe(false);
  });

  it('DUMMY_HASH is a real floor-params Argon2id PHC (A3)', async () => {
    // Drift guard: the baked PHC must carry exactly ARGON2_FLOOR — raising the
    // floor without regenerating DUMMY_HASH would silently create a faster,
    // enumerable dummy path (review finding).
    const floorParams = `m=${ARGON2_FLOOR.memoryKiB},t=${ARGON2_FLOOR.time},p=${ARGON2_FLOOR.parallelism}`;
    expect(DUMMY_HASH.startsWith(`$argon2id$v=19$${floorParams}$`)).toBe(true);
    expect(floorParams).toBe('m=19456,t=2,p=1');
    // The dummy path must do real work: the constant verifies under its
    // documented public input, so it cannot be a cheap decoy.
    await expect(service.verify(DUMMY_HASH, 'bitabar-dummy-input-not-a-secret')).resolves.toBe(
      true,
    );
  });

  it('verifyDummy runs a real verify and always returns false', async () => {
    await expect(service.verifyDummy('anything at all')).resolves.toBe(false);
    // Even the dummy input itself must not "succeed": the login result for an
    // unknown user is a failure, always.
    await expect(service.verifyDummy('bitabar-dummy-input-not-a-secret')).resolves.toBe(false);
  });

  it('verifyDummy with raised parameters still returns false (lazy dummy at raised params)', async () => {
    const raised = new PasswordService(makeConfig({ AUTH_ARGON2_MEMORY_KIB: '32768' }));
    await expect(raised.verifyDummy('anything at all')).resolves.toBe(false);
  });
});

describe('stored-hash parameter bounds (owner T02 fix: no DoS via tampered PHC)', () => {
  // Default config: 19456/2/1 → ceiling 77824/8/4 (ARGON2_STORED_HASH_MAX_FACTOR × config).
  const limits = { memoryKiB: 19456, time: 2, parallelism: 1 };
  const withParams = (params: string): string => DUMMY_HASH.replace('m=19456,t=2,p=1', params);

  it('accepts the floor and anything up to 4× config', () => {
    expect(storedParamsWithinBounds(DUMMY_HASH, limits)).toBe(true);
    expect(storedParamsWithinBounds(withParams('m=77824,t=8,p=4'), limits)).toBe(true);
  });

  it('rejects one notch above the ceiling on any parameter', () => {
    expect(storedParamsWithinBounds(withParams('m=77825,t=2,p=1'), limits)).toBe(false);
    expect(storedParamsWithinBounds(withParams('m=19456,t=9,p=1'), limits)).toBe(false);
    expect(storedParamsWithinBounds(withParams('m=19456,t=2,p=5'), limits)).toBe(false);
  });

  it('rejects malformed or non-argon2id strings without running Argon2', () => {
    expect(storedParamsWithinBounds('not-a-hash', limits)).toBe(false);
    expect(storedParamsWithinBounds('', limits)).toBe(false);
    expect(storedParamsWithinBounds(DUMMY_HASH.replace('$argon2id$', '$argon2i$'), limits)).toBe(
      false,
    );
  });

  it('a stored PHC declaring m=4194304 is rejected fast, without allocating that memory', async () => {
    const evil = withParams('m=4194304,t=2,p=1');
    const started = performance.now();
    await expect(new PasswordService(makeConfig()).verify(evil, 'whatever')).resolves.toBe(false);
    expect(performance.now() - started).toBeLessThan(1000); // in practice: microseconds
  });

  it('normal hashes at config params and at the floor still verify', async () => {
    const service = new PasswordService(makeConfig());
    const phc = await service.hash('Correct-Horse!Battery9');
    await expect(service.verify(phc, 'Correct-Horse!Battery9')).resolves.toBe(true);
    await expect(service.verify(DUMMY_HASH, 'bitabar-dummy-input-not-a-secret')).resolves.toBe(
      true,
    );
  });
});

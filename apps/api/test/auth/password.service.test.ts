import 'reflect-metadata';

import { randomBytes } from 'node:crypto';

import { verify as argon2Verify } from '@node-rs/argon2';
import { describe, expect, it } from 'vitest';

import { parseEnv, type AppConfig } from '../../src/config/env.js';
import { DUMMY_HASH, PasswordService } from '../../src/modules/auth/password.service.js';

/**
 * ATTACK tests for the Argon2id password service (F1-04 T02, ADR-007 A1–A3).
 * Focus: malformed stored hashes, near-miss candidate passwords, and proof
 * that the anti-enumeration DUMMY_HASH is a genuine Argon2id PHC (not a decoy
 * that skips work). Argon2 is memory-hard on purpose — the number of
 * hash/verify runs here is deliberately kept small.
 */

const PASSWORD = 'Correct-Horse!Battery9';
/** Fixed public input behind DUMMY_HASH, as documented in password.service.ts. */
const DUMMY_INPUT = 'bitabar-dummy-input-not-a-secret';

function makeConfig(overrides: Record<string, string> = {}): AppConfig {
  return parseEnv({
    DATABASE_URL: 'postgresql://bitabar_app:x@localhost:5432/bitabar',
    PII_ENC_KEY: randomBytes(32).toString('base64'),
    PII_HMAC_KEY: randomBytes(32).toString('base64'),
    AUTH_TOKEN_SECRET: randomBytes(32).toString('base64'),
    ...overrides,
  });
}

const service = new PasswordService(makeConfig());
/** One shared hash keeps the number of memory-hard runs low. */
const hashPromise = service.hash(PASSWORD);

describe('PasswordService.hash', () => {
  it('returns an $argon2id$ PHC string embedding the configured floor params', async () => {
    const phc = await hashPromise;
    expect(phc.startsWith('$argon2id$')).toBe(true);
    expect(phc).toContain('m=19456,t=2,p=1');
  });

  it('salts every hash: two hashes of the same password differ but both verify', async () => {
    const second = await service.hash(PASSWORD);
    expect(second).not.toBe(await hashPromise);
    await expect(service.verify(second, PASSWORD)).resolves.toBe(true);
  });
});

describe('PasswordService.verify — near-miss candidate passwords', () => {
  it('accepts the original password', async () => {
    await expect(service.verify(await hashPromise, PASSWORD)).resolves.toBe(true);
  });

  it.each([
    ['a completely different password', 'Wr0ng!Passw0rd-xyz'],
    ['a trailing space', `${PASSWORD} `],
    ['a leading space', ` ${PASSWORD}`],
    ['a case flip', 'correct-Horse!Battery9'],
    ['an empty candidate', ''],
  ])('rejects %s', async (_label, candidate) => {
    await expect(service.verify(await hashPromise, candidate)).resolves.toBe(false);
  });

  it('is byte-exact: an NFD candidate does not match an NFC hash', async () => {
    const nfc = 'café-pass-phrase!'; // é = U+00E9 (precomposed)
    const nfd = 'café-pass-phrase!'; // é = e + U+0301 combining accent (NFD)
    const nfcHash = await service.hash(nfc);
    await expect(service.verify(nfcHash, nfc)).resolves.toBe(true);
    await expect(service.verify(nfcHash, nfd)).resolves.toBe(false);
  });
});

describe('PasswordService.verify — malformed stored hashes (A3: false, never throws)', () => {
  it.each([
    ['an empty string', ''],
    ['plain text', 'not-a-hash'],
    ['a truncated PHC', DUMMY_HASH.slice(0, 40)],
    ['params without payload', '$argon2id$v=19$m=19456,t=2,p=1$'],
    ['a bcrypt-shaped string', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'],
    [
      'a doctored $argon2i$ variant of a real hash',
      '$argon2i$v=19$m=19456,t=2,p=1$BGp+/RKj1io3LMWVbbu6oQ$tYYlG4oAjEFm+/v5qEGXOG0/Uo263tUY1vQL4ao3xjI',
    ],
  ])('returns false for %s', async (_label, phc) => {
    await expect(service.verify(phc, PASSWORD)).resolves.toBe(false);
  });

  it.each([[null], [undefined], [42], [{}]])(
    'returns false (no throw) for a non-string stored value: %j',
    async (phc) => {
      await expect(service.verify(phc as unknown as string, PASSWORD)).resolves.toBe(false);
    },
  );
});

describe('DUMMY_HASH / verifyDummy (A3 anti-enumeration)', () => {
  it('is a genuine $argon2id$ PHC at the OWASP floor params', () => {
    expect(DUMMY_HASH.startsWith('$argon2id$')).toBe(true);
    expect(DUMMY_HASH).toContain('m=19456,t=2,p=1');
  });

  it('really verifies against its documented input (not a decoy that skips work)', async () => {
    await expect(argon2Verify(DUMMY_HASH, DUMMY_INPUT)).resolves.toBe(true);
  });

  it.each([
    ['the dummy input itself', DUMMY_INPUT],
    ['an empty candidate', ''],
    ['a real password', PASSWORD],
  ])('verifyDummy always returns false, even for %s', async (_label, candidate) => {
    await expect(service.verifyDummy(candidate)).resolves.toBe(false);
  });
});

describe('raised parameters (ops hardening above the floor)', () => {
  const raised = new PasswordService(makeConfig({ AUTH_ARGON2_MEMORY_KIB: '20480' }));

  it('hash embeds the raised params and still round-trips', async () => {
    const phc = await raised.hash(PASSWORD);
    expect(phc).toContain('m=20480,t=2,p=1');
    await expect(raised.verify(phc, PASSWORD)).resolves.toBe(true);
  });

  it('verifyDummy stays false and functional when the precomputed DUMMY_HASH params no longer match', async () => {
    // The first call lazily builds a matching dummy (one extra hash); both
    // calls must simply return false and never throw.
    await expect(raised.verifyDummy('whatever')).resolves.toBe(false);
    await expect(raised.verifyDummy(DUMMY_INPUT)).resolves.toBe(false);
  });
});

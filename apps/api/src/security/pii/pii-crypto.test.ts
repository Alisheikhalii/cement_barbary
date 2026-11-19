import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { buildAad, PII_FORMAT_VERSION, PiiError, PiiService, type PiiKeys } from './pii-crypto.js';

// Keys are random per run (ADR-006 U17) — nothing in this file is a real secret.
const keys: PiiKeys = {
  encKey: randomBytes(32),
  hmacKey: randomBytes(32),
  keyId: 7,
};

const TENANT_A = randomUUID();
const TENANT_B = randomUUID();
const ROW_A = randomUUID();
const ROW_B = randomUUID();
const PHONE = '09120000001'; // gitleaks-allowlisted synthetic number

function flip(blob: Buffer, index: number): Buffer {
  const copy = Buffer.from(blob);
  copy[index] = (copy[index] ?? 0) ^ 0xff;
  return copy;
}

describe('PiiService encrypt/decrypt', () => {
  const service = new PiiService(keys);
  const aad = buildAad(TENANT_A, 'users.phone', ROW_A);

  it('round-trips a value', () => {
    const blob = service.encrypt(PHONE, aad);
    expect(service.decrypt(blob, aad)).toBe(PHONE);
  });

  it('round-trips an empty string (zero-length ciphertext is valid GCM)', () => {
    const blob = service.encrypt('', aad);
    expect(blob.length).toBe(2 + 12 + 16);
    expect(service.decrypt(blob, aad)).toBe('');
  });

  it('produces different ciphertexts for the same input (random IV)', () => {
    expect(service.encrypt(PHONE, aad).equals(service.encrypt(PHONE, aad))).toBe(false);
  });

  it('writes format version and key_version into the blob header', () => {
    const blob = service.encrypt(PHONE, aad);
    expect(blob[0]).toBe(PII_FORMAT_VERSION);
    expect(blob[1]).toBe(keys.keyId);
    expect(blob.length).toBe(2 + 12 + 16 + Buffer.byteLength(PHONE));
  });

  it('fails when the ciphertext is moved to another tenant (AAD mismatch)', () => {
    const blob = service.encrypt(PHONE, aad);
    expect(() => service.decrypt(blob, buildAad(TENANT_B, 'users.phone', ROW_A))).toThrowError(
      PiiError,
    );
  });

  it('fails when the ciphertext is moved to another column (AAD mismatch)', () => {
    const blob = service.encrypt(PHONE, aad);
    expect(() =>
      service.decrypt(blob, buildAad(TENANT_A, 'users.national_id', ROW_A)),
    ).toThrowError(PiiError);
  });

  it('fails when the ciphertext is moved to another row of the same tenant and column', () => {
    const blob = service.encrypt(PHONE, aad);
    expect(() => service.decrypt(blob, buildAad(TENANT_A, 'users.phone', ROW_B))).toThrowError(
      PiiError,
    );
  });

  it.each([
    ['IV', 3],
    ['tag', 20],
    ['ciphertext', 31],
  ])('fails when one byte of the %s is tampered', (_part, index) => {
    const blob = service.encrypt(PHONE, aad);
    expect(() => service.decrypt(flip(blob, index), aad)).toThrowError(PiiError);
  });

  it('fails on an unknown format version', () => {
    const blob = flip(service.encrypt(PHONE, aad), 0);
    expect(() => service.decrypt(blob, aad)).toThrowError(PiiError);
  });

  it('fails on an unknown key_version', () => {
    const blob = service.encrypt(PHONE, aad);
    blob[1] = keys.keyId === 255 ? 1 : keys.keyId + 1;
    expect(() => service.decrypt(blob, aad)).toThrowError(PiiError);
  });

  it('fails when decrypting with the wrong key (wrong version/key test)', () => {
    const blob = service.encrypt(PHONE, aad);
    const other = new PiiService({ ...keys, encKey: randomBytes(32) });
    expect(() => other.decrypt(blob, aad)).toThrowError(PiiError);
  });

  it('fails on truncated or non-Buffer input', () => {
    const blob = service.encrypt(PHONE, aad);
    expect(() => service.decrypt(blob.subarray(0, 10), aad)).toThrowError(PiiError);
    expect(() => service.decrypt('not-a-buffer' as unknown as Buffer, aad)).toThrowError(PiiError);
  });

  it('never leaks plaintext or detail in decryption errors', () => {
    const blob = flip(service.encrypt(PHONE, aad), 20);
    try {
      service.decrypt(blob, aad);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(PiiError);
      const text = JSON.stringify(error);
      expect(text).not.toContain(PHONE);
      expect((error as Error).message).toBe('PII operation failed');
    }
  });
});

describe('PiiService blindIndex', () => {
  const service = new PiiService(keys);

  it('is deterministic for the same input', () => {
    expect(service.blindIndex('phone', TENANT_A, PHONE)).toEqual(
      service.blindIndex('phone', TENANT_A, PHONE),
    );
  });

  it('differs for another tenant or another field', () => {
    const base = service.blindIndex('phone', TENANT_A, PHONE);
    expect(service.blindIndex('phone', TENANT_B, PHONE).equals(base)).toBe(false);
    expect(service.blindIndex('national_id', TENANT_A, PHONE).equals(base)).toBe(false);
  });

  it('is HMAC-SHA256 keyed with the HMAC key, not plain SHA-256', () => {
    const expected = createHmac('sha256', keys.hmacKey)
      .update(`${TENANT_A}:phone:${PHONE}`, 'utf8')
      .digest();
    expect(service.blindIndex('phone', TENANT_A, PHONE)).toEqual(expected);
    const plain = createHash('sha256').update(`${TENANT_A}:phone:${PHONE}`, 'utf8').digest();
    expect(service.blindIndex('phone', TENANT_A, PHONE).equals(plain)).toBe(false);
  });
});

describe('buildAad validation', () => {
  it('builds a delimiter-safe tenant:column:row string', () => {
    expect(buildAad(TENANT_A, 'users.phone', ROW_A)).toBe(`${TENANT_A}:users.phone:${ROW_A}`);
  });

  it('rejects a non-UUID tenant id or row id', () => {
    for (const bad of ['not-a-uuid', 'tenant:1', '', 42]) {
      expect(() => buildAad(bad as string, 'users.phone', ROW_A)).toThrowError(PiiError);
      expect(() => buildAad(TENANT_A, 'users.phone', bad as string)).toThrowError(PiiError);
    }
  });

  it('rejects a column that is not a plain table.column identifier', () => {
    for (const bad of ['users.phone:x', 'Users.Phone', 'phone', 'users.', 'users.phone-extra']) {
      expect(() => buildAad(TENANT_A, bad, ROW_A)).toThrowError(PiiError);
    }
  });
});

describe('PiiService constructor', () => {
  it('rejects keys that are not 32 bytes', () => {
    expect(() => new PiiService({ ...keys, encKey: randomBytes(16) })).toThrowError(PiiError);
    expect(() => new PiiService({ ...keys, hmacKey: randomBytes(64) })).toThrowError(PiiError);
  });

  it('rejects identical encryption and HMAC keys', () => {
    const same = randomBytes(32);
    expect(() => new PiiService({ encKey: same, hmacKey: same, keyId: 1 })).toThrowError(PiiError);
  });

  it('rejects an out-of-range key id', () => {
    for (const keyId of [0, 256, 1.5]) {
      expect(() => new PiiService({ ...keys, keyId })).toThrowError(PiiError);
    }
  });
});

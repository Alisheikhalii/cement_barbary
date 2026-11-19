import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

import { z } from 'zod';

/**
 * Column encryption for personal data (ADR-006 U7, U8, U10).
 *
 * Blob layout in `bytea`: [format version 1B][key_version 1B][IV 12B][GCM tag 16B][ciphertext].
 * The AAD binds every ciphertext to `tenantId:column:rowId`, so a blob copied
 * to another row, column or tenant fails to decrypt. Every failure raises the
 * same generic PiiError — no plaintext, key material or position detail leaks.
 */

export const PII_FORMAT_VERSION = 1;
export const PII_KEY_LEN = 32;

const KEY_VERSION_LEN = 1;
const IV_LEN = 12;
const TAG_LEN = 16;
const HEADER_LEN = 1 + KEY_VERSION_LEN + IV_LEN + TAG_LEN;

/** Generic failure for any PII crypto problem. Deliberately carries no detail. */
export class PiiError extends Error {
  constructor(message = 'PII operation failed') {
    super(message);
    this.name = 'PiiError';
  }
}

export interface PiiKeys {
  /** 32-byte AES-256-GCM key. */
  encKey: Buffer;
  /** 32-byte HMAC-SHA256 key for blind indexes — MUST differ from encKey. */
  hmacKey: Buffer;
  /** 1–255; written as the key_version byte of every new ciphertext. */
  keyId: number;
}

const uuidSchema = z.uuid();
/** `table.column` — lowercase identifiers only, so ':' stays an unambiguous separator. */
const COLUMN_PATTERN = /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/;

/**
 * AAD string that binds a ciphertext to one tenant, one column and one row.
 * Delimiter-safe: the id parts must be UUIDs (never contain ':') and the
 * column must match `table.column`, so ':' separates unambiguously and no
 * component can inject an extra segment. Rows get their id generated app-side
 * (randomUUID) BEFORE encrypting, so the id is known at write time.
 */
export function buildAad(tenantId: string, column: string, rowId: string): string {
  if (
    !uuidSchema.safeParse(tenantId).success ||
    !uuidSchema.safeParse(rowId).success ||
    !COLUMN_PATTERN.test(column)
  ) {
    throw new PiiError('Invalid PII context');
  }
  return `${tenantId}:${column}:${rowId}`;
}

export class PiiService {
  constructor(private readonly keys: PiiKeys) {
    if (keys.encKey.length !== PII_KEY_LEN || keys.hmacKey.length !== PII_KEY_LEN) {
      throw new PiiError('PII keys must be 32 bytes');
    }
    if (timingSafeEqual(keys.encKey, keys.hmacKey)) {
      throw new PiiError('PII encryption and HMAC keys must differ');
    }
    if (!Number.isInteger(keys.keyId) || keys.keyId < 1 || keys.keyId > 255) {
      throw new PiiError('PII key id must be an integer in 1..255');
    }
  }

  /** Encrypts UTF-8 text; a fresh random IV makes equal inputs produce different blobs. */
  encrypt(plain: string, aad: string): Buffer {
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv('aes-256-gcm', this.keys.encKey, iv);
    cipher.setAAD(Buffer.from(aad, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([Buffer.from([PII_FORMAT_VERSION, this.keys.keyId]), iv, tag, ciphertext]);
  }

  /** Decrypts a blob produced by encrypt(). Any mismatch throws the generic PiiError. */
  decrypt(blob: Buffer, aad: string): string {
    // Zero-length ciphertext is valid GCM (encrypt('') produces a HEADER_LEN
    // blob), so the floor is HEADER_LEN, not HEADER_LEN + 1.
    if (
      !Buffer.isBuffer(blob) ||
      blob.length < HEADER_LEN ||
      blob[0] !== PII_FORMAT_VERSION ||
      blob[1] !== this.keys.keyId
    ) {
      throw new PiiError();
    }
    const iv = blob.subarray(1 + KEY_VERSION_LEN, 1 + KEY_VERSION_LEN + IV_LEN);
    const tag = blob.subarray(1 + KEY_VERSION_LEN + IV_LEN, HEADER_LEN);
    const ciphertext = blob.subarray(HEADER_LEN);
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.keys.encKey, iv);
      decipher.setAAD(Buffer.from(aad, 'utf8'));
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    } catch {
      // GCM auth failure (wrong key, wrong AAD, tampered byte) — same generic error.
      throw new PiiError();
    }
  }

  /**
   * Blind index for exact lookup and uniqueness: HMAC-SHA256 over
   * `tenantId:field:normalized`. Per-tenant by construction, never global;
   * irreversible without the HMAC key (unlike plain SHA-256).
   */
  blindIndex(field: string, tenantId: string, normalized: string): Buffer {
    return createHmac('sha256', this.keys.hmacKey)
      .update(`${tenantId}:${field}:${normalized}`, 'utf8')
      .digest();
  }
}

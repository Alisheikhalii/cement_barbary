import { z } from 'zod';

/**
 * Startup environment validation (Zod). The process must fail fast on invalid
 * config instead of failing later at runtime. Extend this schema per phase;
 * keep it in sync with `.env.example`.
 */

/** Base64 of exactly 32 random bytes (strict alphabet — Buffer.from alone is lenient). */
const piiKeySchema = z
  .string()
  .regex(/^[A-Za-z0-9+/]{43}=$/, 'must be base64 of exactly 32 random bytes')
  .transform((value) => Buffer.from(value, 'base64'));

/**
 * HS256 signing key (ADR-007 A7/A13): base64 of 32–64 random bytes. The
 * strict alphabet + padding check stops Buffer.from's lenient decoding from
 * turning a typo into a shorter key; the byte-length floor is the HS256
 * minimum. Distinctness from both PII keys is enforced in superRefine.
 */
const tokenSecretSchema = z
  .string()
  .regex(/^[A-Za-z0-9+/]+={0,2}$/, 'must be base64')
  .refine((value) => value.length % 4 === 0, 'must be base64')
  .transform((value) => Buffer.from(value, 'base64'))
  .refine((key) => key.length >= 32 && key.length <= 64, 'must decode to 32–64 random bytes');

/**
 * The OWASP Argon2id minimum (ADR-007 A1) — the single source of truth for the
 * floor: the Zod mins/defaults below and the password service's dummy-hash
 * params both derive from it. Raise it only together with DUMMY_HASH (the
 * password-service tests enforce that pairing).
 */
export const ARGON2_FLOOR = { memoryKiB: 19456, time: 2, parallelism: 1 } as const;

/**
 * Stored-hash verify guard (owner T02 fix, ADR-007 A1): a stored PHC string
 * whose declared parameters exceed this multiple of the configured values is
 * rejected WITHOUT running Argon2 — a tampered hash cannot turn verify() into
 * a memory/CPU DoS. Legitimate old hashes stay verifiable: they were written
 * at >= ARGON2_FLOOR, and config can never go below the floor.
 */
export const ARGON2_STORED_HASH_MAX_FACTOR = 4;

const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    API_PORT: z.coerce.number().int().min(1).max(65535).default(4000),
    API_PUBLIC_URL: z.url().default('http://localhost:4000'),
    CORS_ALLOWED_ORIGINS: z.string().min(1).default('http://localhost:3000'),
    // Runtime DB role (bitabar_app) — RLS applies. The migration owner URL
    // (DATABASE_MIGRATION_URL) is deliberately NOT here; only db:migrate reads it.
    DATABASE_URL: z
      .url()
      .refine(
        (u) => u.startsWith('postgres://') || u.startsWith('postgresql://'),
        'must be a postgres URL',
      ),
    DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(100).default(10),
    DATABASE_STATEMENT_TIMEOUT_MS: z.coerce.number().int().min(100).max(120000).default(5000),
    // PII protection (ADR-006 U10): encryption key and blind-index HMAC key are
    // separate secrets; the key id is written as key_version into every ciphertext.
    PII_ENC_KEY: piiKeySchema,
    PII_HMAC_KEY: piiKeySchema,
    PII_KEY_ID: z.coerce.number().int().min(1).max(255).default(1),
    // --- F1-04 authentication (ADR-007) ---
    // A1: Argon2id parameters. The OWASP minimum (ARGON2_FLOOR) is the FLOOR:
    // weaker settings fail startup (owner condition 7).
    AUTH_ARGON2_MEMORY_KIB: z.coerce
      .number()
      .int()
      .min(ARGON2_FLOOR.memoryKiB)
      .max(1048576)
      .default(ARGON2_FLOOR.memoryKiB),
    AUTH_ARGON2_TIME: z.coerce
      .number()
      .int()
      .min(ARGON2_FLOOR.time)
      .max(10)
      .default(ARGON2_FLOOR.time),
    AUTH_ARGON2_PARALLELISM: z.coerce
      .number()
      .int()
      .min(ARGON2_FLOOR.parallelism)
      .max(8)
      .default(ARGON2_FLOOR.parallelism),
    // A2: progressive per-account login delay = base × 2^(failures-1), capped.
    AUTH_LOCK_BASE_SECONDS: z.coerce.number().int().min(1).max(60).default(1),
    AUTH_LOCK_MAX_SECONDS: z.coerce.number().int().min(10).max(3600).default(300),
    // A11: login rate limits (fixed 60 s windows; per-account delay is A2, not these).
    AUTH_RL_LOGIN_IP_PER_MIN: z.coerce.number().int().min(1).max(10000).default(20),
    AUTH_RL_LOGIN_ACCOUNT_PER_MIN: z.coerce.number().int().min(1).max(1000).default(10),
    AUTH_RL_LOGIN_TENANT_PER_MIN: z.coerce.number().int().min(1).max(100000).default(60),
    // A7/A13: HS256 key (base64 of 32–64 random bytes, distinct from PII keys).
    AUTH_TOKEN_SECRET: tokenSecretSchema,
    // A7: access-token lifetime.
    // Owner T05 rule: access tokens stay short (10–15 min); 900 s is the ceiling.
    AUTH_ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(600),
    // A19: operator-set one-time password lifetime.
    AUTH_TEMP_PASSWORD_TTL_HOURS: z.coerce.number().int().min(1).max(168).default(24),
    // --- F1-06 T07 idempotency (ADR-010 L8/L9/L11) ---
    // How long a duplicate claim waits on the unique key before 409. Must stay
    // below the handler cap so the contended request answers before the owner
    // finishes.
    IDEMPOTENCY_LOCK_TIMEOUT_MS: z.coerce.number().int().min(100).max(10000).default(2000),
    // Handler cap (owner C1): the transaction, its rows and the claim are
    // aborted at this point. Also applied as SET LOCAL statement_timeout so the
    // database side stops too (a handler cannot be cancelled from JS).
    IDEMPOTENCY_HANDLER_TIMEOUT_MS: z.coerce.number().int().min(1000).max(30000).default(8000),
    // Stored result lifetime (GUIDELINES §5.4: 24 h).
    IDEMPOTENCY_TTL_HOURS: z.coerce.number().int().min(1).max(168).default(24),
    // --- F1-06 T08 outbox (ADR-010 L12–L14) ---
    // Off by default; production refuses both flags (owner CP5 change 6 / F8).
    OUTBOX_WORKER_ENABLED: z
      .enum(['true', 'false'])
      .default('false')
      .transform((value) => value === 'true'),
    ADAPTER_MOCK_ENABLED: z
      .enum(['true', 'false'])
      .default('false')
      .transform((value) => value === 'true'),
    OUTBOX_POLL_MS: z.coerce.number().int().min(100).max(60000).default(1000),
    OUTBOX_BATCH_SIZE: z.coerce.number().int().min(1).max(100).default(10),
    OUTBOX_LEASE_SECONDS: z.coerce.number().int().min(5).max(600).default(60),
    OUTBOX_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(20).default(5),
    OUTBOX_ADAPTER_TIMEOUT_MS: z.coerce.number().int().min(100).max(30000).default(5000),
    OUTBOX_BACKOFF_BASE_SECONDS: z.coerce.number().int().min(1).max(3600).default(5),
  })
  .superRefine((data, ctx) => {
    // Fields can be un-decoded when their own validation already failed.
    if (!Buffer.isBuffer(data.PII_ENC_KEY) || !Buffer.isBuffer(data.PII_HMAC_KEY)) {
      return;
    }
    if (data.PII_ENC_KEY.equals(data.PII_HMAC_KEY)) {
      ctx.addIssue({
        code: 'custom',
        path: ['PII_HMAC_KEY'],
        message: 'must differ from PII_ENC_KEY',
      });
    }
    if (Buffer.isBuffer(data.AUTH_TOKEN_SECRET)) {
      // A13: one leaked secret must not be useful against two purposes.
      for (const other of ['PII_ENC_KEY', 'PII_HMAC_KEY'] as const) {
        if (data.AUTH_TOKEN_SECRET.equals(data[other])) {
          ctx.addIssue({
            code: 'custom',
            path: ['AUTH_TOKEN_SECRET'],
            message: `must differ from ${other}`,
          });
        }
      }
    }
    if (data.AUTH_LOCK_BASE_SECONDS > data.AUTH_LOCK_MAX_SECONDS) {
      ctx.addIssue({
        code: 'custom',
        path: ['AUTH_LOCK_BASE_SECONDS'],
        message: 'must not exceed AUTH_LOCK_MAX_SECONDS',
      });
    }
    // A duplicate must answer 409 before the claim owner's cap fires, otherwise
    // every contended retry would burn the whole handler window.
    if (data.IDEMPOTENCY_LOCK_TIMEOUT_MS >= data.IDEMPOTENCY_HANDLER_TIMEOUT_MS) {
      ctx.addIssue({
        code: 'custom',
        path: ['IDEMPOTENCY_LOCK_TIMEOUT_MS'],
        message: 'must be below IDEMPOTENCY_HANDLER_TIMEOUT_MS',
      });
    }
    // An adapter call must finish well before its lease expires, otherwise a
    // second worker reclaims the row while the first send is still in flight
    // (owner CP5 change 4).
    if (data.OUTBOX_ADAPTER_TIMEOUT_MS >= data.OUTBOX_LEASE_SECONDS * 1000) {
      ctx.addIssue({
        code: 'custom',
        path: ['OUTBOX_ADAPTER_TIMEOUT_MS'],
        message: 'must be strictly below OUTBOX_LEASE_SECONDS × 1000',
      });
    }
    // A batch is delivered sequentially, so the whole batch must fit inside
    // one lease; otherwise a later row's lease expires before its send starts
    // and a second worker reclaims it mid-flight (T08 review MEDIUM 2).
    if (
      data.OUTBOX_BATCH_SIZE * data.OUTBOX_ADAPTER_TIMEOUT_MS >=
      data.OUTBOX_LEASE_SECONDS * 1000
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['OUTBOX_LEASE_SECONDS'],
        message: 'must exceed OUTBOX_BATCH_SIZE × OUTBOX_ADAPTER_TIMEOUT_MS (seconds × 1000)',
      });
    }
    // The poller and the mock provider are development switches. A production
    // process must not start with either (owner CP5; F8 revisits explicitly).
    if (data.NODE_ENV === 'production') {
      if (data.OUTBOX_WORKER_ENABLED === true) {
        ctx.addIssue({
          code: 'custom',
          path: ['OUTBOX_WORKER_ENABLED'],
          message: 'must be false in production (F8 enables it explicitly)',
        });
      }
      if (data.ADAPTER_MOCK_ENABLED === true) {
        ctx.addIssue({
          code: 'custom',
          path: ['ADAPTER_MOCK_ENABLED'],
          message: 'must be false in production (the mock adapter is refused)',
        });
      }
    }
  });

/** Typed, validated application configuration. Inject via APP_CONFIG. */
export interface AppConfig {
  nodeEnv: 'development' | 'test' | 'production';
  port: number;
  publicUrl: string;
  corsOrigins: string[];
  database: {
    url: string;
    poolMax: number;
    statementTimeoutMs: number;
  };
  pii: {
    /** 32-byte AES-256-GCM key (decoded from base64). */
    encKey: Buffer;
    /** 32-byte HMAC-SHA256 key; guaranteed to differ from encKey. */
    hmacKey: Buffer;
    /** 1–255; the key_version written into every new ciphertext. */
    keyId: number;
  };
  /** F1-04 authentication (ADR-007). All numbers come from env; floors enforced. */
  auth: {
    /** A1: Argon2id parameters, never weaker than the OWASP floor. */
    argon2: {
      memoryKiB: number;
      time: number;
      parallelism: number;
    };
    /** A2: progressive per-account login delay = baseSeconds × 2^(n-1), capped. */
    loginDelay: {
      baseSeconds: number;
      maxSeconds: number;
    };
    /** A11: fixed-window login limits (60 s windows). */
    rateLimit: {
      loginIpPerMinute: number;
      /** Per hashed identifier (unknown identifiers get the same bucket). */
      loginAccountPerMinute: number;
      loginTenantPerMinute: number;
    };
    /** A7: HS256 signing key — 32–64 bytes, distinct from the PII keys. */
    tokenSecret: Buffer;
    /** A7: access-token lifetime. */
    accessTokenTtlSeconds: number;
    /** A19: one-time password lifetime. */
    tempPasswordTtlHours: number;
  };
  /** F1-06 idempotency (ADR-010 L8/L9/L11). */
  idempotency: {
    /** Lock wait on the claim's unique key before 409 IDEMPOTENCY_IN_PROGRESS. */
    lockTimeoutMs: number;
    /** Handler cap; also the transaction's statement_timeout. */
    handlerTimeoutMs: number;
    /** Stored result lifetime. */
    ttlHours: number;
  };
  /** F1-06 outbox worker and adapter (ADR-010 L12–L14). */
  outbox: {
    workerEnabled: boolean;
    mockEnabled: boolean;
    pollMs: number;
    batchSize: number;
    leaseSeconds: number;
    maxAttempts: number;
    adapterTimeoutMs: number;
    backoffBaseSeconds: number;
  };
}

export function parseEnv(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join('; ');
    throw new Error(`Invalid environment configuration — ${issues}`);
  }
  return {
    nodeEnv: parsed.data.NODE_ENV,
    port: parsed.data.API_PORT,
    publicUrl: parsed.data.API_PUBLIC_URL,
    corsOrigins: parsed.data.CORS_ALLOWED_ORIGINS.split(',')
      .map((origin) => origin.trim())
      .filter((origin) => origin.length > 0),
    database: {
      url: parsed.data.DATABASE_URL,
      poolMax: parsed.data.DATABASE_POOL_MAX,
      statementTimeoutMs: parsed.data.DATABASE_STATEMENT_TIMEOUT_MS,
    },
    pii: {
      encKey: parsed.data.PII_ENC_KEY,
      hmacKey: parsed.data.PII_HMAC_KEY,
      keyId: parsed.data.PII_KEY_ID,
    },
    auth: {
      argon2: {
        memoryKiB: parsed.data.AUTH_ARGON2_MEMORY_KIB,
        time: parsed.data.AUTH_ARGON2_TIME,
        parallelism: parsed.data.AUTH_ARGON2_PARALLELISM,
      },
      loginDelay: {
        baseSeconds: parsed.data.AUTH_LOCK_BASE_SECONDS,
        maxSeconds: parsed.data.AUTH_LOCK_MAX_SECONDS,
      },
      rateLimit: {
        loginIpPerMinute: parsed.data.AUTH_RL_LOGIN_IP_PER_MIN,
        loginAccountPerMinute: parsed.data.AUTH_RL_LOGIN_ACCOUNT_PER_MIN,
        loginTenantPerMinute: parsed.data.AUTH_RL_LOGIN_TENANT_PER_MIN,
      },
      tokenSecret: parsed.data.AUTH_TOKEN_SECRET,
      accessTokenTtlSeconds: parsed.data.AUTH_ACCESS_TOKEN_TTL_SECONDS,
      tempPasswordTtlHours: parsed.data.AUTH_TEMP_PASSWORD_TTL_HOURS,
    },
    idempotency: {
      lockTimeoutMs: parsed.data.IDEMPOTENCY_LOCK_TIMEOUT_MS,
      handlerTimeoutMs: parsed.data.IDEMPOTENCY_HANDLER_TIMEOUT_MS,
      ttlHours: parsed.data.IDEMPOTENCY_TTL_HOURS,
    },
    outbox: {
      workerEnabled: parsed.data.OUTBOX_WORKER_ENABLED,
      mockEnabled: parsed.data.ADAPTER_MOCK_ENABLED,
      pollMs: parsed.data.OUTBOX_POLL_MS,
      batchSize: parsed.data.OUTBOX_BATCH_SIZE,
      leaseSeconds: parsed.data.OUTBOX_LEASE_SECONDS,
      maxAttempts: parsed.data.OUTBOX_MAX_ATTEMPTS,
      adapterTimeoutMs: parsed.data.OUTBOX_ADAPTER_TIMEOUT_MS,
      backoffBaseSeconds: parsed.data.OUTBOX_BACKOFF_BASE_SECONDS,
    },
  };
}

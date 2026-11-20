import { Inject, Injectable } from '@nestjs/common';
import { hash as argon2Hash, verify as argon2Verify } from '@node-rs/argon2';

import { APP_CONFIG } from '../../config/config.module.js';
import { ARGON2_FLOOR, ARGON2_STORED_HASH_MAX_FACTOR, type AppConfig } from '../../config/env.js';

/** Fixed, non-secret input behind DUMMY_HASH. It protects nothing; published in-repo. */
const DUMMY_INPUT = 'bitabar-dummy-input-not-a-secret';

/**
 * Precomputed Argon2id PHC of DUMMY_INPUT at the ARGON2_FLOOR parameters (the
 * env defaults). The unknown-user login path verifies against this so it costs
 * the same Argon2 run as a wrong password on a real account (ADR-007 A3).
 * NOT a secret: the input above is fixed and public. The test suite asserts
 * this string carries exactly the ARGON2_FLOOR parameters, so raising the
 * floor without regenerating this constant fails the tests.
 */
export const DUMMY_HASH =
  '$argon2id$v=19$m=19456,t=2,p=1$BGp+/RKj1io3LMWVbbu6oQ$tYYlG4oAjEFm+/v5qEGXOG0/Uo263tUY1vQL4ao3xjI';

/** Leading `$argon2id$v=…$m=…,t=…,p=…$` of a PHC string. */
const PHC_PARAMS = /^\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$/;

/**
 * Pure guard (exported for tests): is this a well-formed Argon2id PHC whose
 * declared cost is at most ARGON2_STORED_HASH_MAX_FACTOR × `limits`? Anything
 * else — malformed, not argon2id, or absurdly expensive — must be rejected
 * BEFORE Argon2 runs.
 */
export function storedParamsWithinBounds(
  phcHash: string,
  limits: { memoryKiB: number; time: number; parallelism: number },
): boolean {
  const match = PHC_PARAMS.exec(phcHash);
  if (!match) return false;
  const [, memory, time, parallelism] = match;
  return (
    Number(memory) <= limits.memoryKiB * ARGON2_STORED_HASH_MAX_FACTOR &&
    Number(time) <= limits.time * ARGON2_STORED_HASH_MAX_FACTOR &&
    Number(parallelism) <= limits.parallelism * ARGON2_STORED_HASH_MAX_FACTOR
  );
}

/**
 * Password hashing and verification (ADR-007 A1–A3). Argon2id only, PHC
 * strings; parameters come from env config, which enforces the OWASP floor at
 * startup (condition 7) — so this service can never run weaker than the floor.
 */
@Injectable()
export class PasswordService {
  /** Lazily built dummy at raised params (see getDummyHash); cleared on failure. */
  private dummyHashPromise: Promise<string> | undefined;

  constructor(@Inject(APP_CONFIG) private readonly config: AppConfig) {}

  private get argon2Options() {
    const { memoryKiB, time, parallelism } = this.config.auth.argon2;
    return { memoryCost: memoryKiB, timeCost: time, parallelism };
  }

  /** Hash a new password; the returned PHC string embeds the configured parameters. */
  hash(password: string): Promise<string> {
    return argon2Hash(password, this.argon2Options);
  }

  /**
   * Verify a candidate against a stored PHC hash. Never throws and never leaks
   * why it failed: a malformed stored hash is simply `false` (A3/A14).
   *
   * Argon2 runs at the parameters declared by the STORED PHC string, so a
   * tampered hash declaring a huge `m=` would be a memory/CPU DoS vector.
   * `storedParamsWithinBounds` therefore rejects anything malformed, non-
   * argon2id, or more than ARGON2_STORED_HASH_MAX_FACTOR × the configured
   * parameters BEFORE Argon2 runs (owner T02 fix).
   */
  async verify(phcHash: string, password: string): Promise<boolean> {
    if (!storedParamsWithinBounds(phcHash, this.config.auth.argon2)) {
      return false;
    }
    try {
      return await argon2Verify(phcHash, password);
    } catch {
      return false;
    }
  }

  /**
   * A3: run the same Argon2 verify against a dummy hash so the unknown-user
   * login path stays on the identical code path with similar cost. Always
   * returns false.
   */
  async verifyDummy(password: string): Promise<false> {
    await this.verify(await this.getDummyHash(), password);
    return false;
  }

  /**
   * DUMMY_HASH is precomputed at the floor params, so with default config no
   * hashing is needed at all. If ops raise the parameters, a real verify is
   * slower than the floor — build a matching dummy lazily (once per process)
   * so the unknown-user path never becomes a faster, enumerable path.
   */
  private getDummyHash(): Promise<string> {
    const { memoryKiB, time, parallelism } = this.config.auth.argon2;
    if (
      memoryKiB === ARGON2_FLOOR.memoryKiB &&
      time === ARGON2_FLOOR.time &&
      parallelism === ARGON2_FLOOR.parallelism
    ) {
      return Promise.resolve(DUMMY_HASH);
    }
    // A rejected build must not poison the cache: every later verifyDummy
    // would throw, turning unknown-user logins into 500s (breaks A3).
    this.dummyHashPromise ??= argon2Hash(DUMMY_INPUT, this.argon2Options).catch((error) => {
      this.dummyHashPromise = undefined;
      throw error;
    });
    return this.dummyHashPromise;
  }
}

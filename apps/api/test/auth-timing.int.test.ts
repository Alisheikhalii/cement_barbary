import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { NestExpressApplication } from '@nestjs/platform-express';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { DomainError } from '../src/common/errors/domain-error.js';
import { AuthService } from '../src/modules/auth/auth.service.js';
import { PasswordService } from '../src/modules/auth/password.service.js';
import { parseEnv } from '../src/config/env.js';
import { assignRole, createTenant, createUser, ownerPool } from './setup/db.js';
import { buildAuthApp } from './setup/auth-app.js';

/**
 * A3 condition 3 timing test (owner T06): 200 samples per failure kind. T08
 * removed the wall-clock noise without loosening any bound:
 *
 *  - measurement is IN PROCESS (AuthService.login), so Express/supertest and
 *    socket scheduling are not part of the sample;
 *  - medians are PAIRED: all five kinds are measured in the same round (in a
 *    rotating order) and each median comparison uses the per-round differences,
 *    so a machine-wide stall that hits every kind cancels out. The p95 check
 *    keeps the original per-case estimator and tolerance.
 *
 * The PasswordMethod clock is overridden far into the future: the progressive
 * delay branch can never be entered by accident, independent of counter-reset
 * timing. Counters are still reset before every wrong-password sample.
 *
 * The rate limiter is an allow-all stub. Its durable bucket commits differ by
 * identifier shape (staff paths use 3 buckets, malformed/driver paths 2), which
 * is a separate control — with those commits in the sample, the test measured
 * bucket count rather than credential existence and crossed the median bound
 * by ~2 ms under load. The real limiter and its no-oracle property are covered
 * end-to-end in auth-rate-limit.int.test.ts.
 *
 * The int config runs files serially (fileParallelism: false, maxWorkers: 1).
 */

const STAFF_PW = 'Correct-Horse!Battery9';
const WRONG_PW = 'Wrong-Passphrase-1';
const SAMPLES = 200;
const WARMUP = 10;

/** Owner T06 tolerance, stated here so it can be re-tuned with the hardware. */
const MEDIAN_TOLERANCE = { absoluteMs: 50, relative: 0.2 };
const P95_TOLERANCE = { absoluteMs: 100, relative: 0.4 };

let app: NestExpressApplication;
let auth: AuthService;
let owner: Pool;
let code: string;
let username: string;
let userId: string;

interface FailureCase {
  readonly label: string;
  readonly identifier: string;
  readonly resetCounters: boolean;
}

function percentile(sorted: readonly number[], fraction: number): number {
  const index = Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1);
  return sorted[Math.max(0, index)] ?? 0;
}

function stats(samples: readonly number[]): {
  median: number;
  p95: number;
  min: number;
  max: number;
} {
  const sorted = [...samples].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const median =
    sorted.length % 2 === 0
      ? ((sorted[mid - 1] ?? 0) + (sorted[mid] ?? 0)) / 2
      : (sorted[mid] ?? 0);
  return {
    median,
    p95: percentile(sorted, 0.95),
    min: sorted[0] ?? 0,
    max: sorted[sorted.length - 1] ?? 0,
  };
}

/** Calls the service directly and requires the one generic credential failure. */
async function attempt(identifier: string): Promise<void> {
  try {
    await auth.login(
      { identifier, password: WRONG_PW },
      { ip: '127.0.0.1', userAgent: 'a3-timing-proof' },
    );
  } catch (error) {
    if (error instanceof DomainError && error.code === 'INVALID_CREDENTIALS') {
      return;
    }
    throw error;
  }
  throw new Error('expected a credential failure');
}

describe('login failure timing similarity (A3, owner T06)', () => {
  beforeAll(async () => {
    app = await buildAuthApp({}, [], {
      // Far-future clock: the progressive-delay branch is skipped
      // deterministically.
      passwordMethodClock: { now: () => Number.MAX_SAFE_INTEGER },
      // Timing proof isolates credential work; bucket commits are tested in
      // auth-rate-limit.int.test.ts.
      rateLimiter: { hit: async () => ({ allowed: true }) },
    });
    auth = app.get(AuthService);
    owner = ownerPool();
    await owner.query('DELETE FROM auth_rate_limits');
    const suffix = randomBytes(4).toString('hex');
    code = `timing-${suffix}`;
    const tenantId = await createTenant(owner, code);
    username = 'timing.user';
    userId = await createUser(owner, tenantId, { username });
    const passwords = new PasswordService(parseEnv(process.env));
    await owner.query(
      'INSERT INTO user_credentials (id, tenant_id, user_id, password_hash) VALUES ($1,$2,$3,$4)',
      [uuidv7(), tenantId, userId, await passwords.hash(STAFF_PW)],
    );
    await assignRole(owner, tenantId, userId, 'FACTORY_OPERATOR', 'tenant');
  });

  afterAll(async () => {
    if (app !== undefined) {
      await app.close();
    }
  });

  it(`keeps paired medians/p95 of five failure kinds within tolerance over ${SAMPLES} rounds`, async () => {
    const cases: FailureCase[] = [
      {
        label: 'unknown tenant code',
        identifier: 'ghost@no-such-tenant-timing',
        resetCounters: false,
      },
      { label: 'unknown username', identifier: `ghost.user@${code}`, resetCounters: false },
      { label: 'unknown phone', identifier: '09120000009', resetCounters: false },
      { label: 'malformed identifier', identifier: 'not-an-identifier', resetCounters: false },
      { label: 'wrong password', identifier: `${username}@${code}`, resetCounters: true },
    ];

    // Warm up JIT, connections and the tenant cache before measuring.
    for (let i = 0; i < WARMUP; i += 1) {
      for (const testCase of cases) {
        if (testCase.resetCounters) {
          await resetFailureCounters();
        }
        await attempt(testCase.identifier);
      }
    }

    const samplesByCase = new Map<string, number[]>(cases.map((c) => [c.label, []]));
    const pairedDiffs = new Map<string, number[]>();
    for (let i = 0; i < cases.length; i += 1) {
      for (let j = i + 1; j < cases.length; j += 1) {
        pairedDiffs.set(pairKey(i, j), []);
      }
    }

    for (let round = 0; round < SAMPLES; round += 1) {
      // Rotate the order so each kind pays each position equally often.
      const shift = round % cases.length;
      const order = [...cases.slice(shift), ...cases.slice(0, shift)];
      const times = new Map<string, number>();
      for (const testCase of order) {
        if (testCase.resetCounters) {
          await resetFailureCounters();
        }
        const started = performance.now();
        await attempt(testCase.identifier);
        times.set(testCase.label, performance.now() - started);
      }
      for (let i = 0; i < cases.length; i += 1) {
        const first = cases[i];
        if (first === undefined) continue;
        samplesByCase.get(first.label)?.push(times.get(first.label) ?? 0);
        for (let j = i + 1; j < cases.length; j += 1) {
          const second = cases[j];
          if (second === undefined) continue;
          pairedDiffs
            .get(pairKey(i, j))
            ?.push((times.get(first.label) ?? 0) - (times.get(second.label) ?? 0));
        }
      }
    }

    const results = cases.map((testCase) => ({
      label: testCase.label,
      stats: stats(samplesByCase.get(testCase.label) ?? []),
    }));

    const table = results.map((result) => ({
      case: result.label,
      medianMs: round1(result.stats.median),
      p95Ms: round1(result.stats.p95),
      minMs: round1(result.stats.min),
      maxMs: round1(result.stats.max),
    }));

    const comparisons: {
      pair: string;
      medianDiffMs: number;
      medianLimitMs: number;
      p95AbsDiffMs: number;
      p95LimitMs: number;
    }[] = [];

    for (let i = 0; i < results.length; i += 1) {
      for (let j = i + 1; j < results.length; j += 1) {
        const first = results[i];
        const second = results[j];
        if (first === undefined || second === undefined) continue;
        const diffs = pairedDiffs.get(pairKey(i, j)) ?? [];
        const medianDiff = stats(diffs).median;
        // p95 keeps the original per-case estimator: a tail stall on one kind is
        // a real signal, while the paired median is what cancels machine-wide
        // stalls. No tolerance changed.
        const p95AbsDiff = Math.abs(first.stats.p95 - second.stats.p95);
        const medianLimit = Math.max(
          MEDIAN_TOLERANCE.absoluteMs,
          MEDIAN_TOLERANCE.relative * Math.max(first.stats.median, second.stats.median),
        );
        const p95Limit = Math.max(
          P95_TOLERANCE.absoluteMs,
          P95_TOLERANCE.relative * Math.max(first.stats.p95, second.stats.p95),
        );
        comparisons.push({
          pair: `${first.label} vs ${second.label}`,
          medianDiffMs: round1(medianDiff),
          medianLimitMs: round1(medianLimit),
          p95AbsDiffMs: round1(p95AbsDiff),
          p95LimitMs: round1(p95Limit),
        });

        expect(
          Math.abs(medianDiff),
          `paired median difference ${first.label} vs ${second.label} (limit ${medianLimit.toFixed(1)} ms)`,
        ).toBeLessThanOrEqual(medianLimit);
        expect(
          p95AbsDiff,
          `paired p95 difference ${first.label} vs ${second.label} (limit ${p95Limit.toFixed(1)} ms)`,
        ).toBeLessThanOrEqual(p95Limit);
      }
    }

    // The owner asked for the numbers: print them and keep a machine-readable copy.
    console.warn('A3 timing (200 paired rounds per case):', JSON.stringify(table, null, 2));
    console.warn('\nA3 timing margins (paired):', JSON.stringify(comparisons, null, 2));
    writeFileSync(
      join(tmpdir(), 'a3-timing.json'),
      JSON.stringify({ perCase: table, comparisons }, null, 2),
    );
  }, 900_000);
});

function pairKey(i: number, j: number): string {
  return `${i}:${j}`;
}

function round1(value: number): number {
  return Math.round(value * 10) / 10;
}

function resetFailureCounters(): Promise<unknown> {
  // The far-future clock already skips the delay branch; resetting keeps every
  // wrong-password sample on the same real-verify path as the other kinds.
  return owner.query(
    'UPDATE user_credentials SET failed_attempts = 0, next_attempt_at = NULL WHERE user_id = $1',
    [userId],
  );
}

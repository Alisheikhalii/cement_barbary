import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { NestExpressApplication } from '@nestjs/platform-express';
import type { Pool } from 'pg';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { PasswordService } from '../src/modules/auth/password.service.js';
import { parseEnv } from '../src/config/env.js';
import { assignRole, createTenant, createUser, ownerPool } from './setup/db.js';
import { buildAuthApp } from './setup/auth-app.js';

/**
 * A3 condition 3 timing test (owner T06): at least 200 samples per failure kind,
 * medians and p95 compared pairwise. The unknown paths run the dummy Argon2;
 * the wrong-password path runs a real verify with counters reset before every
 * sample so the progressive delay never short-circuits. Own file, no parallel
 * files (the int config runs files serially).
 */

const STAFF_PW = 'Correct-Horse!Battery9';
const WRONG_PW = 'Wrong-Passphrase-1';
const SAMPLES = 200;
const WARMUP = 10;

/** Owner T06 tolerance, stated here so it can be re-tuned with the hardware. */
const MEDIAN_TOLERANCE = { absoluteMs: 50, relative: 0.2 };
const P95_TOLERANCE = { absoluteMs: 100, relative: 0.4 };

let app: NestExpressApplication;
let owner: Pool;
let code: string;
let username: string;
let userId: string;

function login(identifier: string): Promise<request.Response> {
  return request(app.getHttpServer())
    .post('/api/v1/auth/login')
    .send({ identifier, password: WRONG_PW });
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

describe('login failure timing similarity (A3, owner T06)', () => {
  beforeAll(async () => {
    app = await buildAuthApp({
      AUTH_RL_LOGIN_IP_PER_MIN: '10000',
      AUTH_RL_LOGIN_ACCOUNT_PER_MIN: '1000',
      AUTH_RL_LOGIN_TENANT_PER_MIN: '100000',
    });
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

  it(`keeps medians/p95 of five failure kinds within tolerance over ${SAMPLES} samples each`, async () => {
    const cases: { label: string; identifier: string; resetCounters: boolean }[] = [
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
    const warmupIdentifiers = cases.map((testCase) => testCase.identifier);
    for (let i = 0; i < WARMUP; i += 1) {
      await login(warmupIdentifiers[i % warmupIdentifiers.length] ?? 'not-an-identifier');
    }

    // Round-robin the samples so drift (thermal, GC, connection churn) hits
    // every case equally instead of the last-measured one.
    const samplesByCase = new Map<string, number[]>(cases.map((c) => [c.label, []]));
    for (let i = 0; i < SAMPLES; i += 1) {
      for (const testCase of cases) {
        if (testCase.resetCounters) {
          await owner.query(
            'UPDATE user_credentials SET failed_attempts = 0, next_attempt_at = NULL WHERE user_id = $1',
            [userId],
          );
        }
        const started = performance.now();
        const res = await login(testCase.identifier);
        const elapsed = performance.now() - started;
        expect(res.status, `${testCase.label} sample ${i}`).toBe(401);
        samplesByCase.get(testCase.label)?.push(elapsed);
      }
    }
    const results = cases.map((testCase) => ({
      label: testCase.label,
      stats: stats(samplesByCase.get(testCase.label) ?? []),
    }));

    const table = results.map((result) => ({
      case: result.label,
      medianMs: Math.round(result.stats.median * 10) / 10,
      p95Ms: Math.round(result.stats.p95 * 10) / 10,
      minMs: Math.round(result.stats.min * 10) / 10,
      maxMs: Math.round(result.stats.max * 10) / 10,
    }));
    // The owner asked for the numbers: print them and keep a machine-readable copy.
    console.warn('A3 timing (200 samples per case):', JSON.stringify(table, null, 2));
    writeFileSync(join(tmpdir(), 'a3-timing.json'), JSON.stringify(table, null, 2));

    for (let i = 0; i < results.length; i += 1) {
      for (let j = i + 1; j < results.length; j += 1) {
        const first = results[i];
        const second = results[j];
        if (first === undefined || second === undefined) {
          continue;
        }
        const a = first.stats;
        const b = second.stats;
        const label = `${first.label} vs ${second.label}`;

        const medianLimit = Math.max(
          MEDIAN_TOLERANCE.absoluteMs,
          MEDIAN_TOLERANCE.relative * Math.max(a.median, b.median),
        );
        expect(
          Math.abs(a.median - b.median),
          `median difference ${label} (limit ${medianLimit.toFixed(1)} ms)`,
        ).toBeLessThanOrEqual(medianLimit);

        const p95Limit = Math.max(
          P95_TOLERANCE.absoluteMs,
          P95_TOLERANCE.relative * Math.max(a.p95, b.p95),
        );
        expect(
          Math.abs(a.p95 - b.p95),
          `p95 difference ${label} (limit ${p95Limit.toFixed(1)} ms)`,
        ).toBeLessThanOrEqual(p95Limit);
      }
    }
  }, 900_000);
});

import { Controller, Module, Post } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import type { Pool } from 'pg';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';
import { z } from 'zod';

import { DomainError } from '../src/common/errors/domain-error.js';
import { Idempotent } from '../src/common/idempotency/idempotent.decorator.js';
import { AuthzFreshness } from '../src/db/authz-freshness.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantDb as the constructor param type for DI
import { TenantDb } from '../src/db/tenant-db.js';
import { sql } from '../src/db/sql.js';
import { TokenService } from '../src/modules/auth/token.service.js';
import { RequirePermission, ZodBody } from '../src/security/authz/decorators.js';
import { sensitiveReasonSchema } from '../src/security/authz/sensitive-reason.js';
import { buildAad } from '../src/security/pii/pii-crypto.js';
import { buildAuthApp } from './setup/auth-app.js';
import { createTenant, createUser, makeAppPool, ownerPool, testPii } from './setup/db.js';

/**
 * Idempotency end-to-end (ADR-010 L8–L11, F1-06 T07) against real PostgreSQL
 * through the real AppModule. The probe module exists only in this test and is
 * refused by the production boot scan. The five owner CP4 changes are covered:
 *   1. statement_timeout aligned with the cap stops the DB side;
 *   2. two concurrent takeovers of one expired row → one execution, one row;
 *   3. lock_timeout (55P03) → 409 + Retry-After: 1, never 500;
 *   4. the fingerprint covers params/query/body only;
 *   5. only successful responses are stored; any thrown error (business 4xx
 *      included) rolls back and a retry re-executes.
 */

const ROUTE_PREFIX = '/api/v1/idempotency-probe';
const ROUTE_OK = 'POST /api/v1/idempotency-probe/ok';
const LOCK_TIMEOUT_MS = 800;
const HANDLER_TIMEOUT_MS = 2500;
const SLOW_HANDLER_MS = 1600;
const REASON = 'دلیل تست ایدمپوتنسی شماره یک';

const executions = {
  ok: 0,
  fail: 0,
  slow: 0,
  dbSlow: 0,
  sensitive: 0,
  sensitiveFail: 0,
  tooSlow: 0,
  void: 0,
};
let slowStarted = false;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

@Controller('idempotency-probe')
class IdempotencyProbeController {
  constructor(private readonly tenantDb: TenantDb) {}

  @RequirePermission('destination.read')
  @Idempotent()
  @Post('ok')
  ok(@ZodBody(z.strictObject({ value: z.string().min(1).max(64) })) body: { value: string }): {
    echo: string;
    n: number;
  } {
    executions.ok += 1;
    return { echo: body.value, n: executions.ok };
  }

  @RequirePermission('destination.read')
  @Idempotent()
  @Post('fail')
  fail(): never {
    executions.fail += 1;
    throw DomainError.badInput({ reason: 'probe_business_error' });
  }

  /** A void handler: the stored body must replay the exact empty response. */
  @RequirePermission('destination.read')
  @Idempotent()
  @Post('void')
  voidResponse(): void {
    executions.void += 1;
  }

  @RequirePermission('destination.read')
  @Idempotent()
  @Post('slow')
  async slow(): Promise<{ slow: true }> {
    executions.slow += 1;
    slowStarted = true;
    await sleep(SLOW_HANDLER_MS);
    return { slow: true };
  }

  @RequirePermission('destination.read')
  @Idempotent()
  @Post('too-slow')
  async tooSlow(): Promise<{ never: true }> {
    executions.tooSlow += 1;
    await sleep(HANDLER_TIMEOUT_MS + 600);
    return { never: true };
  }

  /**
   * A DB-bound handler (owner CP4 change 1): the JS side cannot be cancelled,
   * but `SET LOCAL statement_timeout` aligned with the cap kills the statement.
   */
  @RequirePermission('destination.read')
  @Idempotent()
  @Post('db-slow')
  async dbSlow(): Promise<{ done: true }> {
    executions.dbSlow += 1;
    await this.tenantDb.run((tx) => tx.execute(sql`select pg_sleep(5)`));
    return { done: true };
  }

  @RequirePermission('carrier_membership.write')
  @Idempotent()
  @Post('sensitive')
  sensitive(@ZodBody(z.strictObject({ reason: sensitiveReasonSchema })) body: { reason: string }): {
    ok: true;
    length: number;
  } {
    executions.sensitive += 1;
    return { ok: true, length: body.reason.length };
  }

  /**
   * A sensitive handler that fails: the claim must roll back AND the
   * best-effort failure audit row must survive (this pins the interceptor
   * order — an outer idempotent transaction would swallow that row).
   */
  @RequirePermission('carrier_membership.write')
  @Idempotent()
  @Post('sensitive-fail')
  sensitiveFail(
    @ZodBody(z.strictObject({ reason: sensitiveReasonSchema })) body: { reason: string },
  ): never {
    void body;
    executions.sensitiveFail += 1;
    throw DomainError.badInput({ reason: 'probe_sensitive_business_error' });
  }
}

@Module({ controllers: [IdempotencyProbeController] })
class IdempotencyProbeModule {}

const freshness = {
  read: async (): Promise<{
    userActive: boolean;
    tenantActive: boolean;
    sessionLive: boolean;
    roles: string[];
  }> => ({ userActive: true, tenantActive: true, sessionLive: true, roles: ['FACTORY_OPERATOR'] }),
};

let app: NestExpressApplication;
let owner: Pool;
let tenantA: string;
let tenantB: string;
let userA: string;
let userB: string;
let userOtherTenant: string;
let tokenA: string;
let tokenB: string;
let tokenOtherTenant: string;

function key(): string {
  return uuidv7().replaceAll('-', '');
}

interface ProbeResponse {
  readonly status: number;
  readonly body: Record<string, unknown>;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly text: string;
}

async function send(
  route: string,
  idemKey: string | null,
  body: Record<string, unknown>,
  token: string = tokenA,
): Promise<ProbeResponse> {
  let call = request(app.getHttpServer())
    .post(`${ROUTE_PREFIX}/${route}`)
    .set('authorization', `Bearer ${token}`);
  if (idemKey !== null) {
    call = call.set('idempotency-key', idemKey);
  }
  const response = await call.send(body);
  return {
    status: response.status,
    body: response.body as Record<string, unknown>,
    headers: response.headers as Record<string, string | string[] | undefined>,
    text: response.text,
  };
}

async function keyRows(
  tenantId: string,
  userId: string,
  routeKey: string,
  idemKey: string,
): Promise<
  {
    id: string;
    status: string;
    response_status: number | null;
    response_enc: Buffer | null;
  }[]
> {
  const result = await owner.query<{
    id: string;
    status: string;
    response_status: number | null;
    response_enc: Buffer | null;
  }>(
    `SELECT id, status, response_status, response_enc
       FROM idempotency_keys
      WHERE tenant_id = $1 AND user_id = $2 AND route_key = $3 AND idem_key = $4`,
    [tenantId, userId, routeKey, idemKey],
  );
  return result.rows;
}

function errorCode(body: Record<string, unknown>): unknown {
  return (body as { error?: { code?: unknown } }).error?.code;
}

beforeAll(async () => {
  owner = ownerPool();
  tenantA = await createTenant(owner, `idem-a-${uuidv7().slice(0, 8)}`);
  tenantB = await createTenant(owner, `idem-b-${uuidv7().slice(0, 8)}`);
  userA = await createUser(owner, tenantA, { username: 'idem.a' });
  userB = await createUser(owner, tenantA, { username: 'idem.b' });
  userOtherTenant = await createUser(owner, tenantB, { username: 'idem.other' });

  app = await buildAuthApp(
    {
      IDEMPOTENCY_LOCK_TIMEOUT_MS: String(LOCK_TIMEOUT_MS),
      IDEMPOTENCY_HANDLER_TIMEOUT_MS: String(HANDLER_TIMEOUT_MS),
    },
    [IdempotencyProbeModule],
    {},
    [{ provide: AuthzFreshness, useValue: freshness }],
  );

  const tokens = app.get(TokenService);
  tokenA = await tokens.signAccessToken({
    userId: userA,
    tenantId: tenantA,
    sessionId: uuidv7(),
    roles: ['FACTORY_OPERATOR'],
  });
  tokenB = await tokens.signAccessToken({
    userId: userB,
    tenantId: tenantA,
    sessionId: uuidv7(),
    roles: ['FACTORY_OPERATOR'],
  });
  tokenOtherTenant = await tokens.signAccessToken({
    userId: userOtherTenant,
    tenantId: tenantB,
    sessionId: uuidv7(),
    roles: ['FACTORY_OPERATOR'],
  });
}, 120_000);

beforeEach(() => {
  slowStarted = false;
});

afterAll(async () => {
  await app?.close();
});

describe('idempotency — claim, replay and payload match', () => {
  it('I1: replays the stored status and body and runs the handler once', async () => {
    const idemKey = key();
    const before = executions.ok;
    const first = await send('ok', idemKey, { value: 'alpha' });
    expect(first.status).toBe(201);
    expect(executions.ok).toBe(before + 1);

    const second = await send('ok', idemKey, { value: 'alpha' });
    expect(second.status).toBe(first.status);
    expect(second.text).toBe(first.text);
    expect(second.headers['idempotent-replayed']).toBe('true');
    expect(executions.ok).toBe(before + 1);

    const rows = await keyRows(tenantA, userA, ROUTE_OK, idemKey);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe('completed');
    expect(rows[0]?.response_status).toBe(201);
  });

  it('I2: rejects the same key with a different payload (422, no handler run)', async () => {
    const idemKey = key();
    await send('ok', idemKey, { value: 'beta' });
    const before = executions.ok;

    const reused = await send('ok', idemKey, { value: 'gamma' });
    expect(reused.status).toBe(422);
    expect(errorCode(reused.body)).toBe('IDEMPOTENCY_KEY_REUSED');
    expect(reused.text).not.toContain('beta');
    expect(reused.text).not.toContain('gamma');
    expect(executions.ok).toBe(before);
  });

  it('I3: rejects a missing or malformed key before any claim', async () => {
    const before = executions.ok;
    const missing = await send('ok', null, { value: 'x' });
    expect(missing.status).toBe(400);
    expect(errorCode(missing.body)).toBe('IDEMPOTENCY_KEY_REQUIRED');

    const short = await send('ok', 'too-short', { value: 'x' });
    expect(short.status).toBe(400);
    expect(errorCode(short.body)).toBe('IDEMPOTENCY_KEY_REQUIRED');

    const badChars = await send('ok', 'a'.repeat(15) + '!', { value: 'x' });
    expect(badChars.status).toBe(400);
    expect(executions.ok).toBe(before);
  });

  it('I4: the scope is tenant + user + route; the same key elsewhere is independent', async () => {
    const idemKey = key();
    const first = await send('ok', idemKey, { value: 'scope' });
    expect(first.status).toBe(201);

    // Same tenant, different user.
    const otherUser = await send('ok', idemKey, { value: 'scope' }, tokenB);
    expect(otherUser.status).toBe(201);
    expect(otherUser.headers['idempotent-replayed']).toBeUndefined();

    // Same tenant and user, different route (the failing route still executes).
    const beforeFail = executions.fail;
    const otherRoute = await send('fail', idemKey, {});
    expect(otherRoute.status).toBe(400);
    expect(executions.fail).toBe(beforeFail + 1);

    // Different tenant, same key/route/body.
    const otherTenant = await send('ok', idemKey, { value: 'scope' }, tokenOtherTenant);
    expect(otherTenant.status).toBe(201);
    expect(otherTenant.headers['idempotent-replayed']).toBeUndefined();

    expect(await keyRows(tenantA, userA, ROUTE_OK, idemKey)).toHaveLength(1);
    expect(await keyRows(tenantA, userB, ROUTE_OK, idemKey)).toHaveLength(1);
    expect(await keyRows(tenantB, userOtherTenant, ROUTE_OK, idemKey)).toHaveLength(1);
  });
});

describe('idempotency — concurrency', () => {
  it('I5: 20 parallel identical requests execute the handler exactly once', async () => {
    const idemKey = key();
    const before = executions.ok;
    const responses = await Promise.all(
      Array.from({ length: 20 }, () => send('ok', idemKey, { value: 'parallel' })),
    );

    expect(executions.ok).toBe(before + 1);
    const successful = responses.filter((response) => response.status === 201);
    expect(successful.length).toBeGreaterThanOrEqual(1);
    for (const response of responses) {
      expect([201, 409]).toContain(response.status);
    }
    const bodies = new Set(successful.map((response) => response.text));
    expect(bodies.size).toBe(1);
    expect(responses.some((response) => response.headers['idempotent-replayed'] === 'true')).toBe(
      true,
    );

    const rows = await keyRows(tenantA, userA, ROUTE_OK, idemKey);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe('completed');
  });

  it('I-lock: a duplicate that waits past lock_timeout gets 409 + Retry-After (never 500)', async () => {
    const idemKey = key();
    const before = executions.slow;
    const firstRequest = send('slow', idemKey, {});
    // Wait until the first request claimed the key and is inside its handler.
    for (let i = 0; i < 100 && !slowStarted; i += 1) {
      await sleep(10);
    }
    expect(slowStarted).toBe(true);
    const startedAt = Date.now();

    const duplicate = await send('slow', idemKey, {});
    const waited = Date.now() - startedAt;
    expect(duplicate.status).toBe(409);
    expect(errorCode(duplicate.body)).toBe('IDEMPOTENCY_IN_PROGRESS');
    expect(duplicate.headers['retry-after']).toBe('1');
    expect(waited).toBeGreaterThanOrEqual(LOCK_TIMEOUT_MS - 100);

    const first = await firstRequest;
    expect(first.status).toBe(201);
    expect(executions.slow).toBe(before + 1);
    const rows = await keyRows(tenantA, userA, 'POST /api/v1/idempotency-probe/slow', idemKey);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe('completed');
  }, 20_000);

  it('takeover: two concurrent requests on one expired row run exactly one handler', async () => {
    // The `slow` handler keeps the winning takeover transaction open for
    // 1.6 s, so the second request is guaranteed to reach its CAS UPDATE while
    // the row lock is held — the race is exercised, not merely serialized.
    const routeKey = 'POST /api/v1/idempotency-probe/slow';
    const idemKey = key();
    const expiredId = uuidv7();
    await owner.query(
      `INSERT INTO idempotency_keys
         (id, tenant_id, user_id, route_key, idem_key, fingerprint, status, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'in_progress',
               now() - interval '2 hours', now() - interval '1 minute')`,
      [expiredId, tenantA, userA, routeKey, idemKey, Buffer.alloc(32)],
    );
    const before = executions.slow;

    const winner = send('slow', idemKey, {});
    for (let i = 0; i < 100 && !slowStarted; i += 1) {
      await sleep(10);
    }
    expect(slowStarted).toBe(true);
    // The winner is inside the handler, holding the row lock from its CAS.
    const loser = await send('slow', idemKey, {});
    const first = await winner;

    expect(first.status).toBe(201);
    // The second request's takeover UPDATE waited on the row lock and hit
    // lock_timeout; treating that as a server error would be the bug.
    expect(loser.status).toBe(409);
    expect(errorCode(loser.body)).toBe('IDEMPOTENCY_IN_PROGRESS');
    expect(loser.headers['retry-after']).toBe('1');
    expect(executions.slow).toBe(before + 1);

    const rows = await keyRows(tenantA, userA, routeKey, idemKey);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.id).toBe(expiredId);
    expect(rows[0]?.status).toBe('completed');
    expect(rows[0]?.response_enc).not.toBeNull();
  }, 20_000);
});

describe('idempotency — failures and the handler cap', () => {
  it('I6 / owner change 5: a business 4xx is never stored; a retry re-executes', async () => {
    const idemKey = key();
    const before = executions.fail;
    const first = await send('fail', idemKey, {});
    expect(first.status).toBe(400);
    expect(errorCode(first.body)).toBe('BAD_INPUT');
    const second = await send('fail', idemKey, {});
    expect(second.status).toBe(400);
    expect(executions.fail).toBe(before + 2);
    expect(await keyRows(tenantA, userA, 'POST /api/v1/idempotency-probe/fail', idemKey)).toEqual(
      [],
    );
  });

  it('I7: a JS handler past the cap is 503 with no stored key, and a retry re-executes', async () => {
    const idemKey = key();
    const before = executions.tooSlow;
    const first = await send('too-slow', idemKey, {});
    expect(first.status).toBe(503);
    expect(errorCode(first.body)).toBe('IDEMPOTENCY_TIMEOUT');
    expect(executions.tooSlow).toBe(before + 1);
    expect(
      await keyRows(tenantA, userA, 'POST /api/v1/idempotency-probe/too-slow', idemKey),
    ).toEqual([]);

    const retry = await send('too-slow', idemKey, {});
    expect(retry.status).toBe(503);
    // The key was never stored, so the retry ran the handler again.
    expect(executions.tooSlow).toBe(before + 2);
  }, 20_000);

  it('owner change 1: statement_timeout aligned with the cap stops a DB-bound handler', async () => {
    const idemKey = key();
    const before = executions.dbSlow;
    const startedAt = Date.now();
    const response = await send('db-slow', idemKey, {});
    const elapsed = Date.now() - startedAt;
    expect(response.status).toBe(503);
    expect(errorCode(response.body)).toBe('IDEMPOTENCY_TIMEOUT');
    expect(executions.dbSlow).toBe(before + 1);
    // The proof: pg_sleep(5) would hold the connection ~5 s. Packets only
    // return after ROLLBACK, which queues behind pg_sleep; finishing well
    // before that shows the DB statement itself was cancelled by
    // statement_timeout, not merely abandoned by the JS race.
    expect(elapsed).toBeGreaterThanOrEqual(HANDLER_TIMEOUT_MS - 200);
    expect(elapsed).toBeLessThan(HANDLER_TIMEOUT_MS + 1500);
    expect(
      await keyRows(tenantA, userA, 'POST /api/v1/idempotency-probe/db-slow', idemKey),
    ).toEqual([]);
  }, 20_000);
});

describe('idempotency — storage hygiene and audit', () => {
  it('I9: the stored body is encrypted and bound to its row and tenant', async () => {
    const idemKey = key();
    await send('ok', idemKey, { value: 'secret-value' });
    const rows = await keyRows(tenantA, userA, ROUTE_OK, idemKey);
    expect(rows).toHaveLength(1);
    const row = rows[0];
    if (row?.response_enc === null || row?.response_enc === undefined) {
      throw new Error('response was not stored');
    }
    expect(row.response_enc.toString('utf8')).not.toContain('secret-value');
    expect(
      testPii().decrypt(
        row.response_enc,
        buildAad(tenantA, 'idempotency_keys.response_enc', row.id),
      ),
    ).toContain('secret-value');
    // Another tenant's AAD cannot open it (row/tenant binding).
    expect(() =>
      testPii().decrypt(
        row.response_enc as Buffer,
        buildAad(tenantB, 'idempotency_keys.response_enc', row.id),
      ),
    ).toThrow();
  });

  it('a replayed sensitive request writes no second audit row', async () => {
    const idemKey = key();
    const first = await send('sensitive', idemKey, { reason: REASON });
    expect(first.status).toBe(201);
    const second = await send('sensitive', idemKey, { reason: REASON });
    expect(second.status).toBe(201);
    expect(second.headers['idempotent-replayed']).toBe('true');
    expect(executions.sensitive).toBe(1);

    const rows = await owner.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM audit_logs
        WHERE tenant_id = $1 AND actor_user_id = $2
          AND action = 'carrier_membership.write'
          AND resource_id = 'IdempotencyProbeController.sensitive'`,
      [tenantA, userA],
    );
    expect(rows.rows[0]?.n).toBe(1);
  });

  it('a failing sensitive idempotent handler rolls back the claim and keeps its failure row', async () => {
    const idemKey = key();
    const before = executions.sensitiveFail;
    const response = await send('sensitive-fail', idemKey, { reason: REASON });
    expect(response.status).toBe(400);
    expect(executions.sensitiveFail).toBe(before + 1);
    expect(
      await keyRows(tenantA, userA, 'POST /api/v1/idempotency-probe/sensitive-fail', idemKey),
    ).toEqual([]);

    // This row pins the interceptor order: if the idempotency transaction were
    // outer to the sensitive-audit one, the best-effort failure row would be
    // written into a transaction that then rolled back, and this count is 0.
    const rows = await owner.query<{ n: number; outcome: string; http_status: number }>(
      `SELECT count(*)::int AS n, min(outcome) AS outcome, min(http_status)::int AS http_status
         FROM audit_logs
        WHERE tenant_id = $1 AND actor_user_id = $2
          AND action = 'carrier_membership.write'
          AND resource_id = 'IdempotencyProbeController.sensitiveFail'`,
      [tenantA, userA],
    );
    expect(rows.rows[0]).toMatchObject({ n: 1, outcome: 'failure', http_status: 400 });

    // The claim is gone, so a retry runs the handler again.
    await send('sensitive-fail', idemKey, { reason: REASON });
    expect(executions.sensitiveFail).toBe(before + 2);
  });

  it('replays a void handler with the identical empty body', async () => {
    const idemKey = key();
    const before = executions.void;
    const first = await send('void', idemKey, {});
    expect(first.status).toBe(201);
    const second = await send('void', idemKey, {});
    expect(second.status).toBe(201);
    expect(second.headers['idempotent-replayed']).toBe('true');
    expect(second.text).toBe(first.text);
    expect(second.text).toBe('{}');
    expect(executions.void).toBe(before + 1);
  });
});

describe('idempotency — DB invariants from 0014', () => {
  it('has exactly one permissive tenant policy and one restrictive delete policy', async () => {
    const rows = await owner.query<{ permissive: boolean; cmd: string }>(
      `SELECT p.polpermissive AS permissive, p.polcmd AS cmd
         FROM pg_policy p
        WHERE p.polrelid = 'public.idempotency_keys'::regclass
        ORDER BY p.polcmd`,
    );
    expect(rows.rows).toEqual([
      { permissive: true, cmd: '*' },
      { permissive: false, cmd: 'd' },
    ]);
  });

  it('lets the runtime role delete only an expired row (never a live claim)', async () => {
    const liveId = uuidv7();
    const expiredId = uuidv7();
    const liveKey = key();
    const expiredKey = key();
    await owner.query(
      `INSERT INTO idempotency_keys
         (id, tenant_id, user_id, route_key, idem_key, fingerprint, status, created_at, expires_at)
       VALUES
         ($1, $3, $4, $5, $6, $8, 'in_progress', now(), now() + interval '1 hour'),
         ($2, $3, $4, $5, $7, $8, 'in_progress',
          now() - interval '2 hours', now() - interval '1 minute')`,
      [liveId, expiredId, tenantA, userA, ROUTE_OK, liveKey, expiredKey, Buffer.alloc(32)],
    );

    const runtime = makeAppPool();
    const client = await runtime.connect();
    try {
      await client.query('BEGIN');
      await client.query("select set_config('app.tenant_id', $1, true)", [tenantA]);
      const live = await client.query('DELETE FROM idempotency_keys WHERE id = $1', [liveId]);
      const expired = await client.query('DELETE FROM idempotency_keys WHERE id = $1', [expiredId]);
      await client.query('COMMIT');
      expect(live.rowCount).toBe(0);
      expect(expired.rowCount).toBe(1);
    } finally {
      client.release();
      await runtime.end();
    }

    const remaining = await owner.query('SELECT id FROM idempotency_keys WHERE id = $1', [liveId]);
    expect(remaining.rows).toHaveLength(1);
    await owner.query('DELETE FROM idempotency_keys WHERE id = $1', [liveId]);
  });
});

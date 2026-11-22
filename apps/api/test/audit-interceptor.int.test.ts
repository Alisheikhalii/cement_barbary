import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { PinoLogger } from 'nestjs-pino';
import type { Pool } from 'pg';
import { from, lastValueFrom } from 'rxjs';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { v7 as uuidv7 } from 'uuid';
import { z } from 'zod';

import { DomainError } from '../src/common/errors/domain-error.js';
import { AuditStore } from '../src/db/audit-store.js';
import * as schema from '../src/db/schema/index.js';
import { TenantContext } from '../src/db/tenant-context.js';
import { TenantDb } from '../src/db/tenant-db.js';
import { auditChange } from '../src/modules/audit/audit-context.js';
import { AuditWriter } from '../src/modules/audit/audit-writer.js';
import { PersistentAuditHook } from '../src/modules/audit/persistent-audit-hook.js';
import { AccessScope } from '../src/security/authz/access-scope.js';
import { BODY_SCHEMA_KEY, REQUIRE_PERMISSION_KEY } from '../src/security/authz/decorators.js';
import { createVerifiedPrincipal } from '../src/security/authz/principal.js';
import { SensitiveAuditInterceptor } from '../src/security/authz/sensitive-audit.interceptor.js';
import { createTenant, createUser, makeAppPool, ownerPool, testPii } from './setup/db.js';

/**
 * The real interceptor pipeline against PostgreSQL (F1-06 T05, review findings
 * HIGH + MEDIUM): the handler runs inside the interceptor's transaction, the
 * success row commits with the business write (and carries the captured
 * before/after), and a handler failure rolls the business write back and leaves
 * exactly one best-effort `failure` row in a fresh transaction.
 */

const ACTION = 'carrier_membership.write';
const REQUEST_ID = 'req-interceptor-1';

describe('sensitive audit interceptor (integration)', () => {
  const ctx = new TenantContext();
  let app: Pool;
  let tenantDb: TenantDb;
  let tenantId: string;
  let userId: string;
  let sessionId: string;
  let interceptor: SensitiveAuditInterceptor;

  beforeAll(async () => {
    const owner = ownerPool();
    tenantId = await createTenant(owner, `audit-i-${uuidv7().slice(0, 8)}`);
    userId = await createUser(owner, tenantId, { username: 'audit.interceptor' });
    sessionId = uuidv7();
    app = makeAppPool();
    tenantDb = new TenantDb(drizzle(app, { schema }));
    const writer = new AuditWriter(ctx, testPii(), new AuditStore(tenantDb));
    const hook = new PersistentAuditHook(ctx, writer, {
      setContext: vi.fn(),
      warn: vi.fn(),
    } as unknown as PinoLogger);
    interceptor = new SensitiveAuditInterceptor(new Reflector(), hook, ctx, tenantDb, {
      setContext: vi.fn(),
      warn: vi.fn(),
    } as unknown as PinoLogger);
  });

  afterAll(async () => {
    await app.end();
  });

  function contextFor(body: unknown): ExecutionContext {
    const handler = function probeHandler(): void {
      // metadata carrier only
    };
    Reflect.defineMetadata(REQUIRE_PERMISSION_KEY, ACTION, handler);
    Reflect.defineMetadata(BODY_SCHEMA_KEY, z.object({ reason: z.string() }), handler);
    const principal = createVerifiedPrincipal({
      userId,
      tenantId,
      sessionId,
      roles: ['FACTORY_OPERATOR'],
    });
    const scope = AccessScope.forPermission(principal, ACTION);
    const request = {
      id: REQUEST_ID,
      ip: '203.0.113.20',
      body,
      authz: { principal, scope },
    };
    return {
      getHandler: () => handler,
      getClass: () =>
        class ProbeController {
          readonly probe = true;
        },
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({ statusCode: 200, headersSent: false }),
      }),
    } as unknown as ExecutionContext;
  }

  async function auditRows(requestId: string) {
    return (
      await ownerPool().query<{
        outcome: string;
        http_status: number | null;
        resource_type: string;
        resource_id: string | null;
        before: unknown;
        after: unknown;
        metadata: unknown;
      }>(
        `SELECT outcome, http_status, resource_type, resource_id, before, after, metadata
           FROM audit_logs WHERE tenant_id = $1 AND request_id = $2`,
        [tenantId, requestId],
      )
    ).rows;
  }

  it('commits the success row with the handler and stores the captured snapshots', async () => {
    const target = uuidv7();
    const next = {
      handle: () =>
        from(
          (async () => {
            // Runs in the interceptor's transaction (nested TenantDb.run).
            await tenantDb.run(async (tx) => {
              await tx.execute(sql`
                INSERT INTO users (id, tenant_id, username, display_name)
                VALUES (${target}, ${tenantId}, ${`probe.${uuidv7().slice(0, 8)}`}, 'Snapshot Probe')
              `);
            });
            auditChange({
              resourceType: 'user',
              resourceId: target,
              before: { id: target, status: 'active', phoneEnc: Buffer.from([1, 2, 3]) },
              after: { id: target, status: 'disabled' },
            });
            return { ok: true };
          })(),
        ),
    };

    await expect(
      lastValueFrom(interceptor.intercept(contextFor({ reason: 'snapshot test' }), next)),
    ).resolves.toEqual({ ok: true });

    const rows = await auditRows(REQUEST_ID);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      outcome: 'success',
      http_status: 200,
      resource_type: 'user',
      resource_id: target,
      before: { id: target, status: 'active' },
      after: { id: target, status: 'disabled' },
      metadata: { handler: 'ProbeController.probeHandler' },
    });
  });

  it('rolls the business write back and writes one failure row when the handler throws', async () => {
    const requestId = 'req-interceptor-failure';
    const target = uuidv7();
    const username = `rollback.${uuidv7().slice(0, 8)}`;
    const context = contextFor({ reason: 'failure test' });
    // The success test used a fixed request id; this one needs its own.
    const request = context.switchToHttp().getRequest() as { id: string };
    request.id = requestId;
    const next = {
      handle: () =>
        from(
          (async () => {
            await tenantDb.run(async (tx) => {
              await tx.execute(sql`
                INSERT INTO users (id, tenant_id, username, display_name)
                VALUES (${target}, ${tenantId}, ${username}, 'Rollback Probe')
              `);
            });
            throw DomainError.internal();
          })(),
        ),
    };

    await expect(lastValueFrom(interceptor.intercept(context, next))).rejects.toBeInstanceOf(
      DomainError,
    );

    const business = await ownerPool().query(
      'SELECT count(*)::int AS n FROM users WHERE tenant_id = $1 AND username = $2',
      [tenantId, username],
    );
    expect(business.rows[0]?.n).toBe(0);

    const rows = await auditRows(requestId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      outcome: 'failure',
      http_status: 500,
      before: null,
      after: null,
    });
  });

  it('fails closed when the success audit write is invalid: no business row, no audit row', async () => {
    const requestId = 'req-interceptor-invalid';
    const target = uuidv7();
    const username = `failclosed.${uuidv7().slice(0, 8)}`;
    const context = contextFor({ reason: 'x'.repeat(501) });
    const request = context.switchToHttp().getRequest() as { id: string };
    request.id = requestId;
    const next = {
      handle: () =>
        from(
          (async () => {
            await tenantDb.run(async (tx) => {
              await tx.execute(sql`
                INSERT INTO users (id, tenant_id, username, display_name)
                VALUES (${target}, ${tenantId}, ${username}, 'Fail Closed Probe')
              `);
            });
            return { ok: true };
          })(),
        ),
    };

    await expect(lastValueFrom(interceptor.intercept(context, next))).rejects.toThrow(
      'AUDIT_ENTRY_INVALID',
    );

    const business = await ownerPool().query(
      'SELECT count(*)::int AS n FROM users WHERE tenant_id = $1 AND username = $2',
      [tenantId, username],
    );
    expect(business.rows[0]?.n).toBe(0);
    // The best-effort failure row uses the same oversized reason, so it is
    // rejected too (and logged); nothing is stored.
    expect(await auditRows(requestId)).toEqual([]);
  });
});

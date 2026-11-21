import 'reflect-metadata';

import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { PinoLogger } from 'nestjs-pino';
import { describe, expect, it, vi } from 'vitest';

import { DomainError } from '../../common/errors/domain-error.js';
import type { AuthzFreshness } from '../../db/authz-freshness.js';
import { AuthorizationGuard } from './authorization.guard.js';
import { can } from './can.js';
import { IS_PUBLIC_KEY, REQUIRE_PERMISSION_KEY } from './decorators.js';
import { createPrincipal } from './principal.js';

const freshnessRead = vi.fn();
const freshness = { read: freshnessRead } as unknown as AuthzFreshness;

/**
 * CP1 SA-03: a guard denial is logged server-side with the request id and a
 * stable reason code only. Never the permission name, the role list or any
 * user-supplied text; the client receives the generic 403.
 */
function contextFor(handler: () => void, request: Record<string, unknown>): ExecutionContext {
  return {
    getHandler: () => handler,
    getClass: () =>
      class ProbeController {
        readonly probe = true;
      },
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

describe('AuthorizationGuard denial logging', () => {
  it('logs only the request id and reason code', async () => {
    const warn = vi.fn();
    const logger = { setContext: vi.fn(), warn } as unknown as PinoLogger;
    const guard = new AuthorizationGuard(new Reflector(), { nodeEnv: 'test' }, freshness, logger);

    const handler = (): void => undefined;
    Reflect.defineMetadata(REQUIRE_PERMISSION_KEY, 'destination.read', handler);
    const request: Record<string, unknown> = {
      id: 'req-7',
      method: 'GET',
      originalUrl: '/api/v1/probe',
      auth: {
        sub: '00000000-0000-4000-8000-000000000001',
        tid: '00000000-0000-4000-8000-000000000002',
        sid: '00000000-0000-4000-8000-000000000003',
        roles: ['DRIVER'],
      },
    };

    const caught: unknown = await guard.canActivate(contextFor(handler, request)).then(
      () => null,
      (error: unknown) => error,
    );

    expect(caught).toBeInstanceOf(DomainError);
    expect((caught as DomainError).statusCode).toBe(403);
    expect((caught as DomainError).code).toBe('FORBIDDEN');
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      { reqId: 'req-7', reasonCode: 'AUTHZ_PERMISSION_DENIED' },
      'authorization denied',
    );
    // T05: a denied request never receives a scope context.
    expect('authz' in request).toBe(false);

    const logged = JSON.stringify(warn.mock.calls[0]?.[0]);
    expect(logged).not.toContain('destination.read');
    expect(logged).not.toContain('DRIVER');
  });

  it('uses the marker-count reason code for an unmarked route', async () => {
    const warn = vi.fn();
    const logger = { setContext: vi.fn(), warn } as unknown as PinoLogger;
    const guard = new AuthorizationGuard(new Reflector(), { nodeEnv: 'test' }, freshness, logger);
    const handler = (): void => undefined;
    const request: Record<string, unknown> = {
      id: 'req-8',
      method: 'GET',
      originalUrl: '/api/v1/probe',
      auth: {
        sub: '00000000-0000-4000-8000-000000000001',
        tid: '00000000-0000-4000-8000-000000000002',
        sid: '00000000-0000-4000-8000-000000000003',
        roles: ['FACTORY_OPERATOR'],
      },
    };

    await expect(guard.canActivate(contextFor(handler, request))).rejects.toThrow(DomainError);
    expect(warn).toHaveBeenCalledWith(
      { reqId: 'req-8', reasonCode: 'AUTHZ_MARKER_COUNT' },
      'authorization denied',
    );
  });

  it('accepts the unprefixed public form only outside production', async () => {
    const handler = (): void => undefined;
    Reflect.defineMetadata(IS_PUBLIC_KEY, true, handler);
    const request: Record<string, unknown> = {
      id: 'req-9',
      method: 'POST',
      originalUrl: '/auth/login',
    };

    const testGuard = new AuthorizationGuard(new Reflector(), { nodeEnv: 'test' }, freshness, {
      setContext: vi.fn(),
      warn: vi.fn(),
    } as unknown as PinoLogger);
    await expect(testGuard.canActivate(contextFor(handler, request))).resolves.toBe(true);

    const productionGuard = new AuthorizationGuard(
      new Reflector(),
      { nodeEnv: 'production' },
      freshness,
      {
        setContext: vi.fn(),
        warn: vi.fn(),
      } as unknown as PinoLogger,
    );
    await expect(productionGuard.canActivate(contextFor(handler, request))).rejects.toThrow(
      DomainError,
    );

    request.originalUrl = '/api/v1/auth/login';
    await expect(productionGuard.canActivate(contextFor(handler, request))).resolves.toBe(true);
  });
});

describe('AuthorizationGuard sensitive freshness', () => {
  const request: Record<string, unknown> = {
    id: 'req-sensitive',
    method: 'POST',
    originalUrl: '/api/v1/authz-freshness/probe',
    auth: {
      sub: '00000000-0000-4000-8000-000000000001',
      tid: '00000000-0000-4000-8000-000000000002',
      sid: '00000000-0000-4000-8000-000000000003',
      roles: ['FACTORY_OPERATOR'],
    },
  };

  function sensitiveGuard(): AuthorizationGuard {
    return new AuthorizationGuard(new Reflector(), { nodeEnv: 'test' }, freshness, {
      setContext: vi.fn(),
      warn: vi.fn(),
    } as unknown as PinoLogger);
  }

  function contextForSensitive(): ExecutionContext {
    const handler = (): void => undefined;
    Reflect.defineMetadata(REQUIRE_PERMISSION_KEY, 'carrier_membership.write', handler);
    return contextFor(handler, request);
  }

  it('intersects token and DB roles and passes when both grant', async () => {
    freshnessRead.mockResolvedValueOnce({
      userActive: true,
      tenantActive: true,
      sessionLive: true,
      roles: ['FACTORY_OPERATOR'],
    });
    await expect(sensitiveGuard().canActivate(contextForSensitive())).resolves.toBe(true);
    expect(freshnessRead).toHaveBeenCalledWith({
      tenantId: '00000000-0000-4000-8000-000000000002',
      userId: '00000000-0000-4000-8000-000000000001',
      sessionId: '00000000-0000-4000-8000-000000000003',
    });
    // T05: the successful pass attaches a scope built from the effective
    // (token∩DB) principal and the permission's tenant scope.
    const context = request.authz as { scope?: { tenantId?: string } } | undefined;
    expect(context?.scope?.tenantId).toBe('00000000-0000-4000-8000-000000000002');
  });

  it('denies a token role the DB no longer has', async () => {
    freshnessRead.mockResolvedValueOnce({
      userActive: true,
      tenantActive: true,
      sessionLive: true,
      roles: [],
    });
    await expect(sensitiveGuard().canActivate(contextForSensitive())).rejects.toMatchObject({
      code: 'FORBIDDEN',
    });
  });

  it('denies a non-intersecting token role even when that role would grant', async () => {
    // Token says FACTORY_OPERATOR; the DB says this user is only CARRIER_ADMIN.
    // FACTORY_OPERATOR grants carrier_membership.write and CARRIER_ADMIN does
    // not, so a token-only decision would pass. The 403 can therefore only come
    // from the token∩DB intersection inside the sensitive branch.
    const tokenOnly = createPrincipal({
      userId: '00000000-0000-4000-8000-000000000001',
      tenantId: '00000000-0000-4000-8000-000000000002',
      sessionId: '00000000-0000-4000-8000-000000000003',
      roles: ['FACTORY_OPERATOR'],
    });
    const dbOnly = createPrincipal({
      userId: tokenOnly.userId,
      tenantId: tokenOnly.tenantId,
      sessionId: tokenOnly.sessionId,
      roles: ['CARRIER_ADMIN'],
    });
    expect(can(tokenOnly, 'carrier_membership.write')).toBe(true);
    expect(can(dbOnly, 'carrier_membership.write')).toBe(false);

    freshnessRead.mockClear();
    freshnessRead.mockResolvedValueOnce({
      userActive: true,
      tenantActive: true,
      sessionLive: true,
      roles: ['CARRIER_ADMIN'],
    });
    await expect(sensitiveGuard().canActivate(contextForSensitive())).rejects.toMatchObject({
      code: 'FORBIDDEN',
      statusCode: 403,
    });
    expect(freshnessRead).toHaveBeenCalledTimes(1);
  });

  it('answers the generic 401 for a dead session or inactive account/tenant', async () => {
    for (const state of [
      { userActive: true, tenantActive: true, sessionLive: false, roles: ['FACTORY_OPERATOR'] },
      { userActive: false, tenantActive: true, sessionLive: true, roles: ['FACTORY_OPERATOR'] },
      { userActive: true, tenantActive: false, sessionLive: true, roles: ['FACTORY_OPERATOR'] },
    ]) {
      freshnessRead.mockResolvedValueOnce(state);
      await expect(sensitiveGuard().canActivate(contextForSensitive())).rejects.toMatchObject({
        code: 'UNAUTHORIZED',
        statusCode: 401,
      });
    }
  });
});

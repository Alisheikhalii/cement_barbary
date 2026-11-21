import 'reflect-metadata';

import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { PinoLogger } from 'nestjs-pino';
import { describe, expect, it, vi } from 'vitest';

import { DomainError } from '../../common/errors/domain-error.js';
import { AuthorizationGuard } from './authorization.guard.js';
import { REQUIRE_PERMISSION_KEY } from './decorators.js';

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
  it('logs only the request id and reason code', () => {
    const warn = vi.fn();
    const logger = { setContext: vi.fn(), warn } as unknown as PinoLogger;
    const guard = new AuthorizationGuard(new Reflector(), logger);

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

    let caught: unknown;
    try {
      guard.canActivate(contextFor(handler, request));
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(DomainError);
    expect((caught as DomainError).statusCode).toBe(403);
    expect((caught as DomainError).code).toBe('FORBIDDEN');
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      { reqId: 'req-7', reasonCode: 'AUTHZ_PERMISSION_DENIED' },
      'authorization denied',
    );

    const logged = JSON.stringify(warn.mock.calls[0]?.[0]);
    expect(logged).not.toContain('destination.read');
    expect(logged).not.toContain('DRIVER');
  });

  it('uses the marker-count reason code for an unmarked route', () => {
    const warn = vi.fn();
    const logger = { setContext: vi.fn(), warn } as unknown as PinoLogger;
    const guard = new AuthorizationGuard(new Reflector(), logger);
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

    expect(() => guard.canActivate(contextFor(handler, request))).toThrow(DomainError);
    expect(warn).toHaveBeenCalledWith(
      { reqId: 'req-8', reasonCode: 'AUTHZ_MARKER_COUNT' },
      'authorization denied',
    );
  });
});

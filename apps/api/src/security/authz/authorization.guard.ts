import { Inject, Injectable, type CanActivate, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits PinoLogger as the constructor param type for DI
import { PinoLogger } from 'nestjs-pino';

import { DomainError } from '../../common/errors/domain-error.js';
import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';
import { AuthzFreshness } from '../../db/authz-freshness.js';
import { can } from './can.js';
import {
  hasClassLevelAccessMarker,
  IS_PUBLIC_KEY,
  IS_SELF_SERVICE_KEY,
  REQUIRE_PERMISSION_KEY,
} from './decorators.js';
import { isPermissionName, isSensitivePermission } from './permissions.js';
import { createPrincipal, type Principal } from './principal.js';
import { isAllowlistedPublicRoute, type GuardDenialReason } from './route-scan.js';

/**
 * The single authorization guard (ADR-008 Z3/Z4). It runs AFTER AuthGuard
 * (registration order is locked by a test), reads exactly one handler-level
 * marker, builds the Principal ONLY from the verified access-token claims and
 * answers a byte-identical generic 403 on every denial.
 *
 * It never reads the body, query or params, so a client cannot supply a tenant
 * id, user id, carrier id or role. The forced-change token has a different
 * audience and is rejected by AuthGuard before this guard runs.
 */

interface AuthedClaims {
  readonly sub: string;
  readonly tid: string;
  readonly sid: string;
  readonly roles: readonly string[];
}

interface AuthorizedRequest extends Request {
  auth?: AuthedClaims;
}

@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(APP_CONFIG) private readonly config: Pick<AppConfig, 'nodeEnv'>,
    @Inject(AuthzFreshness) private readonly freshness: AuthzFreshness,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(AuthorizationGuard.name);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthorizedRequest>();
    const handler = context.getHandler();
    const controller = context.getClass();

    // Markers are handler-level only (CP1 GB-04).
    if (hasClassLevelAccessMarker(controller)) {
      return this.deny(request, 'AUTHZ_CLASS_LEVEL_MARKER');
    }

    const isPublic = this.reflector.get<boolean>(IS_PUBLIC_KEY, handler) === true;
    const isSelfService = this.reflector.get<boolean>(IS_SELF_SERVICE_KEY, handler) === true;
    const permissionMetadata: unknown = this.reflector.get<unknown>(
      REQUIRE_PERMISSION_KEY,
      handler,
    );
    const isPermission = permissionMetadata !== undefined;
    const count = Number(isPublic) + Number(isSelfService) + Number(isPermission);
    if (count !== 1) {
      return this.deny(request, 'AUTHZ_MARKER_COUNT');
    }

    if (isPublic) {
      // CP1 GB-03: a public route is valid only on the reviewed §D allowlist.
      // Production accepts canonical paths only; dev/test also accept the
      // unprefixed form (direct controller mounting).
      if (!isAllowlistedPublicRoute(request.method, request.originalUrl, this.config.nodeEnv)) {
        return this.deny(request, 'AUTHZ_PUBLIC_NOT_ALLOWLISTED');
      }
      return true;
    }

    const principal = this.principalOf(request);
    if (principal === null) {
      // AuthGuard should have answered first; fail closed if it did not.
      throw DomainError.unauthorized();
    }
    if (isSelfService) {
      return true;
    }

    if (typeof permissionMetadata !== 'string' || !isPermissionName(permissionMetadata)) {
      return this.deny(request, 'AUTHZ_UNKNOWN_PERMISSION');
    }
    if (isSensitivePermission(permissionMetadata)) {
      // Z6/SR-06: fresh user/tenant/session/roles read. Only the intersection
      // of the token roles and DB roles can act; a dead session, disabled
      // user or suspended tenant is a generic 401 before any handler runs.
      const fresh = await this.freshness.read({
        tenantId: principal.tenantId,
        userId: principal.userId,
        sessionId: principal.sessionId,
      });
      if (!fresh.userActive || !fresh.tenantActive || !fresh.sessionLive) {
        return this.denyUnauthorized(request, 'AUTHZ_FRESHNESS_DENIED');
      }
      const dbRoles = new Set(fresh.roles);
      const effective = createPrincipal({
        userId: principal.userId,
        tenantId: principal.tenantId,
        sessionId: principal.sessionId,
        roles: principal.roles.filter((role) => dbRoles.has(role)),
        ...(principal.carrierId === undefined ? {} : { carrierId: principal.carrierId }),
      });
      if (!can(effective, permissionMetadata)) {
        return this.deny(request, 'AUTHZ_PERMISSION_DENIED');
      }
      return true;
    }
    if (!can(principal, permissionMetadata)) {
      return this.deny(request, 'AUTHZ_PERMISSION_DENIED');
    }
    return true;
  }

  /** Principal from verified claims only — never from body, query or params. */
  private principalOf(request: AuthorizedRequest): Principal | null {
    const claims = request.auth;
    if (claims === undefined) {
      return null;
    }
    return createPrincipal({
      userId: claims.sub,
      tenantId: claims.tid,
      sessionId: claims.sid,
      roles: claims.roles,
    });
  }

  /**
   * Server-side denial log: request id + stable reason code only. Never the
   * permission name, the role list or any user-supplied text (CP1 SA-03).
   */
  private deny(request: AuthorizedRequest, reasonCode: GuardDenialReason): never {
    this.logger.warn({ reqId: request.id ?? null, reasonCode }, 'authorization denied');
    throw DomainError.forbidden();
  }

  /** Freshness failure: generic 401, never a 403 that reveals account state. */
  private denyUnauthorized(request: AuthorizedRequest, reasonCode: GuardDenialReason): never {
    this.logger.warn({ reqId: request.id ?? null, reasonCode }, 'authorization denied');
    throw DomainError.unauthorized();
  }
}

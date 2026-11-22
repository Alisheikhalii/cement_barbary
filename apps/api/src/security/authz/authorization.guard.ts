import { Inject, Injectable, type CanActivate, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits PinoLogger as the constructor param type for DI
import { PinoLogger } from 'nestjs-pino';

import { DomainError } from '../../common/errors/domain-error.js';
import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';
import { AuthzFreshness } from '../../db/authz-freshness.js';
import { AccessScope } from './access-scope.js';
import { can } from './can.js';
import {
  hasClassLevelAccessMarker,
  IS_PUBLIC_KEY,
  IS_SELF_SERVICE_KEY,
  REQUIRE_PERMISSION_KEY,
} from './decorators.js';
import { AUDIT_HOOK, type AuditHook } from './audit-hook.js';
import { isPermissionName, isSensitivePermission, type PermissionName } from './permissions.js';
import { createVerifiedPrincipal, type Principal } from './principal.js';
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
  /** Server-built context; attached only after a permission check passes. */
  authz?: {
    readonly principal: Principal;
    readonly scope: AccessScope;
  };
}

@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(APP_CONFIG) private readonly config: Pick<AppConfig, 'nodeEnv'>,
    @Inject(AuthzFreshness) private readonly freshness: AuthzFreshness,
    @Inject(AUDIT_HOOK) private readonly audit: AuditHook,
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
      const effective = createVerifiedPrincipal({
        userId: principal.userId,
        tenantId: principal.tenantId,
        sessionId: principal.sessionId,
        roles: principal.roles.filter((role) => dbRoles.has(role)),
        ...(principal.carrierId === undefined ? {} : { carrierId: principal.carrierId }),
      });
      if (!can(effective, permissionMetadata)) {
        // ADR-009 L6: an authenticated 403 on a sensitive permission is an
        // audit row (best-effort, never changes the response).
        return this.deny(request, 'AUTHZ_PERMISSION_DENIED', {
          principal: effective,
          permission: permissionMetadata,
          controller: controller.name,
          handler: handler.name,
        });
      }
      return this.attachScope(request, effective, permissionMetadata, {
        controller: controller.name,
        handler: handler.name,
      });
    }
    if (!can(principal, permissionMetadata)) {
      return this.deny(request, 'AUTHZ_PERMISSION_DENIED');
    }
    return this.attachScope(request, principal, permissionMetadata, {
      controller: controller.name,
      handler: handler.name,
    });
  }

  /**
   * Attaches the brand-protected resource scope (T05) only AFTER the permission
   * check passed. The scope is built from the verified principal and the
   * permission's catalog scope — never from body, query, params or headers.
   *
   * Idempotent: a second successful pass on the same request keeps the first
   * attachment instead of throwing on the non-configurable property. A scope
   * that cannot be built (e.g. carrier scope without a carrier id) is logged as
   * a normal guard denial rather than escaping as an unlogged 403.
   */
  private async attachScope(
    request: AuthorizedRequest,
    principal: Principal,
    permission: PermissionName,
    handlerName: { readonly controller: string; readonly handler: string },
  ): Promise<true> {
    if (request.authz !== undefined) {
      return true;
    }
    try {
      const scope = AccessScope.forPermission(principal, permission);
      Object.defineProperty(request, 'authz', {
        value: Object.freeze({ principal, scope }),
        enumerable: false,
        configurable: false,
        writable: false,
      });
      return true;
    } catch (error) {
      if (error instanceof DomainError) {
        return this.deny(request, 'AUTHZ_SCOPE_DENIED', {
          principal,
          permission,
          controller: handlerName.controller,
          handler: handlerName.handler,
        });
      }
      throw error;
    }
  }

  /** Principal from verified claims only — never from body, query or params. */
  private principalOf(request: AuthorizedRequest): Principal | null {
    const claims = request.auth;
    if (claims === undefined) {
      return null;
    }
    // F1-08: add the token's `cid` claim here when carriers get a carrier id;
    // until then `carrierId` stays absent and carrier scope fails closed.
    return createVerifiedPrincipal({
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
  private async deny(
    request: AuthorizedRequest,
    reasonCode: GuardDenialReason,
    audit?: {
      readonly principal: Principal;
      readonly permission: PermissionName;
      readonly controller: string;
      readonly handler: string;
    },
  ): Promise<never> {
    this.logger.warn({ reqId: request.id ?? null, reasonCode }, 'authorization denied');
    if (audit !== undefined && isSensitivePermission(audit.permission)) {
      await this.recordDenial(request, audit);
    }
    throw DomainError.forbidden();
  }

  /**
   * ADR-009 L6 denial row. Best-effort: the persistent hook opens its own
   * short transaction, catches its own failure and never throws. The generic
   * 403 is raised in every case.
   */
  private async recordDenial(
    request: AuthorizedRequest,
    audit: {
      readonly principal: Principal;
      readonly permission: PermissionName;
      readonly controller: string;
      readonly handler: string;
    },
  ): Promise<void> {
    try {
      await this.audit.record({
        actor: {
          userId: audit.principal.userId,
          tenantId: audit.principal.tenantId,
          sessionId: audit.principal.sessionId,
        },
        action: audit.permission,
        resource: { type: 'handler', id: `${audit.controller}.${audit.handler}` },
        reason: null,
        outcome: 'denied',
        httpStatus: 403,
        requestId: this.requestId(request),
        ip: this.clientIp(request),
      });
    } catch {
      // An audit implementation must never change the authorization result.
    }
  }

  /** Same bound as the interceptor: a truncated address is a different address. */
  private clientIp(request: AuthorizedRequest): string | null {
    const ip: unknown = request.ip;
    return typeof ip === 'string' && ip.length > 0 && ip.length <= 64 ? ip : null;
  }

  /** pino's request id is `string | number`; the audit column takes a string. */
  private requestId(request: AuthorizedRequest): string | null {
    const id: unknown = request.id;
    if (typeof id === 'string' && id.length > 0) {
      return id;
    }
    return typeof id === 'number' ? String(id) : null;
  }

  /** Freshness failure: generic 401, never a 403 that reveals account state. */
  private denyUnauthorized(request: AuthorizedRequest, reasonCode: GuardDenialReason): never {
    this.logger.warn({ reqId: request.id ?? null, reasonCode }, 'authorization denied');
    throw DomainError.unauthorized();
  }
}

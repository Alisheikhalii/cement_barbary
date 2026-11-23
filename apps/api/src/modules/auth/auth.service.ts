import { Inject, Injectable } from '@nestjs/common';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits PinoLogger as the constructor param type for DI
import { PinoLogger } from 'nestjs-pino';

import { DomainError } from '../../common/errors/domain-error.js';
import { sqlStateOf } from '../../common/errors/sql-state.js';
import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';
import { TenantContext } from '../../db/tenant-context.js';
import { TenantDb } from '../../db/tenant-db.js';
import { normalizePhone } from '../../security/pii/normalize.js';
import { AuditWriter } from '../audit/audit-writer.js';
import type { AssignableRole } from '../users/users.types.js';
import { AuthRepository } from './auth.repository.js';
import type { ChangePasswordInput, LoginInput } from './auth.dto.js';
import { bearerToken } from './bearer.js';
import { constantTimeEquals } from './refresh-token.js';
import { parseLoginIdentifier } from './login-identifier.js';
import { PasswordMethod } from './password-method.js';
import { PasswordService } from './password.service.js';
import { assertPasswordPolicy, passwordKindForRoles } from './password-policy.js';
import {
  LOGIN_WINDOW_SECONDS,
  RATE_LIMITER,
  rateLimitKeys,
  type RateLimiter,
  type RateLimitVerdict,
} from './rate-limiter.js';
import { SessionService, type SessionClientMeta } from './session.service.js';
import {
  credentialFingerprint,
  PASSWORD_CHANGE_TOKEN_TTL_SECONDS,
  TokenService,
  type AccessTokenClaims,
} from './token.service.js';

/**
 * The auth flows (T06): login, refresh, logout, me and password change. It
 * orchestrates PasswordMethod, sessions and tokens; it owns no HTTP and no SQL.
 *
 * Rules held here:
 * - every credential failure is `DomainError.invalidCredentials()` (A3);
 * - rate limits run BEFORE any credential work, keyed by hashed identifiers
 *   (per IP, per account, per tenant code for staff);
 * - a driver-only login issues and revokes siblings in ONE transaction (BR-18);
 * - `must_change_password` returns only a 5-minute change token (A19);
 * - refresh re-checks user/tenant freshness before rotation (A18).
 */

export interface SessionTokens {
  readonly accessToken: string;
  readonly tokenType: 'Bearer';
  readonly expiresIn: number;
  readonly user: {
    readonly id: string;
    readonly tenantId: string;
    readonly roles: readonly string[];
  };
}

export interface SessionResult {
  readonly tokens: SessionTokens;
  readonly refreshToken: string;
  readonly refreshExpiresAt: Date;
}

export type LoginResult =
  | ({ readonly kind: 'session' } & SessionResult)
  | { readonly kind: 'change'; readonly changeToken: string; readonly expiresIn: number };

export interface MeResult {
  readonly id: string;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly roles: readonly string[];
}

function isDriverOnly(roles: readonly AssignableRole[]): boolean {
  return roles.length > 0 && roles.every((role) => role === 'DRIVER');
}

/** The canonical phone for an identifier-shaped value, or null when it is not a phone. */
function normalizedPhoneOrNull(value: string): string | null {
  try {
    return normalizePhone(value);
  } catch {
    return null;
  }
}

@Injectable()
export class AuthService {
  private readonly keys: ReturnType<typeof rateLimitKeys>;

  constructor(
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    @Inject(PasswordMethod) private readonly passwordMethod: PasswordMethod,
    @Inject(PasswordService) private readonly passwords: PasswordService,
    @Inject(TokenService) private readonly tokens: TokenService,
    @Inject(SessionService) private readonly sessions: SessionService,
    @Inject(AuthRepository) private readonly accounts: AuthRepository,
    @Inject(TenantContext) private readonly tenantContext: TenantContext,
    @Inject(TenantDb) private readonly tenantDb: TenantDb,
    @Inject(AuditWriter) private readonly audit: AuditWriter,
    @Inject(RATE_LIMITER) private readonly limiter: RateLimiter,
    private readonly logger: PinoLogger,
  ) {
    // Hashed key shapes: no raw phone, username or tenant code ever persists.
    this.keys = rateLimitKeys(config.pii.hmacKey);
    this.logger.setContext(AuthService.name);
  }

  async login(input: LoginInput, meta: SessionClientMeta): Promise<LoginResult> {
    await this.enforceLimits(input.identifier, meta.ip ?? null);
    const parsed = parseLoginIdentifier(input.identifier);
    const verified = await this.passwordMethod.verify(
      parsed.kind === 'staff'
        ? { kind: 'staff', identifier: input.identifier.trim(), password: input.password }
        : { kind: 'driver', phone: input.identifier.trim(), password: input.password },
    );
    if (!verified.ok) {
      throw DomainError.invalidCredentials();
    }
    const { identity } = verified;

    if (identity.mustChangePassword) {
      // A19: no session, no cookie — only a change token bound to this exact
      // credential row (single use via the PHC fingerprint).
      const credentials = await this.tenantContext.run({ tenantId: identity.tenantId }, () =>
        this.accounts.getCredentials(identity.userId),
      );
      if (credentials === null) {
        throw DomainError.invalidCredentials();
      }
      const changeToken = await this.tokens.signPasswordChangeToken({
        userId: identity.userId,
        tenantId: identity.tenantId,
        fingerprint: credentialFingerprint(credentials.passwordHash),
      });
      // No session is created and nothing is written here, so there is no
      // auth.login.success row: the completed change records
      // auth.password.changed (L5: audit only paths that already write).
      return {
        kind: 'change',
        changeToken,
        expiresIn: PASSWORD_CHANGE_TOKEN_TTL_SECONDS,
      };
    }

    const session = await this.openSession(
      identity.tenantId,
      identity.userId,
      identity.roles,
      meta,
      {
        action: 'auth.login.success',
        // Q1: failed logins are not rows; this is how a delay episode becomes
        // visible (the value was read before the counter reset).
        metadata: {
          method: this.passwordMethod.method,
          prior_failed_attempts: identity.priorFailedAttempts ?? 0,
        },
      },
    );
    return { kind: 'session', ...session };
  }

  /** A8/A18: rotates the cookie; every failure is the generic 401. */
  async refresh(refreshToken: string | null, meta: SessionClientMeta): Promise<SessionResult> {
    if (refreshToken === null) {
      throw DomainError.unauthorized();
    }
    const rotated = await this.sessions.rotate(refreshToken, meta);
    if (rotated === null) {
      throw DomainError.unauthorized();
    }
    // Z7a: roles and account status were read in the SAME transaction as the
    // rotation; the new access token reflects exactly the DB role set at that
    // point, never a separate read after the rotation committed.
    const roles = rotated.roles;
    const accessToken = await this.tokens.signAccessToken({
      userId: rotated.userId,
      tenantId: rotated.tenantId,
      sessionId: rotated.sessionId,
      roles,
    });
    return {
      tokens: this.tokensPayload(rotated.userId, rotated.tenantId, roles, accessToken),
      refreshToken: rotated.refreshToken,
      refreshExpiresAt: rotated.refreshExpiresAt,
    };
  }

  /** Logout is idempotent and silent — never an oracle (A8). */
  async logout(refreshToken: string | null): Promise<void> {
    if (refreshToken !== null) {
      await this.sessions.revokeByToken(refreshToken);
    }
  }

  me(claims: AccessTokenClaims): MeResult {
    return {
      id: claims.sub,
      tenantId: claims.tid,
      sessionId: claims.sid,
      roles: claims.roles,
    };
  }

  /**
   * A19. Two branches: a forced-change token (new password only, bound to the
   * current PHC) or an access token plus the current password. Success clears
   * the forced-change state, revokes ALL sessions and issues a fresh one.
   */
  async changePassword(
    input: ChangePasswordInput,
    authorizationHeader: string | undefined,
    meta: SessionClientMeta,
  ): Promise<SessionResult> {
    const token = bearerToken(authorizationHeader);
    if (token === null) {
      throw DomainError.unauthorized();
    }
    let mode: 'access' | 'change';
    let userId: string;
    let tenantId: string;
    let fingerprint: string | null = null;
    try {
      const claims = await this.tokens.verifyAccessToken(token);
      mode = 'access';
      userId = claims.sub;
      tenantId = claims.tid;
    } catch {
      const claims = await this.tokens.verifyPasswordChangeToken(token);
      mode = 'change';
      userId = claims.sub;
      tenantId = claims.tid;
      fingerprint = claims.chg;
    }

    // Read-only and expensive work (Argon2 verify/hash, policy checks) runs
    // BEFORE the write transaction, so a pooled connection is not held during
    // hashing (T06 review LOW). The transaction below only writes: CAS hash,
    // session revocations, new session and its audit row (ADR-009 L1/L5).
    try {
      return await this.tenantContext.run({ tenantId }, async () => {
        // A18 for the change flow too: a disabled/deleted user or suspended
        // tenant must not be able to mint a fresh session with an old token.
        // Fast path only — the repository re-checks activity inside the
        // compare-and-swap transaction that writes the new hash.
        if (!(await this.accounts.isAccountActive(userId))) {
          throw DomainError.invalidCredentials();
        }
        // LOW-4 fix: current-password guessing through this endpoint is
        // throttled with the same per-account window as login.
        const changeLimit = await this.limiterHit(
          this.keys.loginAccount(`password-change:${tenantId}:${userId}`),
          this.config.auth.rateLimit.loginAccountPerMinute,
        );
        if (!changeLimit.allowed) {
          throw DomainError.tooManyRequests(changeLimit.retryAfterSeconds ?? LOGIN_WINDOW_SECONDS);
        }
        const credentials = await this.accounts.getCredentials(userId);
        if (credentials === null) {
          throw DomainError.invalidCredentials();
        }
        if (mode === 'change') {
          // Single use: the token must still point at THIS credential row, and
          // the account must still be in the forced-change window.
          const current = Buffer.from(credentialFingerprint(credentials.passwordHash));
          const presented = Buffer.from(fingerprint ?? '');
          if (!constantTimeEquals(current, presented)) {
            throw DomainError.invalidCredentials();
          }
          if (
            !credentials.mustChangePassword ||
            credentials.temporaryPasswordExpiresAt === null ||
            credentials.temporaryPasswordExpiresAt.getTime() <= Date.now()
          ) {
            throw DomainError.invalidCredentials();
          }
        } else {
          if (input.currentPassword === undefined) {
            throw DomainError.badInput({ reason: 'current_password_required' });
          }
          const matches = await this.passwords.verify(
            credentials.passwordHash,
            input.currentPassword,
          );
          if (!matches) {
            throw DomainError.invalidCredentials();
          }
        }

        const roles = await this.accounts.getRoles(userId);
        // A20: "never equal to the login identifier" must cover EVERY form of
        // it — the bare username, username@tenant-code, and the phone. Checking
        // only the bare username let `operator@acme` or a PIN equal to the phone
        // through (review MEDIUM 1).
        const identifiers = await this.accounts.getIdentifiers(userId);
        const kind = passwordKindForRoles(roles);
        const candidates = [
          identifiers.username,
          identifiers.username === null
            ? null
            : `${identifiers.username}@${identifiers.tenantCode}`,
          identifiers.phone,
        ].filter((value): value is string => typeof value === 'string' && value.length > 0);
        if (candidates.length === 0) {
          assertPasswordPolicy(kind, input.newPassword, '');
        } else {
          for (const identifier of candidates) {
            assertPasswordPolicy(kind, input.newPassword, identifier);
          }
        }
        // Aliases of the phone count too: `9120000073`, `989120000073`, `+98…`
        // and spaced forms all normalize to the same login identifier
        // (review delta MEDIUM).
        if (
          identifiers.phone !== null &&
          normalizedPhoneOrNull(input.newPassword) === identifiers.phone
        ) {
          throw DomainError.badInput({ reason: 'equals_identifier' });
        }

        const passwordHash = await this.passwords.hash(input.newPassword);

        return this.tenantDb.run(async () => {
          const changed = await this.accounts.setPasswordAndRevokeAll(
            userId,
            credentials.passwordHash,
            passwordHash,
          );
          if (!changed) {
            // Lost a race (double-submit / replayed change token): generic 401.
            throw DomainError.invalidCredentials();
          }

          return this.openSession(tenantId, userId, roles, meta, {
            action: 'auth.password.changed',
          });
        });
      });
    } catch (error) {
      if (error instanceof DomainError) {
        throw error;
      }
      // F1-07 T01: a concurrent change must never surface a raw 500. A deadlock
      // or statement timeout anywhere after token verification means this
      // attempt applied nothing (its transaction rolled back), so the client
      // gets a retryable generic 503 and the server logs only the structural
      // event code and SQLSTATE.
      const sqlState = sqlStateOf(error);
      if (sqlState === '40P01' || sqlState === '57014') {
        this.logger.warn(
          {
            eventCode: sqlState === '40P01' ? 'AUTH_CHANGE_TX_DEADLOCK' : 'AUTH_CHANGE_TX_TIMEOUT',
            sqlState,
          },
          'password change transaction aborted',
        );
        throw DomainError.serviceUnavailable();
      }
      throw error;
    }
  }

  private async openSession(
    tenantId: string,
    userId: string,
    roles: readonly AssignableRole[],
    meta: SessionClientMeta,
    audit: { readonly action: string; readonly metadata?: Record<string, string | number> },
  ): Promise<SessionResult> {
    // BR-18: for a driver-only account the insert and the sibling revocation
    // share ONE transaction inside SessionRepository.create(); the audit row
    // commits in that same transaction (ADR-009 L1/L5).
    const session = await this.tenantContext.run({ tenantId }, () =>
      this.tenantDb.run(async () => {
        const issued = await this.sessions.issue(userId, meta, {
          singleSession: isDriverOnly(roles),
        });
        await this.audit.append({
          actorType: 'user',
          actorUserId: userId,
          actorSessionId: issued.sessionId,
          action: audit.action,
          resourceType: 'auth_session',
          resourceId: issued.sessionId,
          outcome: 'success',
          ip: meta.ip ?? null,
          ...(audit.metadata === undefined ? {} : { metadata: audit.metadata }),
        });
        return issued;
      }),
    );
    const accessToken = await this.tokens.signAccessToken({
      userId,
      tenantId,
      sessionId: session.sessionId,
      roles,
    });
    return {
      tokens: this.tokensPayload(userId, tenantId, roles, accessToken),
      refreshToken: session.refreshToken,
      refreshExpiresAt: session.refreshExpiresAt,
    };
  }

  private tokensPayload(
    userId: string,
    tenantId: string,
    roles: readonly AssignableRole[],
    accessToken: string,
  ): SessionTokens {
    return {
      accessToken,
      tokenType: 'Bearer',
      expiresIn: this.config.auth.accessTokenTtlSeconds,
      user: { id: userId, tenantId, roles: [...roles] },
    };
  }

  /**
   * A11, owner T06: per-IP, per-account (hashed identifier) and — for staff —
   * per-tenant-code (hashed) fixed windows. An unknown identifier consumes the
   * same buckets as a known one, so a 429 never reveals account existence.
   */
  private async enforceLimits(identifier: string, ip: string | null): Promise<void> {
    const parsed = parseLoginIdentifier(identifier);
    const checks: { key: string; limit: number }[] = [
      {
        key: this.keys.loginIp(ip ?? 'unknown'),
        limit: this.config.auth.rateLimit.loginIpPerMinute,
      },
      {
        key: this.keys.loginAccount(parsed.rateLimitIdentity),
        limit: this.config.auth.rateLimit.loginAccountPerMinute,
      },
    ];
    if (parsed.kind === 'staff') {
      checks.push({
        key: this.keys.loginTenant(parsed.tenantCode),
        limit: this.config.auth.rateLimit.loginTenantPerMinute,
      });
    }
    for (const check of checks) {
      const verdict = await this.limiterHit(check.key, check.limit);
      if (!verdict.allowed) {
        throw DomainError.tooManyRequests(verdict.retryAfterSeconds ?? LOGIN_WINDOW_SECONDS);
      }
    }
  }

  /**
   * F1-07 T01: a limiter failure (for example a 57014 left after the counter
   * transaction) is fail-closed and account-agnostic. The hit runs before any
   * credential lookup, so known and unknown identifiers get the same generic
   * 503 + Retry-After, never a raw 500 and never an existence oracle. Only the
   * structural event code and SQLSTATE are logged.
   */
  private async limiterHit(key: string, limit: number): Promise<RateLimitVerdict> {
    try {
      return await this.limiter.hit(key, limit, LOGIN_WINDOW_SECONDS);
    } catch (error) {
      if (error instanceof DomainError) {
        throw error;
      }
      this.logger.warn(
        { eventCode: 'AUTH_RATE_LIMIT_UNAVAILABLE', sqlState: sqlStateOf(error) },
        'rate limiter hit failed',
      );
      throw DomainError.serviceUnavailable();
    }
  }
}

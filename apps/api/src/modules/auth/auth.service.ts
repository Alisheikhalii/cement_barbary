import { Inject, Injectable } from '@nestjs/common';

import { DomainError } from '../../common/errors/domain-error.js';
import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';
import { TenantContext } from '../../db/tenant-context.js';
import { normalizePhone } from '../../security/pii/normalize.js';
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
    @Inject(RATE_LIMITER) private readonly limiter: RateLimiter,
  ) {
    // Hashed key shapes: no raw phone, username or tenant code ever persists.
    this.keys = rateLimitKeys(config.pii.hmacKey);
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
    // A18: roles are re-read on every refresh, never trusted from the old token.
    const roles = await this.tenantContext.run({ tenantId: rotated.tenantId }, () =>
      this.accounts.getRoles(rotated.userId),
    );
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

    return this.tenantContext.run({ tenantId }, async () => {
      // A18 for the change flow too: a disabled/deleted user or suspended
      // tenant must not be able to mint a fresh session with an old token.
      // Fast path only — the repository re-checks activity inside the
      // compare-and-swap transaction that writes the new hash.
      if (!(await this.accounts.isAccountActive(userId))) {
        throw DomainError.invalidCredentials();
      }
      // LOW-4 fix: current-password guessing through this endpoint is
      // throttled with the same per-account window as login.
      const changeLimit = await this.limiter.hit(
        this.keys.loginAccount(`password-change:${tenantId}:${userId}`),
        this.config.auth.rateLimit.loginAccountPerMinute,
        LOGIN_WINDOW_SECONDS,
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
        identifiers.username === null ? null : `${identifiers.username}@${identifiers.tenantCode}`,
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
      const changed = await this.accounts.setPasswordAndRevokeAll(
        userId,
        credentials.passwordHash,
        passwordHash,
      );
      if (!changed) {
        // Lost a race (double-submit / replayed change token): generic 401.
        throw DomainError.invalidCredentials();
      }

      return this.openSession(tenantId, userId, roles, meta);
    });
  }

  private async openSession(
    tenantId: string,
    userId: string,
    roles: readonly AssignableRole[],
    meta: SessionClientMeta,
  ): Promise<SessionResult> {
    // BR-18: for a driver-only account the insert and the sibling revocation
    // share ONE transaction inside SessionRepository.create().
    const session = await this.tenantContext.run({ tenantId }, () =>
      this.sessions.issue(userId, meta, { singleSession: isDriverOnly(roles) }),
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
      const verdict = await this.limiter.hit(check.key, check.limit, LOGIN_WINDOW_SECONDS);
      if (!verdict.allowed) {
        throw DomainError.tooManyRequests(verdict.retryAfterSeconds ?? LOGIN_WINDOW_SECONDS);
      }
    }
  }
}

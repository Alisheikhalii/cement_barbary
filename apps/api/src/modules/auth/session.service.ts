import { Inject, Injectable } from '@nestjs/common';
import { v7 as uuidv7 } from 'uuid';

import { AuthLookupService } from '../../db/auth-lookup.service.js';
import { TenantContext } from '../../db/tenant-context.js';
import { AuthRepository } from './auth.repository.js';
import { generateRefreshToken, hashRefreshToken, isRefreshTokenShape } from './refresh-token.js';
import { SessionRepository } from './session.repository.js';

/**
 * Refresh-session lifecycle (ADR-007 A8–A10, T05). The refresh cookie is the
 * only client-held secret here: rotation happens on every use, the previous
 * hash stays on the row for reuse detection, and a replayed rotated token
 * revokes the whole family. Resolution before a tenant context exists goes
 * through the `app.auth_lookup_session` definer function — never client input.
 *
 * This module has no HTTP code and no logging: tokens, hashes and reasons
 * never enter a log line or an error message.
 */

/** A8: the session (and its refresh token) lives 30 days. */
export const REFRESH_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;

export interface SessionClientMeta {
  /** Client IP for the row; null when unknown. */
  readonly ip?: string | null;
  /** Truncated by the HTTP layer before it gets here (AGENT.md §7). */
  readonly userAgent?: string | null;
}

export interface IssuedSession {
  readonly sessionId: string;
  readonly familyId: string;
  /** The ONLY time this value exists; only its SHA-256 hash is stored. */
  readonly refreshToken: string;
  readonly refreshExpiresAt: Date;
}

export interface RotatedSession extends IssuedSession {
  readonly tenantId: string;
  readonly userId: string;
}

@Injectable()
export class SessionService {
  constructor(
    @Inject(AuthLookupService) private readonly lookup: AuthLookupService,
    @Inject(TenantContext) private readonly tenantContext: TenantContext,
    @Inject(SessionRepository) private readonly sessions: SessionRepository,
    @Inject(AuthRepository) private readonly accounts: AuthRepository,
  ) {}

  /**
   * Opens a new session family. Requires an active tenant context (the login
   * flow wraps its work in TenantContext.run); the driver single-session rule
   * (BR-18) is a separate call — `revokeOtherSessions` below.
   */
  async issue(
    userId: string,
    meta: SessionClientMeta = {},
    options: { readonly singleSession?: boolean } = {},
  ): Promise<IssuedSession> {
    const refreshToken = generateRefreshToken();
    const familyId = uuidv7();
    const refreshExpiresAt = new Date(Date.now() + REFRESH_SESSION_TTL_SECONDS * 1000);
    const { id } = await this.sessions.create(
      {
        userId,
        familyId,
        refreshHash: hashRefreshToken(refreshToken),
        expiresAt: refreshExpiresAt,
        ip: meta.ip ?? null,
        userAgent: meta.userAgent ?? null,
      },
      { revokeOtherSessions: options.singleSession === true },
    );
    return { sessionId: id, familyId, refreshToken, refreshExpiresAt };
  }

  /**
   * Rotates the presented token. Returns null for EVERY failure — unknown,
   * malformed, expired, revoked, reused — so the caller can only answer the
   * generic 401 (A3/A8). A reused rotated token revokes its family as a side
   * effect before null is returned.
   */
  async rotate(token: string, meta: SessionClientMeta = {}): Promise<RotatedSession | null> {
    if (!isRefreshTokenShape(token)) {
      return null;
    }
    const oldHash = hashRefreshToken(token);
    const found = await this.lookup.lookupSession(oldHash);
    if (!found) {
      return null;
    }
    if (found.reuseDetected) {
      await this.tenantContext.run({ tenantId: found.tenantId }, () =>
        this.sessions.revokeFamily(found.familyId),
      );
      return null;
    }
    if (found.revokedAt !== null || found.expiresAt.getTime() <= Date.now()) {
      return null;
    }
    // A18: a disabled/deleted user or a suspended/deleted tenant fails now,
    // with the generic failure, and the session is revoked so it cannot be
    // retried later.
    const active = await this.tenantContext.run({ tenantId: found.tenantId }, () =>
      this.accounts.isAccountActive(found.userId),
    );
    if (!active) {
      await this.tenantContext.run({ tenantId: found.tenantId }, () =>
        this.sessions.revokeSession(found.sessionId, 'disabled'),
      );
      return null;
    }

    const refreshToken = generateRefreshToken();
    const result = await this.tenantContext.run({ tenantId: found.tenantId }, () =>
      this.sessions.rotate({
        sessionId: found.sessionId,
        oldHash,
        newHash: hashRefreshToken(refreshToken),
        ip: meta.ip ?? null,
        userAgent: meta.userAgent ?? null,
      }),
    );
    if (result.outcome === 'rotated') {
      return {
        sessionId: found.sessionId,
        familyId: result.familyId,
        tenantId: found.tenantId,
        userId: result.userId,
        refreshToken,
        refreshExpiresAt: found.expiresAt,
      };
    }
    if (result.outcome === 'reuse') {
      // The repository already revoked the family in the same transaction;
      // a concurrent loser must still get the generic failure.
      return null;
    }
    return null;
  }

  /**
   * Revokes the session behind a presented token (logout). Idempotent and
   * silent: an unknown or malformed token is a no-op, so logout never becomes
   * an oracle. Presenting a rotated-out token follows the reuse rule and
   * revokes the family.
   */
  async revokeByToken(token: string): Promise<void> {
    if (!isRefreshTokenShape(token)) {
      return;
    }
    const found = await this.lookup.lookupSession(hashRefreshToken(token));
    if (!found) {
      return;
    }
    await this.tenantContext.run({ tenantId: found.tenantId }, async () => {
      if (found.reuseDetected) {
        await this.sessions.revokeFamily(found.familyId);
      } else {
        await this.sessions.revokeSession(found.sessionId, 'logout');
      }
    });
  }

  /**
   * Revokes every live session of a user (password change / operator reset,
   * A19). Requires an active tenant context.
   */
  async revokeAllForUser(userId: string, reason = 'password_change'): Promise<number> {
    return this.sessions.revokeAllForUser(userId, reason);
  }

  /**
   * BR-18 hook (A10) — "one active driver session": the login flow calls this
   * after issuing the new session, inside the same tenant transaction, so the
   * previous device is revoked atomically ("last device wins").
   */
  async revokeOtherSessions(userId: string, keepSessionId: string): Promise<number> {
    return this.sessions.revokeOtherSessions(userId, keepSessionId);
  }
}

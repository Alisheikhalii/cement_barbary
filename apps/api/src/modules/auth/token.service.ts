import { createHash } from 'node:crypto';

import { Inject, Injectable } from '@nestjs/common';
import { jwtVerify, SignJWT } from 'jose';
import { v7 as uuidv7 } from 'uuid';
import { z } from 'zod';

import { DomainError } from '../../common/errors/domain-error.js';
import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';

/**
 * Access tokens (ADR-007 A7, owner condition 8). HS256 only — the algorithm is
 * pinned on BOTH sides: we always sign `alg: HS256`, and verify passes
 * `algorithms: ['HS256']`, so `none`, HS384/HS512 and RS256 tokens are all
 * rejected before any claim is read. Claims carry ids, role codes and token
 * metadata only — never a phone, username or display name.
 */

export const ACCESS_TOKEN_ISSUER = 'bitabar';
export const ACCESS_TOKEN_AUDIENCE = 'bitabar-api';

/**
 * A19: the forced-change token is a separate audience and carries no session
 * or roles, so it can never be used as an access token (and vice versa).
 */
export const PASSWORD_CHANGE_TOKEN_AUDIENCE = 'bitabar-api:password-change';
export const PASSWORD_CHANGE_TOKEN_TTL_SECONDS = 300;

/** A JWT longer than this is rejected unparsed (cheap DoS guard). */
const MAX_TOKEN_LENGTH = 4096;

const claimsSchema = z
  .object({
    /** User id. */
    sub: z.uuid(),
    /** Tenant id — the only tenant source for a request (never a client field). */
    tid: z.uuid(),
    /** Session id — lets logout/revocation target one chain. */
    sid: z.uuid(),
    /** Role codes from the role catalog (no names, no PII). */
    roles: z.array(z.string().min(1).max(64)).max(8),
    /** Token id. */
    jti: z.uuid(),
    iat: z.number().int(),
    exp: z.number().int(),
    iss: z.literal(ACCESS_TOKEN_ISSUER),
    aud: z.union([z.string(), z.array(z.string())]),
  })
  // `.strict()` rejects extra claims: the future password-change token (A19)
  // shares AUTH_TOKEN_SECRET, so a token of one purpose must not verify as the
  // other (the two get different audiences in T06).
  .strict();

/**
 * Binds a forced-change token to the EXACT credential row it was issued for
 * (A19 single use). The fingerprint is a domain-separated SHA-256 of the
 * stored PHC string: any password change or operator reset changes it, so an
 * old token is dead — without a new column or a server-side nonce.
 */
export function credentialFingerprint(passwordHash: string): string {
  return createHash('sha256')
    .update(`password-change:v1:${passwordHash}`, 'utf8')
    .digest('base64url');
}

const changeClaimsSchema = z
  .object({
    sub: z.uuid(),
    tid: z.uuid(),
    jti: z.uuid(),
    chg: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    iat: z.number().int(),
    exp: z.number().int(),
    iss: z.literal(ACCESS_TOKEN_ISSUER),
    aud: z.literal(PASSWORD_CHANGE_TOKEN_AUDIENCE),
  })
  .strict();

export interface AccessTokenInput {
  readonly userId: string;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly roles: readonly string[];
}

export interface PasswordChangeClaims {
  readonly sub: string;
  readonly tid: string;
  readonly jti: string;
  readonly chg: string;
  readonly iat: number;
  readonly exp: number;
}

export interface AccessTokenClaims {
  readonly sub: string;
  readonly tid: string;
  readonly sid: string;
  readonly roles: readonly string[];
  readonly jti: string;
  readonly iat: number;
  readonly exp: number;
}

@Injectable()
export class TokenService {
  /** A copy, so the config Buffer is not retained by the signing code. */
  private readonly key: Uint8Array;

  constructor(@Inject(APP_CONFIG) private readonly config: AppConfig) {
    this.key = new Uint8Array(config.auth.tokenSecret);
  }

  /** Signs an access token with exactly the documented claim set. */
  async signAccessToken(input: AccessTokenInput): Promise<string> {
    const issuedAt = Math.floor(Date.now() / 1000);
    return new SignJWT({
      tid: input.tenantId,
      sid: input.sessionId,
      roles: [...input.roles],
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject(input.userId)
      .setIssuer(ACCESS_TOKEN_ISSUER)
      .setAudience(ACCESS_TOKEN_AUDIENCE)
      .setJti(uuidv7())
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + this.config.auth.accessTokenTtlSeconds)
      .sign(this.key);
  }

  /**
   * Signs the 5-minute forced-change token (A19). Same key, different audience
   * and a smaller claim set, so it cannot open protected endpoints.
   */
  async signPasswordChangeToken(input: {
    readonly userId: string;
    readonly tenantId: string;
    /** `credentialFingerprint()` of the current stored hash (single-use binding). */
    readonly fingerprint: string;
  }): Promise<string> {
    const issuedAt = Math.floor(Date.now() / 1000);
    return new SignJWT({ tid: input.tenantId, chg: input.fingerprint })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject(input.userId)
      .setIssuer(ACCESS_TOKEN_ISSUER)
      .setAudience(PASSWORD_CHANGE_TOKEN_AUDIENCE)
      .setJti(uuidv7())
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + PASSWORD_CHANGE_TOKEN_TTL_SECONDS)
      .sign(this.key);
  }

  /** Verifies a forced-change token; same generic 401 on any failure. */
  async verifyPasswordChangeToken(token: string): Promise<PasswordChangeClaims> {
    const payload = await this.verify(token, PASSWORD_CHANGE_TOKEN_AUDIENCE);
    const parsed = changeClaimsSchema.safeParse(payload);
    if (!parsed.success) {
      throw DomainError.unauthorized();
    }
    return {
      sub: parsed.data.sub,
      tid: parsed.data.tid,
      jti: parsed.data.jti,
      chg: parsed.data.chg,
      iat: parsed.data.iat,
      exp: parsed.data.exp,
    };
  }

  /**
   * Verifies signature, algorithm, issuer, audience and expiry, then the claim
   * shape. Every failure is the same generic 401 — never a reason (A3).
   */
  async verifyAccessToken(token: string): Promise<AccessTokenClaims> {
    const payload = await this.verify(token, ACCESS_TOKEN_AUDIENCE);
    const parsed = claimsSchema.safeParse(payload);
    if (!parsed.success) {
      throw DomainError.unauthorized();
    }
    return {
      sub: parsed.data.sub,
      tid: parsed.data.tid,
      sid: parsed.data.sid,
      roles: parsed.data.roles,
      jti: parsed.data.jti,
      iat: parsed.data.iat,
      exp: parsed.data.exp,
    };
  }

  /** Shared jose verification: pinned alg, iss, aud, exp; failure is a generic 401. */
  private async verify(token: string, audience: string): Promise<Record<string, unknown>> {
    if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
      throw DomainError.unauthorized();
    }
    try {
      const verified = await jwtVerify(token, this.key, {
        algorithms: ['HS256'],
        issuer: ACCESS_TOKEN_ISSUER,
        audience,
        // Default clock tolerance is 0; a small window covers API clock drift.
        clockTolerance: 5,
      });
      return verified.payload;
    } catch {
      // jose errors name the failing step; that detail must not leave the module.
      throw DomainError.unauthorized();
    }
  }
}

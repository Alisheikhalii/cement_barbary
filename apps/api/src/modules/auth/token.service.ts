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

export interface AccessTokenInput {
  readonly userId: string;
  readonly tenantId: string;
  readonly sessionId: string;
  readonly roles: readonly string[];
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
   * Verifies signature, algorithm, issuer, audience and expiry, then the claim
   * shape. Every failure is the same generic 401 — never a reason (A3).
   */
  async verifyAccessToken(token: string): Promise<AccessTokenClaims> {
    if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
      throw DomainError.unauthorized();
    }
    let payload: Record<string, unknown>;
    try {
      const verified = await jwtVerify(token, this.key, {
        algorithms: ['HS256'],
        issuer: ACCESS_TOKEN_ISSUER,
        audience: ACCESS_TOKEN_AUDIENCE,
        // Default clock tolerance is 0; a small window covers API clock drift.
        clockTolerance: 5,
      });
      payload = verified.payload;
    } catch {
      // jose errors name the failing step; that detail must not leave the module.
      throw DomainError.unauthorized();
    }
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
}

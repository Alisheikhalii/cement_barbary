import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { decodeJwt, SignJWT, type JWTHeaderParameters } from 'jose';
import { describe, expect, it } from 'vitest';
import { v7 as uuidv7 } from 'uuid';

import { parseEnv, type AppConfig } from '../../config/env.js';
import {
  ACCESS_TOKEN_AUDIENCE,
  ACCESS_TOKEN_ISSUER,
  credentialFingerprint,
  PASSWORD_CHANGE_TOKEN_AUDIENCE,
  PASSWORD_CHANGE_TOKEN_TTL_SECONDS,
  TokenService,
  type AccessTokenInput,
} from './token.service.js';

/**
 * Access-token behaviour (ADR-007 A7, owner condition 8): the algorithm is
 * pinned on verify, iss/aud/exp are checked, the claim set is exactly the
 * documented one, and every failure is the same generic 401.
 */

function makeConfig(overrides: Record<string, string> = {}): AppConfig {
  return parseEnv({
    DATABASE_URL: 'postgresql://bitabar_app:x@localhost:5432/bitabar',
    PII_ENC_KEY: randomBytes(32).toString('base64'),
    PII_HMAC_KEY: randomBytes(32).toString('base64'),
    AUTH_TOKEN_SECRET: overrides.AUTH_TOKEN_SECRET ?? randomBytes(32).toString('base64'),
    ...overrides,
  });
}

const KEY = randomBytes(32);
const config = makeConfig({ AUTH_TOKEN_SECRET: KEY.toString('base64') });
const service = new TokenService(config);

const INPUT: AccessTokenInput = {
  userId: uuidv7(),
  tenantId: uuidv7(),
  sessionId: uuidv7(),
  roles: ['DRIVER'],
};

const b64 = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');

/** Signs a token with the real key but caller-chosen header/payload fields. */
function craft(
  payload: Record<string, unknown>,
  header: JWTHeaderParameters = { alg: 'HS256', typ: 'JWT' },
): Promise<string> {
  return new SignJWT(payload).setProtectedHeader(header).sign(new Uint8Array(KEY));
}

const now = (): number => Math.floor(Date.now() / 1000);

/** Numeric claim or a test failure — avoids non-null assertions (lint bans them). */
function num(value: unknown): number {
  if (typeof value !== 'number') {
    throw new Error('expected a numeric claim');
  }
  return value;
}

async function expectUnauthorized(token: string): Promise<void> {
  await expect(service.verifyAccessToken(token)).rejects.toMatchObject({
    code: 'UNAUTHORIZED',
    statusCode: 401,
  });
}

describe('TokenService.signAccessToken', () => {
  it('issues exactly the documented claim set — no PII', async () => {
    const token = await service.signAccessToken(INPUT);
    const payload = decodeJwt(token);
    expect(Object.keys(payload).sort()).toEqual(
      ['aud', 'exp', 'iat', 'iss', 'jti', 'roles', 'sid', 'sub', 'tid'].sort(),
    );
    expect(payload).toMatchObject({
      sub: INPUT.userId,
      tid: INPUT.tenantId,
      sid: INPUT.sessionId,
      roles: ['DRIVER'],
      iss: ACCESS_TOKEN_ISSUER,
      aud: ACCESS_TOKEN_AUDIENCE,
    });
    expect(num(payload.exp) - num(payload.iat)).toBe(600);
    expect(payload.jti).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('round-trips through verifyAccessToken', async () => {
    const token = await service.signAccessToken(INPUT);
    await expect(service.verifyAccessToken(token)).resolves.toMatchObject({
      sub: INPUT.userId,
      tid: INPUT.tenantId,
      sid: INPUT.sessionId,
      roles: ['DRIVER'],
    });
  });

  it('honours AUTH_ACCESS_TOKEN_TTL_SECONDS', async () => {
    const shortLived = new TokenService(
      makeConfig({
        AUTH_TOKEN_SECRET: KEY.toString('base64'),
        AUTH_ACCESS_TOKEN_TTL_SECONDS: '120',
      }),
    );
    const payload = decodeJwt(await shortLived.signAccessToken(INPUT));
    expect(num(payload.exp) - num(payload.iat)).toBe(120);
  });
});

describe('TokenService.verifyAccessToken — algorithm pinning (condition 8)', () => {
  it('rejects an unsigned alg=none token', async () => {
    const iat = now();
    const none = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({
      sub: INPUT.userId,
      tid: INPUT.tenantId,
      sid: INPUT.sessionId,
      roles: ['DRIVER'],
      jti: uuidv7(),
      iat,
      exp: iat + 600,
      iss: ACCESS_TOKEN_ISSUER,
      aud: ACCESS_TOKEN_AUDIENCE,
    })}.`;
    await expectUnauthorized(none);
  });

  it('rejects HS384 and HS512 tokens signed with the same key', async () => {
    const payload = {
      sub: INPUT.userId,
      tid: INPUT.tenantId,
      sid: INPUT.sessionId,
      roles: ['DRIVER'],
      jti: uuidv7(),
      iat: now(),
      exp: now() + 600,
      iss: ACCESS_TOKEN_ISSUER,
      aud: ACCESS_TOKEN_AUDIENCE,
    };
    await expectUnauthorized(await craft(payload, { alg: 'HS384', typ: 'JWT' }));
    await expectUnauthorized(await craft(payload, { alg: 'HS512', typ: 'JWT' }));
  });

  it('rejects an RS256 token (asymmetric alg confused-deputy)', async () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const payload = {
      sub: INPUT.userId,
      tid: INPUT.tenantId,
      sid: INPUT.sessionId,
      roles: ['DRIVER'],
      jti: uuidv7(),
      iat: now(),
      exp: now() + 600,
      iss: ACCESS_TOKEN_ISSUER,
      aud: ACCESS_TOKEN_AUDIENCE,
    };
    const token = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .sign(privateKey);
    await expectUnauthorized(token);
  });

  it('rejects a token signed with a different secret', async () => {
    const other = new TokenService(
      makeConfig({ AUTH_TOKEN_SECRET: randomBytes(32).toString('base64') }),
    );
    await expectUnauthorized(await other.signAccessToken(INPUT));
  });

  it('rejects a tampered payload', async () => {
    const token = await service.signAccessToken(INPUT);
    const [head, , sig] = token.split('.') as [string, string, string];
    const forged = b64({ ...decodeJwt(token), roles: ['FACTORY_OPERATOR'] });
    await expectUnauthorized(`${head}.${forged}.${sig}`);
  });
});

describe('TokenService.verifyAccessToken — claims and time', () => {
  const base = () => ({
    sub: INPUT.userId,
    tid: INPUT.tenantId,
    sid: INPUT.sessionId,
    roles: ['DRIVER'],
    jti: uuidv7(),
    iat: now(),
    exp: now() + 600,
    iss: ACCESS_TOKEN_ISSUER,
    aud: ACCESS_TOKEN_AUDIENCE,
  });

  it('rejects an expired token', async () => {
    const iat = now() - 3600;
    const token = await craft({
      ...base(),
      iat,
      exp: iat + 60,
    });
    await expectUnauthorized(token);
  });

  it('rejects a wrong audience and a wrong issuer', async () => {
    await expectUnauthorized(await craft({ ...base(), aud: 'someone-else' }));
    await expectUnauthorized(await craft({ ...base(), iss: 'evil' }));
  });

  it('rejects a missing / malformed claim set', async () => {
    const { sid, ...withoutSid } = base();
    expect(sid).toBeTruthy();
    await expectUnauthorized(await craft(withoutSid));
    await expectUnauthorized(await craft({ ...base(), roles: 'DRIVER' }));
    await expectUnauthorized(await craft({ ...base(), sub: 'not-a-uuid' }));
    await expectUnauthorized(await craft({ ...base(), roles: Array(9).fill('DRIVER') }));

    const { exp, ...withoutExp } = base();
    expect(exp).toBeGreaterThan(0);
    await expectUnauthorized(await craft(withoutExp));
  });

  it('rejects extra claims — a password-change token must not verify as an access token', async () => {
    await expectUnauthorized(await craft({ ...base(), scope: 'password_change' }));
  });

  it('rejects empty, malformed and oversized input without throwing anything else', async () => {
    await expectUnauthorized('');
    await expectUnauthorized('a.b.c');
    await expectUnauthorized(`${'x'.repeat(5000)}.${'y'.repeat(5000)}.z`);
  });

  it('never puts the failure reason in the error', async () => {
    try {
      await service.verifyAccessToken('a.b.c');
      expect.unreachable();
    } catch (err) {
      expect(err).toMatchObject({ code: 'UNAUTHORIZED', statusCode: 401 });
      expect((err as Error).message).not.toMatch(/signature|jwt|algorithm|expired/i);
    }
  });
});

describe('password-change token (A19)', () => {
  const fingerprint = credentialFingerprint('$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA');

  it('signs exactly the documented claims with its own audience and 300 s TTL', async () => {
    const token = await service.signPasswordChangeToken({
      userId: INPUT.userId,
      tenantId: INPUT.tenantId,
      fingerprint,
    });
    const payload = decodeJwt(token);
    expect(Object.keys(payload).sort()).toEqual(
      ['aud', 'chg', 'exp', 'iat', 'iss', 'jti', 'sub', 'tid'].sort(),
    );
    expect(payload).toMatchObject({
      sub: INPUT.userId,
      tid: INPUT.tenantId,
      chg: fingerprint,
      aud: PASSWORD_CHANGE_TOKEN_AUDIENCE,
    });
    expect(num(payload.exp) - num(payload.iat)).toBe(PASSWORD_CHANGE_TOKEN_TTL_SECONDS);
    await expect(service.verifyPasswordChangeToken(token)).resolves.toMatchObject({
      sub: INPUT.userId,
      tid: INPUT.tenantId,
      chg: fingerprint,
    });
  });

  it('is not interchangeable with an access token, in either direction', async () => {
    const access = await service.signAccessToken(INPUT);
    const change = await service.signPasswordChangeToken({
      userId: INPUT.userId,
      tenantId: INPUT.tenantId,
      fingerprint,
    });
    await expect(service.verifyPasswordChangeToken(access)).rejects.toMatchObject({
      code: 'UNAUTHORIZED',
    });
    await expect(service.verifyAccessToken(change)).rejects.toMatchObject({
      code: 'UNAUTHORIZED',
    });
  });

  it('rejects a tampered fingerprint claim', async () => {
    const token = await service.signPasswordChangeToken({
      userId: INPUT.userId,
      tenantId: INPUT.tenantId,
      fingerprint,
    });
    const [head, , sig] = token.split('.') as [string, string, string];
    const forged = b64({ ...decodeJwt(token), chg: credentialFingerprint('other') });
    await expect(
      service.verifyPasswordChangeToken(`${head}.${forged}.${sig}`),
    ).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('rejects an expired change token', async () => {
    const iat = now() - 3600;
    const token = await new SignJWT({
      tid: INPUT.tenantId,
      chg: fingerprint,
      iss: ACCESS_TOKEN_ISSUER,
      aud: PASSWORD_CHANGE_TOKEN_AUDIENCE,
      iat,
      exp: iat + 60,
      jti: uuidv7(),
      sub: INPUT.userId,
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .sign(new Uint8Array(KEY));
    await expect(service.verifyPasswordChangeToken(token)).rejects.toMatchObject({
      code: 'UNAUTHORIZED',
    });
  });

  it('credentials fingerprint is deterministic, domain-separated and changes with the hash', () => {
    const a = credentialFingerprint('$argon2id$v=19$m=19456,t=2,p=1$a$b');
    const b = credentialFingerprint('$argon2id$v=19$m=19456,t=2,p=1$a$c');
    expect(a).toBe(credentialFingerprint('$argon2id$v=19$m=19456,t=2,p=1$a$b'));
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a).not.toContain('argon2id');
  });
});

import type { AssignableRole } from '../users/users.types.js';

/**
 * Pluggable credential verification (ADR-007 A6). v1 ships PasswordMethod
 * (T06) only; OtpMethod (SMS, plan §J) plugs in later without changing the
 * login flow, tokens, sessions or tables.
 */

/** Who a credential method proved the caller to be. No PII, no secrets. */
export interface AuthIdentity {
  readonly tenantId: string;
  readonly userId: string;
  readonly roles: readonly AssignableRole[];
}

/**
 * One generic failure shape (A3): the reason never leaves the server, so the
 * login endpoint can answer every failure — unknown user, malformed
 * identifier, wrong password, delayed, disabled — identically.
 */
export type CredentialVerifyResult =
  { readonly ok: true; readonly identity: AuthIdentity } | { readonly ok: false };

/** Password login input, staff (`username@tenant-code`). */
export interface StaffPasswordInput {
  readonly kind: 'staff';
  /** `username@tenant-code`, exactly as typed. */
  readonly identifier: string;
  readonly password: string;
}

/** Password login input, driver (phone + numeric PIN). */
export interface DriverPasswordInput {
  readonly kind: 'driver';
  /** Phone exactly as typed; normalization happens server-side (A4). */
  readonly phone: string;
  readonly password: string;
}

export type PasswordLoginInput = StaffPasswordInput | DriverPasswordInput;

export interface CredentialMethod<TInput = unknown> {
  /** Stable method id, e.g. 'password'; 'otp' when §J lands. */
  readonly method: string;
  verify(input: TInput): Promise<CredentialVerifyResult>;
}

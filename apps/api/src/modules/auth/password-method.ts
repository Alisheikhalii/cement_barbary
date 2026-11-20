import { randomUUID } from 'node:crypto';

import { Inject, Injectable } from '@nestjs/common';

import { APP_CONFIG } from '../../config/config.module.js';
import type { AppConfig } from '../../config/env.js';
import { normalizePhone } from '../../security/pii/normalize.js';
import { PiiService } from '../../security/pii/pii-crypto.js';
import { AuthLookupService } from '../../db/auth-lookup.service.js';
import type { AuthLookupRow } from '../../db/auth-lookup.js';
import { CredentialFailureStore } from '../../db/credential-failure-store.js';
import { TenantContext } from '../../db/tenant-context.js';
import { AuthRepository } from './auth.repository.js';
import type {
  AuthIdentity,
  CredentialMethod,
  CredentialVerifyResult,
  PasswordLoginInput,
} from './credential-method.js';
import { PasswordService } from './password.service.js';
import { TenantDirectory } from './tenant-directory.js';
import { USERNAME_PATTERN, type AssignableRole } from '../users/users.types.js';

/**
 * The password implementation of CredentialMethod (ADR-007 A4/A5/A6, T06).
 * It only VERIFIES credentials — sessions, tokens and HTTP are the service's
 * job — and it never returns a reason: unknown tenant/user/phone, malformed
 * identifiers, wrong passwords, delayed, expired temporary passwords and
 * disabled accounts all come back as `{ ok: false }` after the same Argon2 cost
 * (a real verify or the dummy path).
 */

/** Same shape as the tenants_code_format CHECK. */
const TENANT_CODE_PATTERN = /^[a-z0-9-]{2,32}$/;

@Injectable()
export class PasswordMethod implements CredentialMethod<PasswordLoginInput> {
  readonly method = 'password';

  constructor(
    @Inject(PasswordService) private readonly passwords: PasswordService,
    @Inject(AuthLookupService) private readonly lookup: AuthLookupService,
    @Inject(TenantDirectory) private readonly directory: TenantDirectory,
    @Inject(AuthRepository) private readonly accounts: AuthRepository,
    @Inject(CredentialFailureStore) private readonly failures: CredentialFailureStore,
    @Inject(TenantContext) private readonly tenantContext: TenantContext,
    @Inject(PiiService) private readonly pii: PiiService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async verify(input: PasswordLoginInput): Promise<CredentialVerifyResult> {
    return input.kind === 'staff'
      ? this.verifyStaff(input.identifier, input.password)
      : this.verifyDriver(input.phone, input.password);
  }

  /** Unknown / malformed input still burns one dummy verify (A3 timing). */
  private async fail(password: string): Promise<CredentialVerifyResult> {
    await this.passwords.verifyDummy(password);
    await this.dummyFailureWrite();
    return { ok: false };
  }

  /**
   * A3 constant-cost failure: a real wrong password pays one bookkeeping
   * transaction (BEGIN/SET/UPDATE/COMMIT on user_credentials). Paths that
   * cannot write a counter (unknown tenant/user/phone, delayed, expired temp
   * password, correct-password-on-disabled) run the SAME transaction against a
   * random tenant/user instead — it matches zero rows, but the round-trip and
   * commit cost is paid, so response timing does not reveal account state.
   */
  private async dummyFailureWrite(): Promise<void> {
    await this.failures.record(
      randomUUID(),
      randomUUID(),
      this.config.auth.loginDelay.baseSeconds,
      this.config.auth.loginDelay.maxSeconds,
    );
  }

  private async verifyStaff(identifier: string, password: string): Promise<CredentialVerifyResult> {
    const at = identifier.lastIndexOf('@');
    const username = at > 0 ? identifier.slice(0, at) : '';
    const tenantCode = at > 0 ? identifier.slice(at + 1) : '';
    if (!USERNAME_PATTERN.test(username) || !TENANT_CODE_PATTERN.test(tenantCode)) {
      return this.fail(password);
    }
    // The tenant comes from the identifier via the server-side directory —
    // never from a client-supplied tenant field (A4).
    const tenant = await this.directory.findByCode(tenantCode);
    if (tenant === null) {
      return this.fail(password);
    }
    const rows = await this.lookup.lookupUsername(tenantCode, username);
    const row = rows[0];
    if (row === undefined) {
      return this.fail(password);
    }
    return this.evaluate(row, password);
  }

  /**
   * Driver login fans out server-side over the cached tenant list (A4/A5).
   * One phone may match several tenants: each match is verified and delay
   * counters advance per matched row; the first successful match wins.
   */
  private async verifyDriver(phone: string, password: string): Promise<CredentialVerifyResult> {
    let normalized: string;
    try {
      normalized = normalizePhone(phone);
    } catch {
      return this.fail(password);
    }
    let rows = await this.lookupFanout(normalized, false);
    if (rows.length === 0) {
      // One forced refresh: the phone may belong to a tenant created a moment ago.
      rows = await this.lookupFanout(normalized, true);
    }
    if (rows.length === 0) {
      return this.fail(password);
    }
    for (const row of rows) {
      const result = await this.evaluate(row, password);
      if (result.ok) {
        return result;
      }
    }
    return { ok: false };
  }

  private async lookupFanout(normalizedPhone: string, force: boolean): Promise<AuthLookupRow[]> {
    const tenants = await this.directory.list(force);
    const pairs = tenants.map((tenant) => ({
      tenantId: tenant.id,
      phoneHash: this.pii.blindIndex('phone', tenant.id, normalizedPhone),
    }));
    return this.lookup.lookupPhone(pairs);
  }

  /**
   * One credential row. Expiry and delay skip the real comparison but still
   * pay the dummy cost; a wrong password advances the progressive delay
   * (A2); a correct password on a disabled account is still a failure.
   */
  private async evaluate(row: AuthLookupRow, password: string): Promise<CredentialVerifyResult> {
    const now = Date.now();
    if (
      row.temporaryPasswordExpiresAt !== null &&
      row.temporaryPasswordExpiresAt.getTime() <= now
    ) {
      await this.passwords.verifyDummy(password);
      await this.dummyFailureWrite();
      return { ok: false };
    }
    if (row.nextAttemptAt !== null && row.nextAttemptAt.getTime() > now) {
      // Under delay: no real comparison (so no password guessing), same CPU cost.
      await this.passwords.verifyDummy(password);
      await this.dummyFailureWrite();
      return { ok: false };
    }
    const matches = await this.passwords.verify(row.passwordHash, password);
    if (!matches) {
      if (row.status === 'active') {
        await this.registerFailure(row);
      } else {
        // Disabled + wrong password: no counter may advance, but the path still
        // pays the same bookkeeping transaction as an active failure (A3).
        await this.dummyFailureWrite();
      }
      return { ok: false };
    }
    if (row.status !== 'active') {
      // Correct password but a disabled account: no counter write happens, so
      // pay the same bookkeeping cost as a wrong password (A3).
      await this.dummyFailureWrite();
      return { ok: false };
    }
    await this.resetFailures(row);
    const identity: AuthIdentity = {
      tenantId: row.tenantId,
      userId: row.userId,
      roles: row.roles as readonly AssignableRole[],
      mustChangePassword: row.mustChangePassword,
    };
    return { ok: true, identity };
  }

  /**
   * A2: the store increments the counter and computes base × 2^(n-1) in one
   * atomic UPDATE, so concurrent failures escalate correctly.
   */
  private async registerFailure(row: AuthLookupRow): Promise<void> {
    await this.failures.record(
      row.tenantId,
      row.userId,
      this.config.auth.loginDelay.baseSeconds,
      this.config.auth.loginDelay.maxSeconds,
    );
  }

  private async resetFailures(row: AuthLookupRow): Promise<void> {
    await this.tenantContext.run({ tenantId: row.tenantId }, () =>
      this.accounts.resetFailures(row.userId),
    );
  }
}

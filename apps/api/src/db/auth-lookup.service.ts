import { Inject, Injectable } from '@nestjs/common';

import {
  AUTH_LOOKUP_MAX_PAIRS,
  authLookupPhone,
  authLookupSession,
  authLookupUsername,
  listTenants,
  type AuthLookupRow,
  type AuthSessionLookupRow,
} from './auth-lookup.js';
import { DB, type Db } from './database.providers.js';

/**
 * Nest provider around the pre-auth SECURITY DEFINER lookups (ADR-007 A4/A8/
 * A17). It lives inside src/db/** so the DB token never leaks into a feature
 * module (D11) and so callers cannot run raw SQL. These functions are the only
 * way to read auth data without a tenant context.
 */
@Injectable()
export class AuthLookupService {
  constructor(@Inject(DB) private readonly db: Db) {}

  /** Active tenants only ({id, code}); the driver fan-out list. */
  listTenants(): Promise<{ id: string; code: string }[]> {
    return listTenants(this.db);
  }

  /** Staff lookup by `username@tenant-code`; identical empty result for unknown input. */
  lookupUsername(tenantCode: string, username: string): Promise<AuthLookupRow[]> {
    return authLookupUsername(this.db, tenantCode, username);
  }

  /**
   * Driver fan-out over (tenant_id, phone blind-index) pairs. Chunked at the
   * function's hard cap so a growing tenant list never silently drops matches.
   */
  async lookupPhone(
    pairs: readonly { tenantId: string; phoneHash: Buffer }[],
  ): Promise<AuthLookupRow[]> {
    const rows: AuthLookupRow[] = [];
    for (let offset = 0; offset < pairs.length; offset += AUTH_LOOKUP_MAX_PAIRS) {
      const chunk = pairs.slice(offset, offset + AUTH_LOOKUP_MAX_PAIRS);
      rows.push(...(await authLookupPhone(this.db, chunk)));
    }
    return rows;
  }

  /** Resolves a SHA-256 refresh hash to its session, or null. */
  lookupSession(refreshHash: Buffer): Promise<AuthSessionLookupRow | null> {
    return authLookupSession(this.db, refreshHash);
  }
}

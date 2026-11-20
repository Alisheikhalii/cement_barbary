import { Inject, Injectable } from '@nestjs/common';

import { authLookupSession, type AuthSessionLookupRow } from './auth-lookup.js';
import { DB, type Db } from './database.providers.js';

/**
 * Nest provider around the pre-auth session lookup (ADR-007 A8/A17). It lives
 * inside src/db/** so the DB token never leaks into a feature module (D11) and
 * so callers cannot run raw SQL. The function itself is the SECURITY DEFINER
 * `app.auth_lookup_session` — the only way to resolve a refresh cookie before
 * a tenant context exists.
 */
@Injectable()
export class AuthLookupService {
  constructor(@Inject(DB) private readonly db: Db) {}

  /** Resolves a SHA-256 refresh hash to its session, or null. */
  lookupSession(refreshHash: Buffer): Promise<AuthSessionLookupRow | null> {
    return authLookupSession(this.db, refreshHash);
  }
}

import { Global, Module } from '@nestjs/common';

import { AuthLookupService } from './auth-lookup.service.js';
import { AuthzFreshness } from './authz-freshness.js';
import { CredentialFailureStore } from './credential-failure-store.js';
import { databaseProviders, DB, PG_POOL } from './database.providers.js';
import { DbHealth } from './db-health.js';
import { RateLimitStore } from './rate-limit-store.js';
import { TenantContext } from './tenant-context.js';
import { TenantDb } from './tenant-db.js';

/**
 * Global so every module can inject DbHealth/TenantContext/TenantDb without
 * imports. TenantDb is the only public path to tenant data (D10); the raw
 * PG_POOL/DB tokens stay internal to src/db/** (D11, lint-enforced in T09).
 */
@Global()
@Module({
  providers: [
    ...databaseProviders,
    DbHealth,
    TenantContext,
    TenantDb,
    AuthLookupService,
    AuthzFreshness,
    RateLimitStore,
    CredentialFailureStore,
  ],
  exports: [
    PG_POOL,
    DB,
    DbHealth,
    TenantContext,
    TenantDb,
    AuthLookupService,
    AuthzFreshness,
    RateLimitStore,
    CredentialFailureStore,
  ],
})
export class DatabaseModule {}

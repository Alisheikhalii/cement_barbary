import { Inject, Injectable } from '@nestjs/common';

import { AuthLookupService } from '../../db/auth-lookup.service.js';

/**
 * 60-second cache of active tenants (ADR-007 A4) used for staff tenant-code
 * resolution and the driver phone fan-out. A miss (unknown code, or a phone
 * that matched no tenant) forces ONE refresh, so a tenant created seconds ago
 * can still log in; concurrent callers share a single in-flight load.
 */

const CACHE_TTL_MS = 60_000;

export interface DirectoryTenant {
  readonly id: string;
  readonly code: string;
}

@Injectable()
export class TenantDirectory {
  private cache: { tenants: readonly DirectoryTenant[]; loadedAt: number } | undefined;
  private inflight: Promise<readonly DirectoryTenant[]> | undefined;

  constructor(@Inject(AuthLookupService) private readonly lookup: AuthLookupService) {}

  /** The cached list; `force` reloads regardless of age. */
  async list(force = false): Promise<readonly DirectoryTenant[]> {
    if (!force) {
      if (this.cache !== undefined && Date.now() - this.cache.loadedAt < CACHE_TTL_MS) {
        return this.cache.tenants;
      }
      if (this.inflight !== undefined) {
        return this.inflight;
      }
    }
    const load = this.lookup.listTenants().then((tenants) => {
      this.cache = { tenants, loadedAt: Date.now() };
      return tenants;
    });
    this.inflight = load;
    try {
      return await load;
    } finally {
      if (this.inflight === load) {
        this.inflight = undefined;
      }
    }
  }

  /** Resolves a tenant code; a miss forces one cache refresh (A4). */
  async findByCode(code: string): Promise<DirectoryTenant | null> {
    const cached = (await this.list()).find((tenant) => tenant.code === code);
    if (cached !== undefined) {
      return cached;
    }
    return (await this.list(true)).find((tenant) => tenant.code === code) ?? null;
  }
}

import { AsyncLocalStorage } from 'node:async_hooks';

import { Injectable } from '@nestjs/common';
import { z } from 'zod';

import { DomainError } from '../common/errors/domain-error.js';

/** Who the current unit of work belongs to. Both ids are UUIDs (validated in TenantContext.run). */
export interface TenantScope {
  readonly tenantId: string;
  readonly carrierId?: string;
}

/**
 * Internal AsyncLocalStorage store. `tx` is opaque here — TenantDb (same
 * src/db/** boundary) owns the transaction handle and casts it back. This
 * type and the two functions below are internal to src/db and are not
 * exported from the Nest module.
 */
export interface TenantStore {
  readonly scope: TenantScope;
  readonly tx: unknown;
}

const storage = new AsyncLocalStorage<TenantStore>();

const scopeSchema = z.object({
  tenantId: z.uuid(),
  carrierId: z.uuid().optional(),
});

/** Internal: the active store, used by TenantDb to find the open transaction. */
export function getTenantStore(): TenantStore | undefined {
  return storage.getStore();
}

/** Internal: bind an open transaction handle to the current scope, used by TenantDb only. */
export function runWithTenantTx<T>(tx: unknown, fn: () => Promise<T>): Promise<T> {
  const store = storage.getStore();
  if (!store) {
    throw DomainError.tenantContextMissing();
  }
  return storage.run({ scope: store.scope, tx }, fn);
}

function sameScope(a: TenantScope, b: TenantScope): boolean {
  return a.tenantId === b.tenantId && a.carrierId === b.carrierId;
}

/**
 * Carries the tenant/carrier scope through async execution (ADR-005 D5).
 * Deliberately not NestJS request-scoped: code that touches tenant data wraps
 * its work in run(). The store lives only for the duration of the callback,
 * on success and on error alike.
 */
@Injectable()
export class TenantContext {
  /**
   * Validates the scope with Zod (UUIDs, before any SQL) and runs `fn` with it
   * active. Switching to a DIFFERENT tenant or carrier while a transaction is
   * active throws TENANT_CONTEXT_MISSING and leaves the outer context
   * untouched; nesting the SAME scope is allowed and keeps the transaction.
   */
  async run<T>(scope: TenantScope, fn: () => Promise<T>): Promise<T> {
    const parsed = scopeSchema.safeParse(scope);
    if (!parsed.success) {
      throw DomainError.badInput();
    }
    const valid: TenantScope =
      parsed.data.carrierId === undefined
        ? { tenantId: parsed.data.tenantId }
        : { tenantId: parsed.data.tenantId, carrierId: parsed.data.carrierId };

    const active = storage.getStore();
    if (active?.tx !== undefined && !sameScope(active.scope, valid)) {
      // Changing tenants inside an open transaction would silently mix rows.
      throw DomainError.tenantContextMissing();
    }
    return storage.run({ scope: valid, tx: active?.tx }, fn);
  }

  /** The active scope, or undefined outside run(). */
  current(): TenantScope | undefined {
    return storage.getStore()?.scope;
  }

  /** The active scope; throws TENANT_CONTEXT_MISSING when there is none (fail closed). */
  require(): TenantScope {
    const scope = this.current();
    if (!scope) {
      throw DomainError.tenantContextMissing();
    }
    return scope;
  }
}

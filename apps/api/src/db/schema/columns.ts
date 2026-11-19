import { sql } from 'drizzle-orm';
import { customType, timestamp, uuid } from 'drizzle-orm/pg-core';
import { v7 as uuidv7 } from 'uuid';

/**
 * Standard column helpers (ADR-005 D8). `tenantId()` lives in tenants.ts to
 * avoid an import cycle and is re-exported from the schema index.
 */

/** Primary key: UUID v7 generated in the app (time-ordered, index-friendly). */
export const id = () =>
  uuid('id')
    .primaryKey()
    .$defaultFn(() => uuidv7());

export const timestamps = {
  createdAt: timestamp('created_at', { withTimezone: true, mode: 'date' }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true, mode: 'date' })
    .notNull()
    .defaultNow()
    .$onUpdateFn(() => sql`now()`),
};

/** Nullable; users.created_by gets a composite FK in users.ts (ADR-006 U6). */
export const createdBy = () => uuid('created_by');

/** Soft delete (operational tables only). */
export const deletedAt = () => timestamp('deleted_at', { withTimezone: true, mode: 'date' });

/**
 * Binary column for encrypted PII blobs and blind-index hashes (ADR-006 U7/U8).
 * node-pg maps Buffer <-> bytea natively, so no codec is needed.
 */
export const bytea = (name: string) =>
  customType<{ data: Buffer; driverData: Buffer }>({
    dataType: () => 'bytea',
  })(name);

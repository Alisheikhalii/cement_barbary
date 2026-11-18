import { sql } from 'drizzle-orm';
import { timestamp, uuid } from 'drizzle-orm/pg-core';
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

/** Nullable; the FK to users is added in F1-03. */
export const createdBy = () => uuid('created_by');

/** Soft delete (operational tables only). */
export const deletedAt = () => timestamp('deleted_at', { withTimezone: true, mode: 'date' });

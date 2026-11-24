import { toAuditSnapshot } from '../../audit/audit-snapshot.js';

/**
 * Wire and persistence shapes for destinations (F1-07 T04, ADR-011).
 *
 * `nameKey`, `tenantId` and `deletedAt` are server-only: they never appear in
 * the HTTP DTO. The audit snapshot is built from the row through the
 * per-entity allowlist, so a future column cannot leak into `audit_logs`
 * unless it is added there too.
 */

export interface DestinationRow {
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  readonly nameKey: string;
  readonly provinceName: string | null;
  readonly isActive: boolean;
  readonly displayOrder: number;
  readonly version: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly deletedAt: Date | null;
}

export interface DestinationDto {
  readonly id: string;
  readonly name: string;
  readonly provinceName: string | null;
  readonly isActive: boolean;
  readonly displayOrder: number;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/** The runtime role's view of a row: no key, no tenant, no deletion marker. */
export function toDestinationDto(row: DestinationRow): DestinationDto {
  return {
    id: row.id,
    name: row.name,
    provinceName: row.provinceName,
    isActive: row.isActive,
    displayOrder: row.displayOrder,
    version: row.version,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

/**
 * B8 allowlist projection. `createdAt`/`updatedAt`/`deletedAt` are Dates; the
 * audit snapshot projects them to ISO strings. `nameKey` and `tenantId` are
 * deliberately absent.
 */
export function destinationSnapshot(row: DestinationRow): Record<string, unknown> | null {
  return toAuditSnapshot('destination', {
    id: row.id,
    name: row.name,
    provinceName: row.provinceName,
    isActive: row.isActive,
    displayOrder: row.displayOrder,
    version: row.version,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    deletedAt: row.deletedAt,
  });
}

import { toAuditSnapshot } from '../../audit/audit-snapshot.js';

/** Wire and audit shapes for loader-type groups and loader types (F1-07 T06). */

export interface LoaderTypeGroupRow {
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  readonly nameKey: string;
  readonly isActive: boolean;
  readonly displayOrder: number;
  readonly version: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly deletedAt: Date | null;
}

export interface LoaderTypeRow {
  readonly id: string;
  readonly tenantId: string;
  readonly groupId: string;
  readonly name: string;
  readonly nameKey: string;
  readonly isActive: boolean;
  readonly displayOrder: number;
  readonly version: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly deletedAt: Date | null;
}

export interface LoaderTypeGroupDto {
  readonly id: string;
  readonly name: string;
  readonly isActive: boolean;
  readonly displayOrder: number;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface LoaderTypeDto {
  readonly id: string;
  readonly groupId: string;
  readonly name: string;
  readonly isActive: boolean;
  readonly displayOrder: number;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export function toLoaderTypeGroupDto(row: LoaderTypeGroupRow): LoaderTypeGroupDto {
  return {
    id: row.id,
    name: row.name,
    isActive: row.isActive,
    displayOrder: row.displayOrder,
    version: row.version,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function toLoaderTypeDto(row: LoaderTypeRow): LoaderTypeDto {
  return {
    id: row.id,
    groupId: row.groupId,
    name: row.name,
    isActive: row.isActive,
    displayOrder: row.displayOrder,
    version: row.version,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

/** B8: business fields + version + deletedAt; `nameKey`/`tenantId` never. */
export function loaderTypeGroupSnapshot(row: LoaderTypeGroupRow): Record<string, unknown> | null {
  return toAuditSnapshot('loader_type_group', {
    id: row.id,
    name: row.name,
    isActive: row.isActive,
    displayOrder: row.displayOrder,
    version: row.version,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    deletedAt: row.deletedAt,
  });
}

/**
 * The type snapshot omits `groupId`: B8 puts the structural parent in
 * `metadata` so the before/after pair stays about the type's own business
 * fields. A move records both the old and the new group there.
 */
export function loaderTypeSnapshot(row: LoaderTypeRow): Record<string, unknown> | null {
  return toAuditSnapshot('loader_type', {
    id: row.id,
    name: row.name,
    isActive: row.isActive,
    displayOrder: row.displayOrder,
    version: row.version,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    deletedAt: row.deletedAt,
  });
}

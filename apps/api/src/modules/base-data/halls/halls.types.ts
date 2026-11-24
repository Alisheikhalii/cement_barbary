import { toAuditSnapshot } from '../../audit/audit-snapshot.js';

/** Wire and audit shapes for halls and their terminals (F1-07 T05). */

export interface HallRow {
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

export interface TerminalRow {
  readonly id: string;
  readonly tenantId: string;
  readonly hallId: string;
  readonly name: string;
  readonly nameKey: string;
  readonly isActive: boolean;
  readonly displayOrder: number;
  readonly version: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly deletedAt: Date | null;
}

export interface HallDto {
  readonly id: string;
  readonly name: string;
  readonly isActive: boolean;
  readonly displayOrder: number;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface TerminalDto {
  readonly id: string;
  readonly hallId: string;
  readonly name: string;
  readonly isActive: boolean;
  readonly displayOrder: number;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export function toHallDto(row: HallRow): HallDto {
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

export function toTerminalDto(row: TerminalRow): TerminalDto {
  return {
    id: row.id,
    hallId: row.hallId,
    name: row.name,
    isActive: row.isActive,
    displayOrder: row.displayOrder,
    version: row.version,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

/** B8: business fields + version + deletedAt; `nameKey`/`tenantId` never. */
export function hallSnapshot(row: HallRow): Record<string, unknown> | null {
  return toAuditSnapshot('hall', {
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
 * The terminal snapshot omits `hallId`: B8 puts the structural parent in
 * `metadata: { hallId }`, so the before/after pair stays about the terminal's
 * own business fields.
 */
export function terminalSnapshot(row: TerminalRow): Record<string, unknown> | null {
  return toAuditSnapshot('terminal', {
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

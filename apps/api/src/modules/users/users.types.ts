import { z } from 'zod';

/**
 * Input schemas and DTOs for UsersRepository (ADR-006 U15). Inputs are
 * whitelisted and strict — unknown fields are rejected, so `tenantId`,
 * `status`, `createdBy` or any PII column can never be mass-assigned from
 * caller input.
 */

/** The 3-role catalog after the T05b trim (owner decision). Anything else — including removed roles — is BAD_INPUT. */
export const ASSIGNABLE_ROLES = ['FACTORY_OPERATOR', 'CARRIER_ADMIN', 'DRIVER'] as const;
export type AssignableRole = (typeof ASSIGNABLE_ROLES)[number];

/**
 * Scope per role. This copy is re-verified on every write by the composite FK
 * (role_code, role_scope) → roles(code, scope), so it can never drift from the
 * catalog without an FK violation.
 */
export const ROLE_SCOPE: Record<AssignableRole, 'tenant' | 'carrier' | 'driver'> = {
  FACTORY_OPERATOR: 'tenant',
  CARRIER_ADMIN: 'carrier',
  DRIVER: 'driver',
};

/** Same rule as the users_username_format CHECK — rejected cheaply, before any SQL. */
export const USERNAME_PATTERN = /^[a-z0-9._-]{3,32}$/;

export const userIdSchema = z.uuid();

/**
 * create() input. strict: unknown keys are rejected (mass-assignment guard).
 * refine: at least one login path — mirrors the users_login_present CHECK.
 * national ID is absent BY DESIGN (owner Q3): no field exists to accept it.
 */
export const createUserInputSchema = z
  .strictObject({
    username: z.string().regex(USERNAME_PATTERN).optional(),
    displayName: z.string().trim().min(1).max(200),
    phone: z.string().min(1).max(40).optional(),
  })
  .refine((v) => v.username !== undefined || v.phone !== undefined);

export type CreateUserInput = z.infer<typeof createUserInputSchema>;

export const roleCodeSchema = z.enum(ASSIGNABLE_ROLES);

/**
 * What every read returns. Field-by-field built (never a row spread), so
 * phone_enc/phone_hash/national_id_* can never leak into a DTO — not even if
 * a column is added later (ADR-006 U11/U15).
 */
export interface UserDto {
  readonly id: string;
  readonly tenantId: string;
  readonly username: string | null;
  readonly displayName: string;
  readonly status: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

/** Structural view of a users row for the DTO mapper; extra columns (PII blobs) are ignored. */
export interface UserRowLike {
  id: string;
  tenantId: string;
  username: string | null;
  displayName: string;
  status: string;
  createdAt: Date;
  updatedAt: Date;
}

export function toUserDto(row: UserRowLike): UserDto {
  return {
    id: row.id,
    tenantId: row.tenantId,
    username: row.username,
    displayName: row.displayName,
    status: row.status,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

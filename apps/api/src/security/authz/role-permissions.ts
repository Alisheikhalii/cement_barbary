import type { PermissionName } from './permissions.js';

/**
 * Role → permission map (ADR-008 Z1/Z2/Z9). Roles are data (ADR-006); this map
 * is the reviewed code decision for who may do what.
 *
 * F1-05 gives CARRIER_ADMIN and DRIVER no data permission. CARRIER_ADMIN gets
 * carrier-scoped permissions only in F1-08, after `users.carrier_id` and the
 * carrier RLS policy exist; until then carrier scope fails closed in `can()`.
 */

export const ROLE_CODES = Object.freeze(['FACTORY_OPERATOR', 'CARRIER_ADMIN', 'DRIVER'] as const);

export type RoleCode = (typeof ROLE_CODES)[number];

export type RolePermissionMap = Readonly<Record<RoleCode, readonly PermissionName[]>>;

/** The tenant operator's full F1-05/F1-07/F1-08 catalog. */
const FACTORY_OPERATOR_PERMISSIONS = Object.freeze([
  'destination.read',
  'destination.write',
  'hall.read',
  'hall.write',
  'loader_type.read',
  'loader_type.write',
  'carrier.read',
  'carrier.write',
  'carrier_membership.write',
  'carrier_quota.write',
] as const satisfies readonly PermissionName[]);

/** No data permission in F1-05 (Z9). */
const NO_PERMISSIONS: readonly PermissionName[] = Object.freeze([]);

export const ROLE_PERMISSIONS = Object.freeze({
  FACTORY_OPERATOR: FACTORY_OPERATOR_PERMISSIONS,
  CARRIER_ADMIN: NO_PERMISSIONS,
  DRIVER: NO_PERMISSIONS,
} satisfies RolePermissionMap);

/** True only for one of the three catalog role codes. */
export function isRoleCode(value: string): value is RoleCode {
  return (ROLE_CODES as readonly string[]).includes(value);
}

/** Permissions held by a role; an unknown or removed role gets an empty list. */
export function permissionsForRole(role: string): readonly PermissionName[] {
  return isRoleCode(role) ? ROLE_PERMISSIONS[role] : NO_PERMISSIONS;
}

/** Whether a role string (known or not) holds a catalog permission. */
export function roleHasPermission(role: string, permission: PermissionName): boolean {
  return permissionsForRole(role).includes(permission);
}

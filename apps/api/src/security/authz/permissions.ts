/**
 * Permission catalog (ADR-008 Z1/Z2, F1-05). Permissions are code; roles are
 * data. Only permissions needed by existing routes and by F1-07 (base data) and
 * F1-08 (carriers) exist here. Later phases add their own permission together
 * with their endpoint; there is no `permissions` table.
 *
 * Every name is `resource.action`. `scope` says what the caller must be able to
 * resolve: `tenant` (tenant id only), `carrier` (tenant + carrier id) or `own`
 * (tenant + the principal's own user id). `sensitive` triggers the guard's
 * fresh user/tenant/role/session read (Z6, Z10).
 */

export const PERMISSION_SCOPES = Object.freeze(['tenant', 'carrier', 'own'] as const);

export type PermissionScope = (typeof PERMISSION_SCOPES)[number];

export interface PermissionDefinition {
  readonly scope: PermissionScope;
  readonly sensitive: boolean;
}

/** A frozen definition — freezing the outer map alone would leave entries mutable. */
function definePermission(scope: PermissionScope, sensitive: boolean): PermissionDefinition {
  return Object.freeze({ scope, sensitive });
}

/** The catalog. Object keys are the permission names; insertion order is stable for the matrix. */
export const PERMISSIONS = Object.freeze({
  'destination.read': definePermission('tenant', false),
  'destination.write': definePermission('tenant', false),
  'hall.read': definePermission('tenant', false),
  'hall.write': definePermission('tenant', false),
  'loader_type.read': definePermission('tenant', false),
  'loader_type.write': definePermission('tenant', false),
  'carrier.read': definePermission('tenant', false),
  'carrier.write': definePermission('tenant', false),
  'carrier_membership.write': definePermission('tenant', true),
  'carrier_quota.write': definePermission('tenant', true),
} satisfies Record<string, PermissionDefinition>);

export type PermissionName = keyof typeof PERMISSIONS;

export const PERMISSION_NAMES = Object.freeze(Object.keys(PERMISSIONS) as PermissionName[]);

/** Names are lower-case `resource.action`; underscores are allowed inside either part. */
export const PERMISSION_NAME_PATTERN = /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/;

/** True only for a key that exists in the catalog — never for an arbitrary string. */
export function isPermissionName(value: string): value is PermissionName {
  return Object.prototype.hasOwnProperty.call(PERMISSIONS, value);
}

/** The definition for a catalog name, or undefined for an unknown name. */
export function getPermission(name: string): PermissionDefinition | undefined {
  return isPermissionName(name) ? PERMISSIONS[name] : undefined;
}

/** True only for a known permission flagged sensitive (Z6/Z10). */
export function isSensitivePermission(name: string): boolean {
  return getPermission(name)?.sensitive === true;
}

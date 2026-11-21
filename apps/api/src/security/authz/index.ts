export {
  getPermission,
  isPermissionName,
  isSensitivePermission,
  PERMISSION_NAME_PATTERN,
  PERMISSION_NAMES,
  PERMISSION_SCOPES,
  PERMISSIONS,
} from './permissions.js';
export type { PermissionDefinition, PermissionName, PermissionScope } from './permissions.js';

export {
  isRoleCode,
  permissionsForRole,
  roleHasPermission,
  ROLE_CODES,
  ROLE_PERMISSIONS,
} from './role-permissions.js';
export type { RoleCode, RolePermissionMap } from './role-permissions.js';

export { createPrincipal } from './principal.js';
export type { Principal, PrincipalInput } from './principal.js';

export { can, scopeAllows } from './can.js';
export type { ResourceRef } from './can.js';

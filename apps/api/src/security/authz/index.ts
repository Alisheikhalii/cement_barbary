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

export { assertInScope, readAuthzContext, rowInScope } from './access-scope.js';
export type { AccessScope, AuthzContext, ScopedRow } from './access-scope.js';

export { AUDIT_HOOK, NoopAuditHook } from './audit-hook.js';
export type {
  AuditActor,
  AuditHook,
  AuditOutcome,
  AuditRecord,
  AuditResource,
} from './audit-hook.js';

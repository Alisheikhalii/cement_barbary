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

export {
  BODY_SCHEMA_KEY,
  PARAMS_SCHEMA_KEY,
  Public,
  QUERY_SCHEMA_KEY,
  RequirePermission,
  SelfService,
  ZodBody,
  ZodParams,
  ZodQuery,
} from './decorators.js';

export { FORBIDDEN_INPUT_KEYS, scanInputSchema } from './input-scan.js';
export type { InputScanCode, InputScanIssue, InputSurface } from './input-scan.js';

export {
  extractMatrixBlock,
  MATRIX_BEGIN,
  MATRIX_END,
  renderMatrix,
  replaceMatrixBlock,
} from './matrix.js';
export type { MatrixRoute } from './matrix.js';

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

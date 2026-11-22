import { API_PREFIX } from '@bitabar/shared';

import { scanInputSchema } from './input-scan.js';
import { isPermissionName, isSensitivePermission } from './permissions.js';
import { FORBIDDEN_REASON_RANGES } from './sensitive-reason.js';

/**
 * Route-scan rules (ADR-008 Z3/Z5/Z10/Z13; CP1 GB-03/GB-04, RD-03, SA-05).
 *
 * Pure functions over the production controller/route metadata collected from
 * Nest's DiscoveryService. The same data feeds three independent checks:
 *   1. the boot assertion (`AuthzBootCheck`) — the app refuses to start;
 *   2. the route-scan test — CI fails;
 *   3. the runtime guard — generic 403 even if 1 and 2 were bypassed.
 *
 * Server-side issue details may name the route; none of them ever reaches a
 * client.
 */

/** Public routes are allowed only on this reviewed list (plan §D, GB-03). */
export const PUBLIC_ROUTE_ALLOWLIST = Object.freeze([
  { method: 'GET', path: '/health/live' },
  { method: 'GET', path: '/health/ready' },
  { method: 'POST', path: '/api/v1/auth/login' },
  { method: 'POST', path: '/api/v1/auth/refresh' },
  { method: 'POST', path: '/api/v1/auth/logout' },
  { method: 'POST', path: '/api/v1/auth/password/change' },
] as const);

/**
 * Self-service routes are allowed only on this reviewed list (F1-06 T03,
 * closing F1-05 MEDIUM-2). `@SelfService` opens a route to every authenticated
 * principal, so a new one must be a reviewed allowlist change — not an
 * annotation someone adds to a new controller.
 */
export const SELF_SERVICE_ROUTE_ALLOWLIST = Object.freeze([
  { method: 'GET', path: '/api/v1/auth/me' },
] as const);

/**
 * Controllers allowed in a production process (RD-03). A new production
 * controller deliberately updates this list in a reviewed change; a probe,
 * fixture or test controller can never slip into the production surface.
 */
export const PRODUCTION_CONTROLLERS = Object.freeze([
  'HealthController',
  'AuthController',
] as const);

/**
 * A controller/module name that looks like a probe, fixture or test surface.
 * Case-sensitive CamelCase words, so `ContestModule`/`LatestModule` are not
 * false hits while `AuthTestModule` is.
 */
export const TEST_SURFACE_PATTERN = /(Probe|Fixture|Test|E2e|E2E)/;

export interface ScannedRoute {
  readonly moduleName: string;
  readonly controllerName: string;
  readonly handlerName: string;
  readonly method: string;
  readonly path: string;
  readonly isPublic: boolean;
  readonly isSelfService: boolean;
  readonly isPermission: boolean;
  readonly classLevelMarker: boolean;
  /** Raw `@RequirePermission` metadata when present (a string in production). */
  readonly permission: string | null;
  /** Schema recorded by `@ZodBody` (SA-05), or null. */
  readonly bodySchema: unknown;
  /** Schema recorded by `@ZodQuery` (T07 mass-assignment scan), or null. */
  readonly querySchema: unknown;
  /** Schema recorded by `@ZodParams` (T07 mass-assignment scan), or null. */
  readonly paramsSchema: unknown;
}

/** A controller discovered by Nest, including one with no route handlers. */
export interface ScannedController {
  readonly moduleName: string;
  readonly controllerName: string;
}

export type ScanEnvironment = 'development' | 'test' | 'production';

export interface ScanIssue {
  readonly code: string;
  readonly route: string;
  readonly detail: string;
}

/** Marker count as the scan sees it; one and only one is valid. */
export function markerCount(route: ScannedRoute): number {
  return Number(route.isPublic) + Number(route.isSelfService) + Number(route.isPermission);
}

/**
 * Method + path comparison for the runtime public-route check. The canonical
 * list is exact and case-sensitive. In production ONLY the canonical paths are
 * accepted; development/test also accept the unprefixed form used by direct
 * controller mounting (`/auth/login`). A malformed path (`..`, `%2e`, `%2f`,
 * `;param`, a different case) never matches and is rejected by the guard.
 */
export function isAllowlistedPublicRoute(
  method: string,
  rawPath: string,
  environment: ScanEnvironment,
): boolean {
  return isAllowlisted(method, rawPath, environment, PUBLIC_ROUTE_ALLOWLIST);
}

/** Same path rules as the public allowlist, for the reviewed self-service list (T03). */
export function isAllowlistedSelfServiceRoute(
  method: string,
  rawPath: string,
  environment: ScanEnvironment,
): boolean {
  return isAllowlisted(method, rawPath, environment, SELF_SERVICE_ROUTE_ALLOWLIST);
}

function isAllowlisted(
  method: string,
  rawPath: string,
  environment: ScanEnvironment,
  allowlist: readonly { readonly method: string; readonly path: string }[],
): boolean {
  const path = normalizeRequestPath(rawPath);
  const normalizedMethod = method.toUpperCase();
  const matches = (candidate: string): boolean =>
    allowlist.some((entry) => entry.method === normalizedMethod && entry.path === candidate);
  if (matches(path)) {
    return true;
  }
  if (environment === 'production') {
    return false;
  }
  const candidates = [path];
  if (path.startsWith(API_PREFIX)) {
    const stripped = path.slice(API_PREFIX.length);
    candidates.push(stripped.length === 0 ? '/' : stripped);
  } else {
    candidates.push(`${API_PREFIX}${path}`);
  }
  return candidates.some(matches);
}

function normalizeRequestPath(rawPath: string): string {
  const withoutQuery = rawPath.split('?')[0] ?? '/';
  // Preserve internal empty segments: `//api/v1/...` is NOT the canonical
  // route and must not become public merely because the guard collapsed it.
  const path = withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
  return path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
}

/** Normalizes Nest path metadata (`undefined`, `'/'`, arrays) into `a/b`. */
export function normalizeRoutePath(value: unknown): string {
  return normalizeRoutePaths(value)[0] ?? '';
}

/**
 * Expands Nest's array path metadata. A handler/controller mounted at
 * `['live', '']` registers BOTH paths; flattening them would hide one from the
 * scan, so every path becomes its own scanned route.
 */
export function normalizeRoutePaths(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((part) => normalizeRoutePaths(part));
  }
  if (typeof value !== 'string') {
    return [''];
  }
  return [value.replace(/^\/+|\/+$/g, '')];
}

/**
 * Canonical path the matrix and the §D allowlist use. Health is excluded from
 * the global prefix in `main.ts`; every other controller is prefixed.
 */
export function canonicalRoutePath(
  controllerPath: string,
  handlerPath: string,
  unprefixed = false,
): string {
  const base = unprefixed ? '' : API_PREFIX;
  const parts = [base, controllerPath, handlerPath].filter((part) => part.length > 0);
  const path = parts.join('/').replaceAll(/\/+/g, '/');
  return path.startsWith('/') ? path : `/${path}`;
}

/**
 * True only when the schema's `reason` field is required, trims, is bounded to
 * 10–500 and rejects the COMPLETE C0/C1, zero-width, bidi and lone-surrogate
 * set (CP1 SA-05 / SA-02). The field schema is inspected directly, so unrelated
 * required body fields do not matter.
 */
export function reasonSchemaIsValid(schema: unknown): boolean {
  const field = reasonFieldSchema(schema);
  if (field === null) {
    return false;
  }
  const valid = field.safeParse('a'.repeat(10));
  if (!valid.success || valid.data !== 'a'.repeat(10)) {
    return false;
  }
  const max = field.safeParse('b'.repeat(500));
  if (!max.success || max.data !== 'b'.repeat(500)) {
    return false;
  }
  const padded = field.safeParse(`  ${'c'.repeat(10)}  `);
  if (!padded.success || padded.data !== 'c'.repeat(10)) {
    return false;
  }
  const invalidValues: readonly unknown[] = [
    undefined,
    null,
    123,
    ['a'.repeat(10)],
    'short',
    'a'.repeat(9),
    'd'.repeat(501),
    ' '.repeat(10),
    // Raw length 10, trimmed length 6: proves the bounds run AFTER trim.
    `  ${'i'.repeat(6)}  `,
  ];
  if (!invalidValues.every((value) => !field.safeParse(value).success)) {
    return false;
  }
  // Exhaustive proof over the documented ranges, not a few representatives.
  for (const [start, end] of FORBIDDEN_REASON_RANGES) {
    for (let codePoint = start; codePoint <= end; codePoint += 1) {
      const candidate = `${'x'.repeat(5)}${String.fromCodePoint(codePoint)}${'y'.repeat(5)}`;
      if (field.safeParse(candidate).success) {
        return false;
      }
    }
  }
  // Normal Persian text and emoji must still be accepted.
  return [`${'z'.repeat(10)}`, 'دلیل تست شماره یک', '😀'.repeat(10)].every(
    (value) => field.safeParse(value).success,
  );
}

interface ReasonField {
  safeParse(value: unknown): { readonly success: boolean; readonly data?: unknown };
}

function isReasonField(value: unknown): value is ReasonField {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  return typeof (value as { safeParse?: unknown }).safeParse === 'function';
}

function reasonFieldSchema(schema: unknown): ReasonField | null {
  if (schema === null || typeof schema !== 'object') {
    return null;
  }
  const shape = (schema as { shape?: unknown }).shape;
  if (shape === null || typeof shape !== 'object') {
    return null;
  }
  const reason = (shape as Record<string, unknown>)['reason'];
  return isReasonField(reason) ? reason : null;
}

/**
 * The complete scan. Order is stable so boot logs and tests are readable.
 */
export function scanRoutes(
  routes: readonly ScannedRoute[],
  environment: ScanEnvironment,
): readonly ScanIssue[] {
  const issues: ScanIssue[] = [];
  for (const route of routes) {
    const routeName = `${route.method} ${route.path}`;
    const count = markerCount(route);

    if (route.classLevelMarker) {
      issues.push({
        code: 'AUTHZ_CLASS_LEVEL_MARKER',
        route: routeName,
        detail: 'access markers must be on the handler, never on the controller class',
      });
    }
    if (count !== 1) {
      issues.push({
        code: 'AUTHZ_MARKER_COUNT',
        route: routeName,
        detail: `expected exactly one access marker, found ${count}`,
      });
    }
    if (route.isPublic && !isAllowlistedPublicRoute(route.method, route.path, environment)) {
      issues.push({
        code: 'AUTHZ_PUBLIC_NOT_ALLOWLISTED',
        route: routeName,
        detail: 'public routes are limited to the reviewed §D allowlist',
      });
    }
    if (
      route.isSelfService &&
      !isAllowlistedSelfServiceRoute(route.method, route.path, environment)
    ) {
      issues.push({
        code: 'AUTHZ_SELF_SERVICE_NOT_ALLOWLISTED',
        route: routeName,
        detail: 'self-service routes are limited to the reviewed allowlist (GET /api/v1/auth/me)',
      });
    }
    if (route.isPermission) {
      if (route.permission === null || !isPermissionName(route.permission)) {
        issues.push({
          code: 'AUTHZ_UNKNOWN_PERMISSION',
          route: routeName,
          detail: 'the route names a permission that is not in the catalog',
        });
      } else if (isSensitivePermission(route.permission)) {
        if (route.bodySchema === null || route.bodySchema === undefined) {
          issues.push({
            code: 'AUTHZ_SENSITIVE_BODY_SCHEMA',
            route: routeName,
            detail: 'a sensitive route must record its body schema with @ZodBody',
          });
        } else if (!reasonSchemaIsValid(route.bodySchema)) {
          issues.push({
            code: 'AUTHZ_SENSITIVE_REASON',
            route: routeName,
            detail:
              'a sensitive route body must require a trimmed 10–500 character reason without control characters',
          });
        }
      }
    }
    issues.push(...inputSchemaIssues(route, routeName));
    if (environment === 'production') {
      issues.push(...productionSurfaceIssues(route.controllerName, route.moduleName, routeName));
    }
  }
  return issues;
}

/**
 * T07 mass-assignment gate: every recorded body/query/params schema is walked.
 * A forbidden identity/status key, a non-strict object or an arbitrary `any`/
 * `unknown` schema is a startup failure.
 */
function inputSchemaIssues(route: ScannedRoute, routeName: string): readonly ScanIssue[] {
  const surfaces = [
    ['body', route.bodySchema],
    ['query', route.querySchema],
    ['params', route.paramsSchema],
  ] as const;
  const issues: ScanIssue[] = [];
  for (const [surface, schema] of surfaces) {
    for (const issue of scanInputSchema(schema, surface)) {
      issues.push({
        code: issue.code,
        route: routeName,
        detail: `${issue.path}: ${issue.detail}`,
      });
    }
  }
  return issues;
}

/**
 * Production surface for controllers with no route handlers. Route-bearing
 * controllers were already checked by `scanRoutes`; this closes the RD-03 gap
 * where an empty probe/test module would otherwise never appear in the scan.
 */
export function scanControllers(
  controllers: readonly ScannedController[],
  routes: readonly ScannedRoute[],
  environment: ScanEnvironment,
): readonly ScanIssue[] {
  if (environment !== 'production') {
    return [];
  }
  const alreadyScanned = new Set(
    routes.map((route) => `${route.moduleName}\u0000${route.controllerName}`),
  );
  const issues: ScanIssue[] = [];
  for (const controller of controllers) {
    if (alreadyScanned.has(`${controller.moduleName}\u0000${controller.controllerName}`)) {
      continue;
    }
    issues.push(
      ...productionSurfaceIssues(
        controller.controllerName,
        controller.moduleName,
        `CONTROLLER ${controller.controllerName}`,
      ),
    );
  }
  return issues;
}

function productionSurfaceIssues(
  controllerName: string,
  moduleName: string,
  routeName: string,
): readonly ScanIssue[] {
  const issues: ScanIssue[] = [];
  if (!(PRODUCTION_CONTROLLERS as readonly string[]).includes(controllerName)) {
    issues.push({
      code: 'AUTHZ_PRODUCTION_CONTROLLER',
      route: routeName,
      detail: `controller ${controllerName} is not on the production allowlist`,
    });
  }
  if (TEST_SURFACE_PATTERN.test(moduleName)) {
    issues.push({
      code: 'AUTHZ_PRODUCTION_MODULE',
      route: routeName,
      detail: `module ${moduleName} looks like a probe/test surface`,
    });
  }
  return issues;
}

/** The stable reason code the runtime guard logs for each failure class. */
export type GuardDenialReason =
  | 'AUTHZ_CLASS_LEVEL_MARKER'
  | 'AUTHZ_MARKER_COUNT'
  | 'AUTHZ_PUBLIC_NOT_ALLOWLISTED'
  | 'AUTHZ_UNKNOWN_PERMISSION'
  | 'AUTHZ_FRESHNESS_DENIED'
  | 'AUTHZ_PERMISSION_DENIED'
  | 'AUTHZ_SCOPE_DENIED';

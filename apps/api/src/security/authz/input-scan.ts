/**
 * Mass-assignment scan (ADR-008 Z3/Z8, F1-05 T07).
 *
 * Every input schema a route records (`@ZodBody`, `@ZodQuery`, `@ZodParams`)
 * is walked recursively. Two rules apply at every object level:
 *
 *  1. Forbidden identity/status keys are never accepted from a client. The
 *     comparison ignores case and underscores, so `tenantId`, `tenant_id`,
 *     `TenantId`, `createdBy` and `created_by` are all the same key.
 *  2. Every object that accepts caller fields must be strict — unknown keys are
 *     rejected, not stripped or passed through. A non-strict nested object is
 *     enough to fail the route scan and the production boot check.
 *
 * The walker understands the Zod wrappers the codebase uses, including arrays,
 * tuples, records, unions, intersections, lazy/recursive schemas and pipes. A
 * `pipe` is inspected on its INPUT side: that is the value the client sends.
 */

/** The listed keys plus their snake_case forms; matching canonicalizes both. */
export const FORBIDDEN_INPUT_KEYS = Object.freeze([
  'role',
  'roles',
  'tenantId',
  'tenant_id',
  'carrierId',
  'carrier_id',
  'status',
  'userId',
  'user_id',
  'createdBy',
  'created_by',
] as const);

const FORBIDDEN_CANONICAL = new Set(FORBIDDEN_INPUT_KEYS.map((key) => canonicalKey(key)));

function canonicalKey(key: string): string {
  return key.replaceAll('_', '').toLowerCase();
}

export type InputSurface = 'body' | 'query' | 'params';

export type InputScanCode =
  'AUTHZ_MASS_ASSIGNMENT' | 'AUTHZ_NON_STRICT_INPUT' | 'AUTHZ_UNSAFE_INPUT_SCHEMA';

export interface InputScanIssue {
  readonly code: InputScanCode;
  readonly surface: InputSurface;
  /** Dotted path inside the schema, e.g. `body.items[].tenantId`. */
  readonly path: string;
  readonly detail: string;
}

interface ZodDef {
  readonly type?: unknown;
  readonly shape?: unknown;
  readonly catchall?: unknown;
  readonly element?: unknown;
  readonly valueType?: unknown;
  readonly options?: unknown;
  readonly left?: unknown;
  readonly right?: unknown;
  readonly items?: unknown;
  readonly rest?: unknown;
  readonly innerType?: unknown;
  readonly in?: unknown;
  readonly out?: unknown;
  readonly getter?: unknown;
}

/**
 * Reads the Zod 4 definition. A different Zod major (or any non-Zod object)
 * has no inspectable definition and is reported as unsafe rather than silently
 * skipped, so a future dependency change fails closed.
 */
function definitionOf(schema: unknown): ZodDef | undefined {
  if (schema === null || typeof schema !== 'object') {
    return undefined;
  }
  return (schema as { _zod?: { def?: ZodDef } })._zod?.def;
}

function typeOf(schema: unknown): string | undefined {
  const type = definitionOf(schema)?.type;
  return typeof type === 'string' ? type : undefined;
}

/** True when the object schema rejects every key outside `shape`. */
function isStrictObject(def: ZodDef): boolean {
  return typeOf(def.catchall) === 'never';
}

/**
 * Scans one recorded input schema. A missing schema means the route records no
 * input of that kind and contributes nothing.
 */
export function scanInputSchema(schema: unknown, surface: InputSurface): readonly InputScanIssue[] {
  if (schema === null || schema === undefined) {
    return [];
  }
  const issues: InputScanIssue[] = [];
  walk(schema, surface, surface, issues, new Set<object>());
  return issues;
}

function walk(
  schema: unknown,
  surface: InputSurface,
  path: string,
  issues: InputScanIssue[],
  seen: Set<object>,
): void {
  if (schema === null || typeof schema !== 'object') {
    return;
  }
  // Recursive lazy schemas must not loop forever.
  if (seen.has(schema)) {
    return;
  }
  seen.add(schema);

  const def = definitionOf(schema);
  const type = typeof def?.type === 'string' ? def.type : undefined;
  if (def === undefined || type === undefined) {
    // Fail closed: a recorded schema the scanner cannot inspect is not proof
    // of strictness. `@ZodBody`/`@ZodQuery`/`@ZodParams` only accept Zod.
    issues.push({
      code: 'AUTHZ_UNSAFE_INPUT_SCHEMA',
      surface,
      path,
      detail: 'schema is not an inspectable Zod schema',
    });
    return;
  }

  switch (type) {
    case 'object': {
      if (!isStrictObject(def)) {
        issues.push({
          code: 'AUTHZ_NON_STRICT_INPUT',
          surface,
          path,
          detail: 'object must reject unknown keys (use z.strictObject at every level)',
        });
      }
      const shape = readShape(def.shape);
      if (shape === null) {
        issues.push({
          code: 'AUTHZ_UNSAFE_INPUT_SCHEMA',
          surface,
          path,
          detail: 'object shape could not be inspected',
        });
        return;
      }
      for (const [key, value] of Object.entries(shape)) {
        const childPath = `${path}.${key}`;
        if (FORBIDDEN_CANONICAL.has(canonicalKey(key))) {
          issues.push({
            code: 'AUTHZ_MASS_ASSIGNMENT',
            surface,
            path: childPath,
            detail: `forbidden identity/status key "${key}" is accepted from the client`,
          });
        }
        walk(value, surface, childPath, issues, seen);
      }
      // A catch-all is the non-strict branch; walking it keeps nested forbidden
      // keys visible when the object is loose rather than absent.
      if (def.catchall !== undefined && !isStrictObject(def)) {
        walk(def.catchall, surface, `${path}.*`, issues, seen);
      }
      return;
    }
    case 'array':
      walk(def.element, surface, `${path}[]`, issues, seen);
      return;
    case 'tuple':
      walkTuple(def.items, path, surface, issues, seen);
      walk(def.rest, surface, `${path}[...]`, issues, seen);
      return;
    case 'record':
    case 'map':
    case 'set':
      walk(def.valueType, surface, `${path}{*}`, issues, seen);
      return;
    case 'union':
      walkOptions(def.options, path, surface, issues, seen);
      return;
    case 'intersection':
      walk(def.left, surface, path, issues, seen);
      walk(def.right, surface, path, issues, seen);
      return;
    case 'pipe':
      // `transform` puts the shape schema on the input side, while
      // `z.preprocess` puts it on the output side. Both are client-facing
      // schemas, so both sides are inspected.
      walk(def.in, surface, path, issues, seen);
      walk(def.out, surface, path, issues, seen);
      return;
    case 'lazy': {
      if (typeof def.getter === 'function') {
        try {
          walk(def.getter(), surface, path, issues, seen);
        } catch {
          issues.push({
            code: 'AUTHZ_UNSAFE_INPUT_SCHEMA',
            surface,
            path,
            detail: 'lazy schema getter could not be inspected',
          });
        }
      }
      return;
    }
    case 'optional':
    case 'nullable':
    case 'default':
    case 'prefault':
    case 'catch':
    case 'readonly':
    case 'nonoptional':
      walk(def.innerType, surface, path, issues, seen);
      return;
    case 'any':
    case 'unknown':
    case 'custom':
    case 'function':
      issues.push({
        code: 'AUTHZ_UNSAFE_INPUT_SCHEMA',
        surface,
        path,
        detail: `schema type "${type}" accepts arbitrary data`,
      });
      return;
    default:
      // Primitives, enums, literals, dates, etc. cannot mass-assign fields.
      return;
  }
}

function readShape(shape: unknown): Record<string, unknown> | null {
  if (shape === null || typeof shape !== 'object') {
    return null;
  }
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(shape)) {
    result[key] = value;
  }
  return result;
}

function walkTuple(
  items: unknown,
  path: string,
  surface: InputSurface,
  issues: InputScanIssue[],
  seen: Set<object>,
): void {
  if (!Array.isArray(items)) {
    return;
  }
  items.forEach((item, index) => {
    walk(item, surface, `${path}[${index}]`, issues, seen);
  });
}

function walkOptions(
  options: unknown,
  path: string,
  surface: InputSurface,
  issues: InputScanIssue[],
  seen: Set<object>,
): void {
  if (!Array.isArray(options)) {
    return;
  }
  options.forEach((option, index) => {
    walk(option, surface, `${path}|${index}`, issues, seen);
  });
}

import { PERMISSIONS, PERMISSION_NAMES } from './permissions.js';
import { ROLE_CODES, roleHasPermission } from './role-permissions.js';
import type { ScannedRoute } from './route-scan.js';

/**
 * Permission-matrix generator (F1-05 T07). The catalog, role map and the SAME
 * route-scan records that drive the boot check are the only inputs; no table is
 * hand-maintained. `docs/security/permission-matrix.md` owns the surrounding
 * prose and the generated block is replaced by `authz:matrix`.
 */

export const MATRIX_BEGIN = '<!-- matrix:begin -->';
export const MATRIX_END = '<!-- matrix:end -->';

export interface MatrixRoute {
  readonly method: string;
  readonly path: string;
  readonly marker: '@Public' | '@SelfService' | '@RequirePermission' | 'missing';
  readonly permission: string | null;
}

/** Routes are rendered in discovery order, which is stable across boots. */
export function buildMatrixRoutes(routes: readonly ScannedRoute[]): readonly MatrixRoute[] {
  return routes.map((route) => ({
    method: route.method,
    path: route.path,
    marker: route.isPublic
      ? '@Public'
      : route.isSelfService
        ? '@SelfService'
        : route.isPermission
          ? '@RequirePermission'
          : 'missing',
    permission: route.permission,
  }));
}

/** The generated block body, without the begin/end markers. */
export function renderMatrix(routes: readonly ScannedRoute[]): string {
  const permissionRows = PERMISSION_NAMES.map((name) => {
    const definition = PERMISSIONS[name];
    return [
      `\`${name}\``,
      definition.scope,
      definition.sensitive ? '**yes**' : 'no',
      ...ROLE_CODES.map((role) => (roleHasPermission(role, name) ? 'allow' : 'deny')),
    ];
  });
  const routeRows = buildMatrixRoutes(routes).map((route) => [
    route.method,
    `\`${route.path}\``,
    `\`${route.marker}\``,
    route.permission === null ? '—' : `\`${route.permission}\``,
  ]);

  return [
    '### Permissions and roles',
    '',
    renderTable(['Permission', 'Scope', 'Sensitive', ...ROLE_CODES], permissionRows),
    '',
    '### Routes',
    '',
    renderTable(['Method', 'Path', 'Marker', 'Permission'], routeRows),
  ].join('\n');
}

/** Replaces only the marked block; the prose around it stays human-owned. */
export function replaceMatrixBlock(markdown: string, body: string): string {
  const { start, end } = blockOffsets(markdown);
  return `${markdown.slice(0, start)}\n\n${body.trim()}\n\n${markdown.slice(end)}`;
}

/** The current generated block body, trimmed, for the sync test. */
export function extractMatrixBlock(markdown: string): string {
  const { start, end } = blockOffsets(markdown);
  return markdown.slice(start, end).trim();
}

function blockOffsets(markdown: string): { readonly start: number; readonly end: number } {
  // The markers also appear inside backticks in the prose, so only a marker on
  // its own line opens or closes the generated block.
  const begin = markerPattern(MATRIX_BEGIN).exec(markdown);
  if (begin === null || begin.index === undefined) {
    throw new Error(`matrix document is missing ${MATRIX_BEGIN}`);
  }
  const end = markerPattern(MATRIX_END).exec(markdown.slice(begin.index + begin[0].length));
  if (end === null || end.index === undefined) {
    throw new Error(`matrix document is missing ${MATRIX_END}`);
  }
  return {
    start: begin.index + begin[0].length,
    end: begin.index + begin[0].length + end.index,
  };
}

function markerPattern(marker: string): RegExp {
  return new RegExp(`^${marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[ \\t]*$`, 'm');
}

/**
 * GitHub-flavoured markdown table with padded columns. Padding is deterministic
 * so the sync test and the script produce byte-identical output.
 */
function renderTable(headers: readonly string[], rows: readonly (readonly string[])[]): string {
  const widths = headers.map((header, index) =>
    Math.max(header.length, ...rows.map((row) => (row[index] ?? '').length)),
  );
  const line = (cells: readonly string[]): string =>
    `| ${cells.map((cell, index) => pad(cell, widths[index] ?? 0)).join(' | ')} |`;
  return [
    line(headers),
    `| ${widths.map((width) => '-'.repeat(width)).join(' | ')} |`,
    ...rows.map(line),
  ].join('\n');
}

function pad(value: string, width: number): string {
  return value.padEnd(width, ' ');
}

import { DomainError } from '../errors/domain-error.js';

/**
 * Log-safe projection of an exception (F1-06 T02, ADR-009/T01 D3).
 *
 * A raw drizzle/PG error carries `message`, `detail`, `query`, `parameters`,
 * `where` and `cause` values — the SQL text and the bound parameter values are
 * inside them, and key-based pino redaction cannot see into a serialized Error.
 * Logging the raw object for a 5xx is therefore a PII leak path (F1-03 U11).
 *
 * This module keeps only fields that are structural: a validated SQLSTATE, a
 * schema-defined constraint/table identifier, a stack trace made of frame lines
 * (never the message line) and a small allowlist of DomainError detail keys.
 * Everything else is dropped. It never throws: a malformed exception still
 * produces a usable, empty-ish object.
 */

export interface SanitizedError {
  readonly name: string;
  /** DomainError code (e.g. `INTERNAL`) — code, never a message. */
  readonly code?: string;
  readonly statusCode?: number;
  /** PostgreSQL SQLSTATE, e.g. `23505`. */
  readonly sqlState?: string;
  readonly constraint?: string;
  readonly table?: string;
  /** DomainError details, restricted to structural keys with validated values. */
  readonly details?: Record<string, string | number>;
  /** Stack frames only (`at …`), message line removed. */
  readonly stack?: readonly string[];
}

const SQLSTATE_PATTERN = /^[0-9A-Z]{5}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z_][A-Za-z0-9_.]{0,63}$/;
const NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const DOMAIN_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
const DETAIL_KEY_ALLOWLIST = new Set(['pgCode', 'sqlState', 'constraint', 'errorCode']);
const MAX_CHAIN_DEPTH = 5;
const MAX_STACK_FRAMES = 12;
const MAX_FRAME_LENGTH = 240;

/** Walks `cause` (bounded) looking for a string field that matches `pattern`. */
function findInChain(error: unknown, field: string, pattern: RegExp): string | undefined {
  let current: unknown = error;
  for (let depth = 0; depth < MAX_CHAIN_DEPTH; depth += 1) {
    if (current === null || current === undefined) {
      return undefined;
    }
    const value = (current as Record<string, unknown>)[field];
    if (typeof value === 'string' && pattern.test(value)) {
      return value;
    }
    current = (current as { cause?: unknown }).cause;
  }
  return undefined;
}

function safeName(error: unknown): string {
  if (error instanceof Error && NAME_PATTERN.test(error.name)) {
    return error.name;
  }
  return 'Unknown';
}

/** Frame lines only; the first stack line usually repeats the message, so it cannot be kept. */
function safeStack(error: unknown): string[] | undefined {
  const stack = typeof error === 'object' && error !== null ? (error as Error).stack : undefined;
  if (typeof stack !== 'string') {
    return undefined;
  }
  const frames = stack
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('at '))
    .slice(0, MAX_STACK_FRAMES)
    .map((line) => line.slice(0, MAX_FRAME_LENGTH));
  return frames.length > 0 ? frames : undefined;
}

function safeDomainDetails(
  details: Record<string, unknown> | undefined,
): Record<string, string | number> | undefined {
  if (details === undefined) {
    return undefined;
  }
  const safe: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(details)) {
    if (!DETAIL_KEY_ALLOWLIST.has(key)) {
      continue;
    }
    if (typeof value === 'number' && Number.isFinite(value)) {
      safe[key] = value;
    } else if (typeof value === 'string' && value.length <= 64 && /^[A-Za-z0-9_.-]+$/.test(value)) {
      safe[key] = value;
    }
  }
  return Object.keys(safe).length > 0 ? safe : undefined;
}

/** Returns a plain object that is safe to log for any thrown value. */
export function sanitizeErrorForLog(error: unknown): SanitizedError {
  if (error instanceof DomainError) {
    const details = safeDomainDetails(error.details);
    return {
      name: 'DomainError',
      code: DOMAIN_CODE_PATTERN.test(error.code) ? error.code : 'INTERNAL',
      statusCode: error.statusCode,
      ...(details ? { details } : {}),
    };
  }

  const sqlState = findInChain(error, 'code', SQLSTATE_PATTERN);
  const constraint = findInChain(error, 'constraint', IDENTIFIER_PATTERN);
  const table = findInChain(error, 'table', IDENTIFIER_PATTERN);
  const stack = safeStack(error);
  return {
    name: safeName(error),
    ...(sqlState ? { sqlState } : {}),
    ...(constraint ? { constraint } : {}),
    ...(table ? { table } : {}),
    ...(stack ? { stack } : {}),
  };
}

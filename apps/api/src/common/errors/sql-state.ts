/**
 * PostgreSQL SQLSTATE reader for wrapped errors (drizzle wraps driver errors and
 * keeps the original on `cause`). Returns only a 5-character code, never the
 * message or parameters, so callers can branch on a stable class without
 * touching value-bearing fields.
 */
export function sqlStateOf(error: unknown, depth = 0): string | null {
  if (depth > 5 || typeof error !== 'object' || error === null) {
    return null;
  }
  const code = (error as { code?: unknown }).code;
  if (typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code)) {
    return code;
  }
  return sqlStateOf((error as { cause?: unknown }).cause, depth + 1);
}

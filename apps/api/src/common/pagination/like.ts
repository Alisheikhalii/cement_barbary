/**
 * LIKE metacharacter escaping for the B3 `q` search (`name_key LIKE '%…%'`).
 *
 * `%`, `_` and `\` are wildcards/escape characters in PostgreSQL LIKE. Without
 * escaping, a user typing `%` matches every row and `_` matches any character.
 * The query must be written with an explicit escape clause so the meaning is
 * not dependent on the server default:
 *
 *   WHERE name_key LIKE $1 ESCAPE '\'
 *   -- $1 = likeContains(term)
 */
export function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, '\\$&');
}

/** `term` → a `%…%` contains-pattern with all metacharacters escaped. */
export function likeContains(value: string): string {
  return `%${escapeLike(value)}%`;
}

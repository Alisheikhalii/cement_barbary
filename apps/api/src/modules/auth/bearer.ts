/**
 * Extracts a bearer credential from an Authorization header. Returns null for
 * anything that is not exactly one `Bearer <token>` value — malformed headers
 * must fall through to the generic 401, not a parser error.
 */
export function bearerToken(header: string | undefined): string | null {
  if (header === undefined) {
    return null;
  }
  const match = /^Bearer[ \t]+(\S+)$/i.exec(header.trim());
  const token = match?.[1];
  return token === undefined || token.length === 0 ? null : token;
}

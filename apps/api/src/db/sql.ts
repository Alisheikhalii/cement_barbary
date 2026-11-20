/**
 * Sanctioned re-export of pure SQL builder helpers (ADR-005 D11). These build
 * query EXPRESSIONS only — they cannot open a connection or run a query — so
 * sharing them does not weaken the D11 boundary: all execution still goes
 * through TenantDb.run(). The lint rule keeps banning direct 'drizzle-orm'
 * imports outside src/db/**; modules import from here instead.
 */
export { and, eq, gt, isNull, ne } from 'drizzle-orm';

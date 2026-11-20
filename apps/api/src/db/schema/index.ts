/**
 * Schema entry point for drizzle-kit (`drizzle.config.ts`) and for the runtime
 * Drizzle instance (`drizzle(pool, { schema })`). Re-export every table here.
 */
export * from './tenants.js';
export * from './roles.js';
export * from './users.js';
export * from './user-roles.js';
export * from './user-credentials.js';
export * from './auth-sessions.js';
export * from './auth-rate-limits.js';

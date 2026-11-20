/**
 * DI tokens for the DB boundary. They live in their own module so guards can
 * import a token without importing database.providers.ts (which would create
 * an import cycle and leave the decorator token undefined).
 */
export const PG_POOL = Symbol('PG_POOL');
export const DB = Symbol('DB');

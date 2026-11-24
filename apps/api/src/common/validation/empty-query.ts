import { z } from 'zod';

/**
 * Strict empty query schema for routes whose path carries every input (e.g.
 * `GET /base/halls/:id`). An unexpected query key is a 400, never silently
 * ignored, and the recorded schema also clears the mass-assignment scan.
 */
export const emptyQuerySchema = z.strictObject({});

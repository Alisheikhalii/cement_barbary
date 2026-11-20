import { z } from 'zod';

/**
 * Auth request bodies (T07). Strict schemas reject unknown fields, so no body
 * can mass-assign a tenant id, user id or role. Length caps are generous but
 * finite: every identifier is HMAC'd for rate limiting, so it must be bounded.
 */

export const loginInputSchema = z.strictObject({
  /** `username@tenant-code` (staff) or a phone number (driver). */
  identifier: z.string().trim().min(1).max(200),
  password: z.string().min(1).max(128),
});

export type LoginInput = z.infer<typeof loginInputSchema>;

export const changePasswordInputSchema = z.strictObject({
  /** Required for the Bearer (access-token) branch; not for a change token. */
  currentPassword: z.string().min(1).max(128).optional(),
  newPassword: z.string().min(1).max(128),
});

export type ChangePasswordInput = z.infer<typeof changePasswordInputSchema>;

import { z } from 'zod';

/**
 * The `reason` contract for sensitive actions (ADR-008 Z10, CP1 SA-02).
 * Guards run before pipes, so the route scan cannot rely on the pipe alone:
 * it inspects the body schema's `reason` field and proves this exact contract
 * (required, trimmed, 10–500 characters, no control characters).
 *
 * F1-08 sensitive endpoints reuse this schema inside their strict body schema.
 */
// eslint-disable-next-line no-control-regex -- intentional: these are the control characters the reason must reject (ADR-008 Z10/SA-02)
export const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001F\u007F]/;

export const sensitiveReasonSchema = z
  .string()
  .trim()
  .min(10)
  .max(500)
  .refine((value) => !CONTROL_CHARACTER_PATTERN.test(value), {
    message: 'must not contain control characters',
  });

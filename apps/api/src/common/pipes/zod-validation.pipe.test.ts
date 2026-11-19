import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { DomainError } from '../errors/domain-error.js';
import { ZodValidationPipe } from './zod-validation.pipe.js';

const schema = z.object({ mobile: z.string().regex(/^09\d{9}$/) });

describe('ZodValidationPipe', () => {
  it('returns the parsed value for valid input', () => {
    const pipe = new ZodValidationPipe(schema);
    expect(pipe.transform({ mobile: '09120000000' })).toEqual({ mobile: '09120000000' });
  });

  it('throws a BAD_INPUT DomainError with issues for invalid input', () => {
    const pipe = new ZodValidationPipe(schema);
    try {
      pipe.transform({ mobile: '123' });
      expect.unreachable('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(DomainError);
      const domainError = error as DomainError;
      expect(domainError.code).toBe('BAD_INPUT');
      expect(domainError.statusCode).toBe(400);
      expect(domainError.details).toHaveProperty('issues');
    }
  });

  it('strips unknown fields (mass-assignment protection)', () => {
    const pipe = new ZodValidationPipe(schema);
    expect(pipe.transform({ mobile: '09120000000', role: 'DRIVER' })).toEqual({
      mobile: '09120000000',
    });
  });
});

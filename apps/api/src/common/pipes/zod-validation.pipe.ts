import { Injectable, type PipeTransform } from '@nestjs/common';
import type { z } from 'zod';

import { DomainError } from '../errors/domain-error.js';

/**
 * Validates input against a Zod schema (GUIDELINES §6.3: whitelist validation).
 * Usage: `@Body(new ZodValidationPipe(mySchema))`. Extra fields are stripped by
 * the schema, which prevents mass assignment.
 */
@Injectable()
export class ZodValidationPipe<T extends z.ZodType> implements PipeTransform<unknown, z.output<T>> {
  constructor(private readonly schema: T) {}

  transform(value: unknown): z.output<T> {
    const result = this.schema.safeParse(value);
    if (!result.success) {
      throw DomainError.badInput({ issues: result.error.issues });
    }
    return result.data;
  }
}

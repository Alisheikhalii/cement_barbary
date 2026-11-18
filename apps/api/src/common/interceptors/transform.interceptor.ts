import {
  type CallHandler,
  type ExecutionContext,
  Injectable,
  type NestInterceptor,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { map, type Observable } from 'rxjs';

interface Envelope {
  data: unknown;
  meta?: Record<string, unknown>;
}

/** Controllers may return `{ data, meta }` themselves (e.g. paginated lists). */
function isEnvelope(value: unknown): value is Envelope {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const keys = Object.keys(value);
  return keys.includes('data') && keys.every((key) => key === 'data' || key === 'meta');
}

/**
 * Wraps every successful response in the standard envelope `{ data }` /
 * `{ data, meta }` (GUIDELINES §3.1) and echoes the request id as a header.
 */
@Injectable()
export class TransformInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = context.switchToHttp().getRequest<Request & { id?: string }>();
    const res = context.switchToHttp().getResponse<Response>();
    return next.handle().pipe(
      map((payload: unknown) => {
        if (req.id) {
          res.setHeader('x-request-id', req.id);
        }
        return isEnvelope(payload) ? payload : { data: payload };
      }),
    );
  }
}

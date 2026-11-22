import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import type { Request, Response } from 'express';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits PinoLogger as the constructor param type for DI
import { PinoLogger } from 'nestjs-pino';

import { DomainError } from '../errors/domain-error.js';
import { sanitizeErrorForLog } from '../logging/sanitize-error.js';

interface ErrorBody {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

/** Stable error codes for plain HTTP errors without a domain code. */
const HTTP_ERROR_CODES: Record<number, string> = {
  [HttpStatus.BAD_REQUEST]: 'BAD_REQUEST',
  [HttpStatus.UNAUTHORIZED]: 'UNAUTHORIZED',
  [HttpStatus.FORBIDDEN]: 'FORBIDDEN',
  [HttpStatus.NOT_FOUND]: 'NOT_FOUND',
  [HttpStatus.METHOD_NOT_ALLOWED]: 'METHOD_NOT_ALLOWED',
  [HttpStatus.CONFLICT]: 'CONFLICT',
  [HttpStatus.TOO_MANY_REQUESTS]: 'TOO_MANY_REQUESTS',
};

/** Persian user-facing messages; technical detail stays in the logs (GUIDELINES §3). */
const HTTP_ERROR_MESSAGES: Record<number, string> = {
  [HttpStatus.BAD_REQUEST]: 'درخواست نامعتبر است',
  [HttpStatus.UNAUTHORIZED]: 'احراز هویت انجام نشده است',
  [HttpStatus.FORBIDDEN]: 'دسترسی مجاز نیست',
  [HttpStatus.NOT_FOUND]: 'مسیر مورد نظر یافت نشد',
  [HttpStatus.METHOD_NOT_ALLOWED]: 'این روش برای مسیر مورد نظر مجاز نیست',
  [HttpStatus.CONFLICT]: 'درخواست با وضعیت فعلی ناسازگار است',
  [HttpStatus.TOO_MANY_REQUESTS]: 'تعداد درخواست‌ها بیش از حد مجاز است',
};

const INTERNAL_ERROR_BODY: ErrorBody = {
  error: { code: 'INTERNAL_ERROR', message: 'خطای داخلی سرور رخ داد' },
};

/**
 * Single place that turns every thrown error into the standard API error
 * envelope (GUIDELINES §3.1). Never leaks stack traces to the client.
 */
@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  constructor(private readonly logger: PinoLogger) {
    this.logger.setContext(GlobalExceptionFilter.name);
  }

  catch(exception: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    const req = host.switchToHttp().getRequest<Request & { id?: string }>();
    if (req.id) {
      res.setHeader('x-request-id', req.id);
    }

    const { status, body } = this.toError(exception);
    if (status === HttpStatus.TOO_MANY_REQUESTS && exception instanceof DomainError) {
      // A11: clients (and tests) get an explicit Retry-After; no bucket details.
      const retry = exception.details?.retryAfterSeconds;
      if (typeof retry === 'number' && Number.isFinite(retry)) {
        res.setHeader('Retry-After', String(Math.ceil(retry)));
      }
    }
    if (status >= HttpStatus.INTERNAL_SERVER_ERROR) {
      // 5xx details are log-only, never sent to clients. The exception is
      // projected before logging (F1-06 T02): a raw PG/drizzle error carries
      // SQL text and bound parameter values in `message`/`detail`/`parameters`,
      // which key-based redaction cannot reach. Only structural fields survive.
      // errorCode is logged explicitly: the A14 redaction hides `code` keys
      // (future OTP codes) and would otherwise swallow DomainError.code here.
      const safe = sanitizeErrorForLog(exception);
      this.logger.error(
        {
          err: safe,
          reqId: req.id,
          errorCode: body.error.code,
          ...(safe.details ? { details: safe.details } : {}),
        },
        'Unhandled error',
      );
    }
    res.status(status).json(body);
  }

  private toError(exception: unknown): { status: number; body: ErrorBody } {
    if (exception instanceof DomainError) {
      return {
        status: exception.statusCode,
        body: {
          error: {
            code: exception.code,
            message: exception.message,
            // Client errors (4xx) may carry details (e.g. validation issues);
            // server errors (5xx) never expose details — they are log-only.
            // 429 is the exception: its only detail is the wait time, which is
            // already in Retry-After. Keeping it out of the body makes two
            // blocked responses byte-identical (no account oracle) and removes
            // a time-varying field from the security-sensitive comparison.
            ...(exception.statusCode < HttpStatus.INTERNAL_SERVER_ERROR &&
            exception.statusCode !== HttpStatus.TOO_MANY_REQUESTS &&
            exception.details
              ? { details: exception.details }
              : {}),
          },
        },
      };
    }
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      return {
        status,
        body: {
          error: {
            code: HTTP_ERROR_CODES[status] ?? `HTTP_${status}`,
            message: HTTP_ERROR_MESSAGES[status] ?? 'درخواست نامعتبر است',
          },
        },
      };
    }
    return { status: HttpStatus.INTERNAL_SERVER_ERROR, body: INTERNAL_ERROR_BODY };
  }
}

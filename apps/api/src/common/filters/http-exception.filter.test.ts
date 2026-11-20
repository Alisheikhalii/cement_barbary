import { type ArgumentsHost, NotFoundException } from '@nestjs/common';
import type { PinoLogger } from 'nestjs-pino';
import { describe, expect, it, vi } from 'vitest';

import { DomainError } from '../errors/domain-error.js';
import { GlobalExceptionFilter } from './http-exception.filter.js';

function createHost() {
  const json = vi.fn();
  const status = vi.fn().mockReturnValue({ json });
  const setHeader = vi.fn();
  const host = {
    switchToHttp: () => ({
      getRequest: () => ({ id: 'req-1' }),
      getResponse: () => ({ status, setHeader }),
    }),
  } as unknown as ArgumentsHost;
  return { host, json, status, setHeader };
}

function createFilter() {
  const logger = { setContext: vi.fn(), error: vi.fn() };
  const filter = new GlobalExceptionFilter(logger as unknown as PinoLogger);
  return { filter, logger };
}

describe('GlobalExceptionFilter', () => {
  it('maps a DomainError to its code, message and status', () => {
    const { filter } = createFilter();
    const { host, json, status } = createHost();
    filter.catch(
      new DomainError('QUEUE_ALREADY_JOINED', 'قبلاً در این صف ثبت‌نام کرده‌اید', 409),
      host,
    );
    expect(status).toHaveBeenCalledWith(409);
    expect(json).toHaveBeenCalledWith({
      error: { code: 'QUEUE_ALREADY_JOINED', message: 'قبلاً در این صف ثبت‌نام کرده‌اید' },
    });
  });

  it('maps a Nest NotFoundException to a stable NOT_FOUND envelope', () => {
    const { filter } = createFilter();
    const { host, json, status } = createHost();
    filter.catch(new NotFoundException(), host);
    expect(status).toHaveBeenCalledWith(404);
    expect(json).toHaveBeenCalledWith({
      error: { code: 'NOT_FOUND', message: 'مسیر مورد نظر یافت نشد' },
    });
  });

  it('maps unknown errors to 500 without leaking internals', () => {
    const { filter, logger } = createFilter();
    const { host, json, status } = createHost();
    filter.catch(new Error('database connection string leaked here'), host);
    expect(status).toHaveBeenCalledWith(500);
    expect(json).toHaveBeenCalledWith({
      error: { code: 'INTERNAL_ERROR', message: 'خطای داخلی سرور رخ داد' },
    });
    expect(logger.error).toHaveBeenCalledOnce();
  });

  it('echoes the request id header on errors too', () => {
    const { filter } = createFilter();
    const { host, setHeader } = createHost();
    filter.catch(new NotFoundException(), host);
    expect(setHeader).toHaveBeenCalledWith('x-request-id', 'req-1');
  });

  it('never exposes 5xx DomainError details (e.g. pgCode) in the body — log only', () => {
    const { filter, logger } = createFilter();
    const { host, json, status } = createHost();
    filter.catch(DomainError.internal({ pgCode: '22P02' }), host);
    expect(status).toHaveBeenCalledWith(500);
    expect(json).toHaveBeenCalledWith({
      error: { code: 'INTERNAL', message: 'خطای داخلی سرور رخ داد' },
    });
    const body = json.mock.calls[0]?.[0] as { error: Record<string, unknown> };
    expect(body.error).not.toHaveProperty('details');
    // details are logged (SQLSTATE only, no PII) with the request id instead
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ reqId: 'req-1', details: { pgCode: '22P02' } }),
      'Unhandled error',
    );
  });

  it('keeps 4xx details in the body (client-facing validation issues)', () => {
    const { filter } = createFilter();
    const { host, json, status } = createHost();
    const issues = [{ path: ['username'], message: 'Required' }];
    filter.catch(DomainError.badInput({ issues }), host);
    expect(status).toHaveBeenCalledWith(400);
    expect(json).toHaveBeenCalledWith({
      error: { code: 'BAD_INPUT', message: 'ورودی نامعتبر است', details: { issues } },
    });
  });

  it('maps a 409 conflict unchanged (details allowed but not required)', () => {
    const { filter } = createFilter();
    const { host, json, status } = createHost();
    filter.catch(DomainError.conflict(), host);
    expect(status).toHaveBeenCalledWith(409);
    expect(json).toHaveBeenCalledWith({
      error: { code: 'CONFLICT', message: 'این مقدار قبلاً ثبت شده است' },
    });
  });
});

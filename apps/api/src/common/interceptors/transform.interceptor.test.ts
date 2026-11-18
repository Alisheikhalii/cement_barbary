import type { CallHandler, ExecutionContext } from '@nestjs/common';
import { firstValueFrom, of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { TransformInterceptor } from './transform.interceptor.js';

function createContext(requestId?: string) {
  const setHeader = vi.fn();
  const context = {
    switchToHttp: () => ({
      getRequest: () => (requestId ? { id: requestId } : {}),
      getResponse: () => ({ setHeader }),
    }),
  } as unknown as ExecutionContext;
  return { context, setHeader };
}

function handlerOf(payload: unknown): CallHandler {
  return { handle: () => of(payload) };
}

describe('TransformInterceptor', () => {
  it('wraps a plain value into the standard envelope', async () => {
    const { context } = createContext();
    const result = await firstValueFrom(
      new TransformInterceptor().intercept(context, handlerOf({ a: 1 })),
    );
    expect(result).toEqual({ data: { a: 1 } });
  });

  it('passes through an existing `{ data, meta }` envelope', async () => {
    const { context } = createContext();
    const payload = { data: [1, 2], meta: { page: 1, pageSize: 50, total: 2 } };
    const result = await firstValueFrom(
      new TransformInterceptor().intercept(context, handlerOf(payload)),
    );
    expect(result).toBe(payload);
  });

  it('echoes the request id as the x-request-id header', async () => {
    const { context, setHeader } = createContext('req-123');
    await firstValueFrom(new TransformInterceptor().intercept(context, handlerOf(null)));
    expect(setHeader).toHaveBeenCalledWith('x-request-id', 'req-123');
  });
});

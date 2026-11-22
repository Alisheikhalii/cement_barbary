import { describe, expect, it } from 'vitest';

import { DomainError } from '../errors/domain-error.js';
import { sanitizeErrorForLog } from './sanitize-error.js';

/** Synthetic values only — never a real phone. */
const PHONE = '09120000009';

function pgError(): Error {
  return Object.assign(new Error(`Failed query: insert into users … values ($1) = ${PHONE}`), {
    code: '23505',
    detail: `Key (phone_hash)=(${PHONE}) already exists.`,
    table: 'users',
    constraint: 'users_tenant_phone_unique',
    query: 'insert into users …',
    parameters: [PHONE],
  });
}

describe('sanitizeErrorForLog', () => {
  it('keeps only structural PG fields and drops every value-bearing field', () => {
    const safe = sanitizeErrorForLog(pgError());
    expect(safe.name).toBe('Error');
    expect(safe.sqlState).toBe('23505');
    expect(safe.constraint).toBe('users_tenant_phone_unique');
    expect(safe.table).toBe('users');
    expect(JSON.stringify(safe)).not.toContain(PHONE);
    expect(safe).not.toHaveProperty('message');
    expect(safe).not.toHaveProperty('detail');
    expect(safe).not.toHaveProperty('query');
    expect(safe).not.toHaveProperty('parameters');
  });

  it('walks a drizzle wrapper to the SQLSTATE and still drops the message', () => {
    const wrapper = new Error(`Failed query: select … ${PHONE}`);
    (wrapper as { cause?: unknown }).cause = pgError();
    const safe = sanitizeErrorForLog(wrapper);
    expect(safe.sqlState).toBe('23505');
    expect(JSON.stringify(safe)).not.toContain(PHONE);
  });

  it('rejects a malformed SQLSTATE, constraint or table identifier', () => {
    const error = Object.assign(new Error('boom'), {
      code: 'nope!',
      constraint: `evil constraint ${PHONE}`,
      table: 'users; drop table users',
    });
    const safe = sanitizeErrorForLog(error);
    expect(safe.sqlState).toBeUndefined();
    expect(safe.constraint).toBeUndefined();
    expect(safe.table).toBeUndefined();
  });

  it('keeps only allowlisted DomainError details with validated values', () => {
    const safe = sanitizeErrorForLog(
      DomainError.internal({ pgCode: '22P02', leaked: PHONE, nested: { phone: PHONE } }),
    );
    expect(safe).toEqual({
      name: 'DomainError',
      code: 'INTERNAL',
      statusCode: 500,
      details: { pgCode: '22P02' },
    });
    expect(JSON.stringify(safe)).not.toContain(PHONE);
  });

  it('never puts the error message into the stack (only frame lines survive)', () => {
    const error = new Error(`secret ${PHONE}`);
    const safe = sanitizeErrorForLog(error);
    expect(safe.stack?.length ?? 0).toBeGreaterThan(0);
    for (const frame of safe.stack ?? []) {
      expect(frame.startsWith('at ')).toBe(true);
      expect(frame).not.toContain(PHONE);
    }
    expect(JSON.stringify(safe)).not.toContain(PHONE);
  });

  it('never throws on a non-Error thrown value', () => {
    expect(sanitizeErrorForLog(`raw ${PHONE}`)).toEqual({ name: 'Unknown' });
    expect(sanitizeErrorForLog(undefined)).toEqual({ name: 'Unknown' });
  });
});

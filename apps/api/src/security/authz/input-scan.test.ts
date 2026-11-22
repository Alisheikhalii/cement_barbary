import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  FORBIDDEN_INPUT_KEYS,
  scanInputSchema,
  type InputScanCode,
  type InputSurface,
} from './input-scan.js';
import { sensitiveReasonSchema } from './sensitive-reason.js';

/**
 * Mass-assignment scan (ADR-008 Z3/Z8, F1-05 T07): every input schema is
 * strict at every object level and never accepts an identity/status key.
 */
function codes(schema: unknown, surface: InputSurface = 'body'): readonly InputScanCode[] {
  return scanInputSchema(schema, surface).map((issue) => issue.code);
}

function paths(schema: unknown, surface: InputSurface = 'body'): readonly string[] {
  return scanInputSchema(schema, surface).map((issue) => issue.path);
}

describe('mass-assignment scan — strictness', () => {
  it('accepts a strict object with primitive, enum and literal fields', () => {
    const schema = z.strictObject({
      name: z.string().trim().min(1).max(200),
      kind: z.enum(['a', 'b']),
      flag: z.literal(true),
      count: z.number().int().nonnegative(),
    });
    expect(scanInputSchema(schema, 'body')).toEqual([]);
  });

  it('rejects a non-strict object at the top level', () => {
    expect(codes(z.object({ name: z.string() }))).toEqual(['AUTHZ_NON_STRICT_INPUT']);
    expect(codes(z.looseObject({ name: z.string() }))).toEqual([
      'AUTHZ_NON_STRICT_INPUT',
      'AUTHZ_UNSAFE_INPUT_SCHEMA',
    ]);
  });

  it('rejects a non-strict nested object even when the parent is strict', () => {
    const schema = z.strictObject({
      profile: z.object({ name: z.string() }),
    });
    expect(codes(schema)).toContain('AUTHZ_NON_STRICT_INPUT');
    expect(paths(schema)).toContain('body.profile');
  });

  it('rejects a non-strict object inside an array, tuple, union and intersection', () => {
    expect(codes(z.strictObject({ items: z.array(z.object({ id: z.string() })) }))).toContain(
      'AUTHZ_NON_STRICT_INPUT',
    );
    expect(codes(z.tuple([z.object({ id: z.string() })]))).toContain('AUTHZ_NON_STRICT_INPUT');
    expect(
      codes(z.union([z.strictObject({ a: z.string() }), z.object({ b: z.string() })])),
    ).toContain('AUTHZ_NON_STRICT_INPUT');
    expect(
      codes(z.intersection(z.strictObject({ a: z.string() }), z.object({ b: z.string() }))),
    ).toContain('AUTHZ_NON_STRICT_INPUT');
  });

  it('rejects a non-strict record value object', () => {
    expect(codes(z.record(z.string(), z.object({ id: z.string() })))).toContain(
      'AUTHZ_NON_STRICT_INPUT',
    );
    expect(codes(z.record(z.string(), z.strictObject({ id: z.string() })))).toEqual([]);
  });

  it('walks wrappers and lazy schemas to the object underneath', () => {
    expect(codes(z.object({ id: z.string() }).optional())).toContain('AUTHZ_NON_STRICT_INPUT');
    expect(codes(z.object({ id: z.string() }).nullable())).toContain('AUTHZ_NON_STRICT_INPUT');
    expect(codes(z.object({ id: z.string() }).default({ id: 'x' }))).toContain(
      'AUTHZ_NON_STRICT_INPUT',
    );
    expect(codes(z.object({ id: z.string() }).readonly())).toContain('AUTHZ_NON_STRICT_INPUT');
    expect(codes(z.lazy(() => z.object({ id: z.string() })))).toContain('AUTHZ_NON_STRICT_INPUT');
  });

  it('inspects both sides of a pipe (transform and preprocess)', () => {
    // `transform` keeps the shape schema on the input side.
    expect(codes(z.object({ id: z.string() }).transform((value) => value.id))).toContain(
      'AUTHZ_NON_STRICT_INPUT',
    );
    expect(codes(z.strictObject({ id: z.string() }).transform((value) => value.id))).toEqual([]);
    // `z.preprocess` puts the object schema on the OUTPUT side.
    const preprocessed = z.preprocess((value) => value, z.strictObject({ tenantId: z.uuid() }));
    expect(codes(preprocessed)).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
  });

  it('rejects arbitrary any/unknown/custom input schemas', () => {
    expect(codes(z.strictObject({ payload: z.any() }))).toContain('AUTHZ_UNSAFE_INPUT_SCHEMA');
    expect(codes(z.strictObject({ payload: z.unknown() }))).toContain('AUTHZ_UNSAFE_INPUT_SCHEMA');
    expect(codes(z.strictObject({ payload: z.custom<{ role: string }>(() => true) }))).toContain(
      'AUTHZ_UNSAFE_INPUT_SCHEMA',
    );
    expect(codes(z.instanceof(Date))).toContain('AUTHZ_UNSAFE_INPUT_SCHEMA');
  });

  it('walks set and map values', () => {
    expect(codes(z.strictObject({ items: z.set(z.strictObject({ role: z.string() })) }))).toEqual([
      'AUTHZ_MASS_ASSIGNMENT',
    ]);
    expect(
      codes(
        z.strictObject({
          entries: z.map(z.string(), z.strictObject({ tenantId: z.string() })),
        }),
      ),
    ).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
  });
});

describe('mass-assignment scan — forbidden identity/status keys', () => {
  const forbidden = [
    'role',
    'roles',
    'tenantId',
    'tenant_id',
    'carrierId',
    'carrier_id',
    'status',
    'userId',
    'user_id',
    'createdBy',
    'created_by',
  ] as const;

  it('lists every forbidden key explicitly', () => {
    expect([...FORBIDDEN_INPUT_KEYS]).toEqual([...forbidden]);
  });

  it.each(forbidden)('rejects %s at the top level', (key) => {
    const schema = z.strictObject({ [key]: z.string() });
    expect(codes(schema)).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
    expect(paths(schema)).toEqual([`body.${key}`]);
  });

  it('matches case and underscore variants of the same key', () => {
    for (const key of ['TenantId', 'TENANT_ID', 'tenantid', 'Tenant_ID', 'CreatedBy']) {
      expect(codes(z.strictObject({ [key]: z.string() })), key).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
    }
  });

  it('rejects forbidden keys at nested paths, including arrays and records', () => {
    expect(codes(z.strictObject({ nested: z.strictObject({ role: z.string() }) }))).toEqual([
      'AUTHZ_MASS_ASSIGNMENT',
    ]);
    expect(
      codes(z.strictObject({ items: z.array(z.strictObject({ userId: z.string() })) })),
    ).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
    expect(
      paths(z.strictObject({ items: z.array(z.strictObject({ userId: z.string() })) })),
    ).toEqual(['body.items[].userId']);
    expect(
      codes(z.strictObject({ byId: z.record(z.string(), z.strictObject({ status: z.string() })) })),
    ).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
    expect(
      codes(
        z.strictObject({
          variant: z.union([
            z.strictObject({ carrierId: z.string() }),
            z.strictObject({ ok: z.string() }),
          ]),
        }),
      ),
    ).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
  });

  it('rejects a forbidden key on only one intersection branch', () => {
    const schema = z.intersection(
      z.strictObject({ name: z.string() }),
      z.strictObject({ createdBy: z.string() }),
    );
    expect(codes(schema)).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
  });

  it('accepts ordinary words that merely contain a forbidden word', () => {
    const schema = z.strictObject({
      roleName: z.string(),
      statusNote: z.string(),
      userIdentity: z.string(),
      createdAt: z.string(),
    });
    expect(scanInputSchema(schema, 'body')).toEqual([]);
  });

  it('rejects carrierId even beside a valid sensitive reason schema', () => {
    const schema = z.strictObject({
      reason: sensitiveReasonSchema,
      carrierId: z.uuid(),
    });
    // Carrier identity must come from the principal/scope; the scan treats the
    // key as forbidden on every surface, including a sensitive body.
    expect(codes(schema)).toEqual(['AUTHZ_MASS_ASSIGNMENT']);
  });
});

describe('mass-assignment scan — surfaces', () => {
  it('reports the correct surface and path for query and params schemas', () => {
    expect(
      scanInputSchema(z.strictObject({ tenantId: z.string() }), 'query').map((issue) => ({
        code: issue.code,
        path: issue.path,
      })),
    ).toEqual([{ code: 'AUTHZ_MASS_ASSIGNMENT', path: 'query.tenantId' }]);
    expect(
      scanInputSchema(z.strictObject({ userId: z.string() }), 'params').map((issue) => issue.path),
    ).toEqual(['params.userId']);
  });

  it('treats a missing schema as no input and contributes no issues', () => {
    expect(scanInputSchema(null, 'body')).toEqual([]);
    expect(scanInputSchema(undefined, 'query')).toEqual([]);
    expect(scanInputSchema(42, 'params')).toEqual([]);
  });

  it('fails closed on a recorded object that is not an inspectable Zod schema', () => {
    expect(codes({ shape: { name: 'string' } })).toEqual(['AUTHZ_UNSAFE_INPUT_SCHEMA']);
  });

  it('does not loop forever on a recursive lazy schema', () => {
    interface Node {
      children: Node[];
    }
    const node: z.ZodType<Node> = z.lazy(() =>
      z.strictObject({ children: z.array(node) }),
    ) as z.ZodType<Node>;
    expect(scanInputSchema(node, 'body')).toEqual([]);
  });

  it('flags both a forbidden key and a non-strict object in the same schema', () => {
    const result = scanInputSchema(z.object({ role: z.string() }), 'body');
    expect(result.map((issue) => issue.code).sort()).toEqual([
      'AUTHZ_MASS_ASSIGNMENT',
      'AUTHZ_NON_STRICT_INPUT',
    ]);
  });
});

import { v7 as uuidv7 } from 'uuid';
import { beforeAll, describe, expect, it } from 'vitest';

import { nameInputSchema, normalizeNameKey } from '../src/common/text/name-key.js';
import { createTenant, ownerPool } from './setup/db.js';

/**
 * Constraint-level proof for the five base-data tables (F1-07 T03, ADR-011).
 * Runs as the schema OWNER so RLS cannot mask a CHECK/UNIQUE/FK: the owner
 * path is also the migration/runbook path, so these invariants must hold
 * there too. RLS isolation is proven separately in base-data-rls.int.test.ts.
 */

function pgCode(err: unknown): string | undefined {
  let current: unknown = err;
  for (let i = 0; i < 5 && current !== null && current !== undefined; i++) {
    const code = (current as { code?: unknown }).code;
    if (typeof code === 'string') {
      return code;
    }
    current = (current as { cause?: unknown }).cause;
  }
  return undefined;
}

async function expectPgCode(promise: Promise<unknown>, code: string): Promise<void> {
  const err = await promise.then(
    () => {
      throw new Error(`expected a rejection with pg code ${code}, but the query succeeded`);
    },
    (e: unknown) => e,
  );
  expect(pgCode(err)).toBe(code);
}

interface Overrides {
  displayOrder?: number;
  version?: number;
}

function insertDestination(
  tenantId: string,
  name: string,
  nameKey: string,
  over: Overrides = {},
): Promise<unknown> {
  return ownerPool().query(
    `INSERT INTO destinations (id, tenant_id, name, name_key, display_order, version)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [uuidv7(), tenantId, name, nameKey, over.displayOrder ?? 0, over.version ?? 1],
  );
}

function insertHall(
  tenantId: string,
  name: string,
  nameKey: string,
  over: Overrides = {},
): Promise<unknown> {
  return ownerPool().query(
    `INSERT INTO halls (id, tenant_id, name, name_key, display_order, version)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [uuidv7(), tenantId, name, nameKey, over.displayOrder ?? 0, over.version ?? 1],
  );
}

function insertTerminal(
  tenantId: string,
  hallId: string,
  name: string,
  nameKey: string,
  over: Overrides = {},
): Promise<unknown> {
  return ownerPool().query(
    `INSERT INTO hall_terminals (id, tenant_id, hall_id, name, name_key, display_order, version)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [uuidv7(), tenantId, hallId, name, nameKey, over.displayOrder ?? 0, over.version ?? 1],
  );
}

function insertGroup(
  tenantId: string,
  name: string,
  nameKey: string,
  over: Overrides = {},
): Promise<unknown> {
  return ownerPool().query(
    `INSERT INTO loader_type_groups (id, tenant_id, name, name_key, display_order, version)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [uuidv7(), tenantId, name, nameKey, over.displayOrder ?? 0, over.version ?? 1],
  );
}

function insertLoaderType(
  tenantId: string,
  groupId: string,
  name: string,
  nameKey: string,
  over: Overrides = {},
): Promise<unknown> {
  return ownerPool().query(
    `INSERT INTO loader_types (id, tenant_id, group_id, name, name_key, display_order, version)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [uuidv7(), tenantId, groupId, name, nameKey, over.displayOrder ?? 0, over.version ?? 1],
  );
}

/** A fresh unique key fragment so unrelated inserts never collide on name_key. */
function tag(): string {
  return uuidv7().slice(0, 8);
}

describe('base-data schema constraints (integration)', () => {
  let tenantA: string;
  let tenantB: string;
  let hallA: string;
  let hallB: string;
  let groupA: string;
  let groupB: string;

  beforeAll(async () => {
    const owner = ownerPool();
    tenantA = await createTenant(owner, `base-a-${tag()}`);
    tenantB = await createTenant(owner, `base-b-${tag()}`);
    await insertHall(tenantA, 'Hall A', 'hall a');
    await insertHall(tenantB, 'Hall B', 'hall b');
    await insertGroup(tenantA, 'Group A', 'group a');
    await insertGroup(tenantB, 'Group B', 'group b');
    hallA = (
      await owner.query<{ id: string }>('SELECT id FROM halls WHERE tenant_id = $1', [tenantA])
    ).rows[0]?.id as string;
    hallB = (
      await owner.query<{ id: string }>('SELECT id FROM halls WHERE tenant_id = $1', [tenantB])
    ).rows[0]?.id as string;
    groupA = (
      await owner.query<{ id: string }>('SELECT id FROM loader_type_groups WHERE tenant_id = $1', [
        tenantA,
      ])
    ).rows[0]?.id as string;
    groupB = (
      await owner.query<{ id: string }>('SELECT id FROM loader_type_groups WHERE tenant_id = $1', [
        tenantB,
      ])
    ).rows[0]?.id as string;
  });

  it('defaults are applied: display_order 0, version 1, is_active true, timestamps set', async () => {
    const id = uuidv7();
    await ownerPool().query(
      `INSERT INTO destinations (id, tenant_id, name, name_key) VALUES ($1, $2, 'Defaults', 'defaults')`,
      [id, tenantA],
    );
    const row = (
      await ownerPool().query<{
        display_order: number;
        version: number;
        is_active: boolean;
        deleted_at: Date | null;
        created_at: Date;
        updated_at: Date;
      }>(
        'SELECT display_order, version, is_active, deleted_at, created_at, updated_at FROM destinations WHERE id = $1',
        [id],
      )
    ).rows[0];
    expect(row).toMatchObject({ display_order: 0, version: 1, is_active: true, deleted_at: null });
    expect(row?.created_at).toBeInstanceOf(Date);
    expect(row?.updated_at).toBeInstanceOf(Date);
  });

  it('all five tables reject a 1-character name and an empty name_key at the DB (23514)', async () => {
    const specs: ((name: string, key: string) => Promise<unknown>)[] = [
      (name, key) => insertDestination(tenantA, name, key),
      (name, key) => insertHall(tenantA, name, key),
      (name, key) => insertTerminal(tenantA, hallA, name, key),
      (name, key) => insertGroup(tenantA, name, key),
      (name, key) => insertLoaderType(tenantA, groupA, name, key),
    ];

    for (const insert of specs) {
      await expectPgCode(insert('a', `k-${tag()}`), '23514');
      // The app normalizes whitespace/ZWNJ-only names to '', so this row is
      // what a bypass would try; the DB rejects it instead of storing a key
      // no uniqueness rule can match.
      await expectPgCode(insert(`ab-${tag()}`, ''), '23514');
    }
  });

  it('a name that normalizes to empty is rejected at the DB level (two ZWNJ, key empty)', async () => {
    const zwnjOnly = '‌‌';
    expect(normalizeNameKey(zwnjOnly)).toBe('');
    await expectPgCode(insertDestination(tenantA, zwnjOnly, ''), '23514');
  });

  it('display_order and version CHECK bounds (destinations as the shared definition)', async () => {
    await expectPgCode(
      insertDestination(tenantA, `Order low ${tag()}`, `order-low-${tag()}`, { displayOrder: -1 }),
      '23514',
    );
    await expectPgCode(
      insertDestination(tenantA, `Order high ${tag()}`, `order-high-${tag()}`, {
        displayOrder: 10000,
      }),
      '23514',
    );
    await expectPgCode(
      insertDestination(tenantA, `Version zero ${tag()}`, `version-zero-${tag()}`, { version: 0 }),
      '23514',
    );
    await insertDestination(tenantA, `Order zero ${tag()}`, `order-zero-${tag()}`, {
      displayOrder: 0,
    });
    await insertDestination(tenantA, `Order max ${tag()}`, `order-max-${tag()}`, {
      displayOrder: 9999,
    });
  });

  it('column cap: a 65-character name or name_key is rejected (22001), 64 is accepted', async () => {
    const name64 = 'ب'.repeat(64);
    await insertDestination(tenantA, name64, name64);
    await expectPgCode(insertDestination(tenantA, 'Over Length', 'x'.repeat(65)), '22001');
  });

  it('emoji boundary: PostgreSQL counts code points, so 64 code points fit and 65 do not', async () => {
    const emoji = '😀'; // 1 code point, 2 UTF-16 units
    // 32 emoji = 64 UTF-16 units but only 32 characters: accepted.
    const thirtyTwo = emoji.repeat(32);
    await insertDestination(tenantA, thirtyTwo, thirtyTwo);

    // 32 Persian + 32 emoji = exactly 64 characters (96 UTF-16 units): accepted.
    const sixtyFour = 'م'.repeat(32) + emoji.repeat(32);
    expect(Array.from(sixtyFour)).toHaveLength(64);
    await insertDestination(tenantA, sixtyFour, sixtyFour);

    // 65 characters: the varchar(64) column cap fires first (22001); the
    // `char_length <= 64` CHECK is a redundant backstop behind the column type.
    const sixtyFive = 'م'.repeat(32) + emoji.repeat(33);
    expect(Array.from(sixtyFive)).toHaveLength(65);
    await expectPgCode(insertDestination(tenantA, sixtyFive, sixtyFive), '22001');

    // Isolate the name column: 65 characters in `name` with a valid short key,
    // so the 22001 can only come from `name varchar(64)`.
    await expectPgCode(insertDestination(tenantA, 'n'.repeat(65), `ok-${tag()}`), '22001');
  });

  it('the T02 app gate never emits a key over 64 code points; 22001 is only reachable by bypass', async () => {
    // A 40-unit input that expands on lowercasing (İ → i + combining dot) is
    // accepted by the schema (40 <= 64) and capped at 64 code points by the
    // normalizer, so the insert succeeds in the normal flow.
    const expanding = 'İ'.repeat(40);
    const parsed = nameInputSchema.parse(expanding);
    const key = normalizeNameKey(parsed);
    expect(Array.from(key).length).toBeLessThanOrEqual(64);
    await insertDestination(tenantA, parsed, key);

    // Raw over-length input never reaches normalization through the app.
    expect(nameInputSchema.safeParse('x'.repeat(65)).success).toBe(false);
    expect(nameInputSchema.safeParse('x'.repeat(100)).success).toBe(false);
    // Even a direct caller of the normalizer is capped at 64.
    expect(Array.from(normalizeNameKey('x'.repeat(100)))).toHaveLength(64);

    // The DB 22001 is the backstop for code that skips both helpers.
    await expectPgCode(insertDestination(tenantA, 'Bypass', 'y'.repeat(65)), '22001');
  });

  it('name_key uniqueness is per tenant and applies to live rows only', async () => {
    const key = `uq-${tag()}`;
    const first = uuidv7();
    await ownerPool().query(
      `INSERT INTO destinations (id, tenant_id, name, name_key) VALUES ($1, $2, 'Unique', $3)`,
      [first, tenantA, key],
    );
    // Same key, other tenant: allowed.
    await insertDestination(tenantB, 'Unique', key);
    // Same key, same tenant, live: rejected.
    await expectPgCode(insertDestination(tenantA, 'Unique', key), '23505');
    // Soft-deleted rows drop out of the partial unique index.
    await ownerPool().query('UPDATE destinations SET deleted_at = now() WHERE id = $1', [first]);
    await insertDestination(tenantA, 'Unique', key);
  });

  it('B4 normalization makes Arabic/Persian variants collide on the live key', async () => {
    const arabic = 'كريمان';
    const persian = 'کریمان';
    const key = normalizeNameKey(arabic);
    expect(normalizeNameKey(persian)).toBe(key);
    await insertDestination(tenantA, arabic, key);
    await expectPgCode(insertDestination(tenantA, persian, key), '23505');
  });

  it('terminal keys are unique per hall, not per tenant', async () => {
    const key = `term-${tag()}`;
    const secondHall = uuidv7();
    await ownerPool().query(
      `INSERT INTO halls (id, tenant_id, name, name_key) VALUES ($1, $2, 'Hall A2', $3)`,
      [secondHall, tenantA, `hall-a2-${tag()}`],
    );
    await insertTerminal(tenantA, hallA, 'Terminal', key);
    await insertTerminal(tenantB, hallB, 'Terminal', key);
    // Same tenant, different hall: allowed — a per-tenant index would fail here.
    await insertTerminal(tenantA, secondHall, 'Terminal', key);
    await expectPgCode(insertTerminal(tenantA, hallA, 'Terminal', key), '23505');
  });

  it('loader-type keys are unique per tenant even across groups', async () => {
    const key = `type-${tag()}`;
    await insertLoaderType(tenantA, groupA, 'Type', key);
    await insertLoaderType(tenantB, groupB, 'Type', key);
    const secondGroup = uuidv7();
    await ownerPool().query(
      `INSERT INTO loader_type_groups (id, tenant_id, name, name_key) VALUES ($1, $2, 'Group Two', $3)`,
      [secondGroup, tenantA, `group-two-${tag()}`],
    );
    // A different live group in the same tenant cannot reuse the type name.
    await expectPgCode(insertLoaderType(tenantA, secondGroup, 'Type', key), '23505');
  });

  it('composite FKs reject a cross-tenant or missing parent (23503)', async () => {
    await expectPgCode(
      insertTerminal(tenantA, hallB, 'Cross Hall', `cross-hall-${tag()}`),
      '23503',
    );
    await expectPgCode(
      insertLoaderType(tenantA, groupB, 'Cross Group', `cross-group-${tag()}`),
      '23503',
    );
    await expectPgCode(
      insertTerminal(tenantA, uuidv7(), 'Missing Hall', `missing-hall-${tag()}`),
      '23503',
    );
    await expectPgCode(
      insertDestination(uuidv7(), 'Missing Tenant', `missing-tenant-${tag()}`),
      '23503',
    );
  });
});

import { randomInt } from 'node:crypto';

import { parseEnv } from '../config/env.js';
import { createOperatorRuntime } from '../db/cli-runtime.js';
import type { OperatorRuntime } from '../db/cli-runtime.js';
import { assertPasswordPolicy, passwordKindForRoles } from '../modules/auth/password-policy.js';
import type { PasswordKind } from '../modules/auth/password-policy.js';
import { ASSIGNABLE_ROLES } from '../modules/users/users.types.js';
import type { AssignableRole } from '../modules/users/users.types.js';

/**
 * Operator credential CLI (F1-04 T08). Creates staff/driver accounts with a
 * generated one-time password and resets an existing account's password.
 *
 * Hard rules:
 * - The password is generated HERE with node:crypto and is NEVER accepted as
 *   an argument or environment variable, so it cannot leak through argv, shell
 *   history, process listings or env dumps. It is printed once, to stdout,
 *   only after the database write succeeded, and only as an Argon2id hash ever
 *   reaches storage.
 * - Production is refused unless `--allow-production` is passed explicitly;
 *   the guard runs before parseEnv or any connection is opened.
 * - Nothing else is printed on success; errors carry no argv values.
 */

export interface CliIo {
  out(line: string): void;
  err(line: string): void;
}

export interface CliContext {
  io: CliIo;
  env: NodeJS.ProcessEnv;
}

const PRODUCTION_FLAG = '--allow-production';

const STAFF_LENGTH = 20;
const DRIVER_PIN_LENGTH = 10;
const MAX_GENERATION_ATTEMPTS = 50;

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*-_=+';
const ALL_STAFF = LOWER + UPPER + DIGITS + SYMBOLS;

const CREATE_USER_FLAGS = ['--tenant', '--username', '--display-name', '--role', '--phone'];
const RESET_PASSWORD_FLAGS = ['--tenant', '--username', '--phone'];
const BOOLEAN_FLAGS = [PRODUCTION_FLAG];

const CREATE_USER_USAGE: readonly string[] = [
  'usage: create-user --tenant <code> --display-name <text> [--username <name>] [--role FACTORY_OPERATOR|CARRIER_ADMIN|DRIVER] [--phone <number>] [--allow-production]',
  '  Staff roles (FACTORY_OPERATOR, CARRIER_ADMIN) require --username.',
  '  DRIVER requires --phone; --username is optional.',
];

const RESET_PASSWORD_USAGE: readonly string[] = [
  'usage: reset-password --tenant <code> (--username <name> | --phone <number>) [--allow-production]',
  '  The stored role decides the password type: staff get a 20-character',
  '  password, a driver-only account gets a 10-digit PIN.',
];

interface ParsedFlags {
  readonly values: Map<string, string>;
  readonly booleans: Set<string>;
}

type ParseResult =
  | { readonly ok: true; readonly flags: ParsedFlags }
  | { readonly ok: false; readonly error: string };

function parseFlags(
  argv: string[],
  valueFlags: readonly string[],
  booleanFlags: readonly string[],
): ParseResult {
  const values = new Map<string, string>();
  const booleans = new Set<string>();
  let index = 0;
  while (index < argv.length) {
    const arg = argv[index];
    if (arg === undefined) {
      break;
    }
    if (booleanFlags.includes(arg)) {
      if (booleans.has(arg)) {
        return { ok: false, error: `duplicate flag: ${arg}` };
      }
      booleans.add(arg);
      index += 1;
      continue;
    }
    if (valueFlags.includes(arg)) {
      if (values.has(arg)) {
        return { ok: false, error: `duplicate flag: ${arg}` };
      }
      const value = argv[index + 1];
      if (value === undefined || value.startsWith('--')) {
        return { ok: false, error: `missing value for ${arg}` };
      }
      values.set(arg, value);
      index += 2;
      continue;
    }
    // Never echo a bare positional value: an operator who pasted a password
    // by mistake must not have it land in stderr or shell logs (T08 review).
    return {
      ok: false,
      error: arg.startsWith('--') ? `unknown argument: ${arg}` : 'unexpected positional argument',
    };
  }
  return { ok: true, flags: { values, booleans } };
}

function usageError(ctx: CliContext, lines: readonly string[]): number {
  for (const line of lines) {
    ctx.io.err(line);
  }
  return 2;
}

const LOCAL_DB_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function isLocalDatabaseUrl(url: string | undefined): boolean {
  if (url === undefined) {
    return false;
  }
  try {
    return LOCAL_DB_HOSTS.has(new URL(url).hostname);
  } catch {
    return false;
  }
}

function productionRefused(argv: string[], ctx: CliContext): boolean {
  const env = ctx.env.NODE_ENV;
  // Flag-free operation requires BOTH a development/test NODE_ENV AND a local
  // database. A stray `development` copied onto a production host (remote
  // DATABASE_URL) is refused, mirroring assertDevSeedAllowed (review L3).
  const developmentLike =
    (env === 'development' || env === 'test') && isLocalDatabaseUrl(ctx.env.DATABASE_URL);
  if (!developmentLike && !argv.includes(PRODUCTION_FLAG)) {
    ctx.io.err(
      'refused: running outside a local development/test database requires --allow-production',
    );
    return true;
  }
  return false;
}

function pick(chars: string): string {
  return chars.charAt(randomInt(chars.length));
}

function shuffle(chars: string[]): void {
  for (let index = chars.length - 1; index > 0; index -= 1) {
    const swapWith = randomInt(index + 1);
    const current = chars[index];
    const other = chars[swapWith];
    if (current === undefined || other === undefined) {
      continue;
    }
    chars[index] = other;
    chars[swapWith] = current;
  }
}

/** 20 characters, guaranteed to carry every required class, then shuffled. */
function generateStaffPassword(): string {
  const chars = [pick(LOWER), pick(UPPER), pick(DIGITS), pick(SYMBOLS)];
  while (chars.length < STAFF_LENGTH) {
    chars.push(pick(ALL_STAFF));
  }
  shuffle(chars);
  return chars.join('');
}

function generateDriverPin(): string {
  let pin = '';
  for (let index = 0; index < DRIVER_PIN_LENGTH; index += 1) {
    pin += pick(DIGITS);
  }
  return pin;
}

/**
 * Generates a candidate and re-generates until the A20 policy accepts it
 * (driver PIN blocklist / equality with the identifier). The candidate never
 * leaves this function unless it passed the policy.
 */
function generatePassword(kind: PasswordKind, identifier: string): string {
  for (let attempt = 0; attempt < MAX_GENERATION_ATTEMPTS; attempt += 1) {
    const candidate = kind === 'staff' ? generateStaffPassword() : generateDriverPin();
    try {
      assertPasswordPolicy(kind, candidate, identifier);
      return candidate;
    } catch {
      // Policy rejected it (blocklist / equals identifier) — try again.
    }
  }
  throw new Error('could not generate a password that satisfies the policy');
}

function isAssignableRole(value: string): value is AssignableRole {
  return (ASSIGNABLE_ROLES as readonly string[]).includes(value);
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'unknown error';
}

interface OneTimeOutput {
  readonly tenantCode: string;
  readonly login: string;
  readonly role: string;
  readonly password: string;
  readonly expiresAt: Date;
}

function printOneTimePassword(io: CliIo, output: OneTimeOutput): void {
  io.out('One-time password (shown once, NEVER logged or stored in plaintext):');
  io.out(`  tenant: ${output.tenantCode}`);
  io.out(`  login:  ${output.login}`);
  io.out(`  role:   ${output.role}`);
  io.out(`  password: ${output.password}`);
  io.out('');
  io.out(
    `The user must change it at first login. It expires at ${output.expiresAt.toISOString()}.`,
  );
}

function loginLabel(
  username: string | undefined,
  phone: string | undefined,
  tenantCode: string,
): string {
  return username !== undefined ? `${username}@${tenantCode}` : (phone ?? '');
}

export async function runCreateUser(argv: string[], ctx: CliContext): Promise<number> {
  if (productionRefused(argv, ctx)) {
    return 2;
  }

  const parsed = parseFlags(argv, CREATE_USER_FLAGS, BOOLEAN_FLAGS);
  if (!parsed.ok) {
    return usageError(ctx, [parsed.error, ...CREATE_USER_USAGE]);
  }
  const { values } = parsed.flags;

  const tenantCode = values.get('--tenant');
  const displayName = values.get('--display-name');
  const username = values.get('--username');
  const phone = values.get('--phone');
  const rawRole = values.get('--role');

  if (tenantCode === undefined || displayName === undefined || displayName.trim().length === 0) {
    return usageError(ctx, CREATE_USER_USAGE);
  }
  if (rawRole !== undefined && !isAssignableRole(rawRole)) {
    return usageError(ctx, [`invalid --role: ${rawRole}`, ...CREATE_USER_USAGE]);
  }
  const role: AssignableRole = rawRole === undefined ? 'FACTORY_OPERATOR' : rawRole;
  if (role === 'DRIVER') {
    if (phone === undefined) {
      return usageError(ctx, ['DRIVER requires --phone', ...CREATE_USER_USAGE]);
    }
  } else if (username === undefined) {
    return usageError(ctx, [`role ${role} requires --username`, ...CREATE_USER_USAGE]);
  }
  if (username === undefined && phone === undefined) {
    return usageError(ctx, CREATE_USER_USAGE);
  }
  // Guaranteed by the checks above; keeps the identifier's type honest.
  const identifier = username ?? phone;
  if (identifier === undefined) {
    return usageError(ctx, CREATE_USER_USAGE);
  }

  let runtime: OperatorRuntime | undefined;
  try {
    const config = parseEnv(ctx.env);
    runtime = await createOperatorRuntime(config);

    const tenant = await runtime.findTenant(tenantCode);
    if (tenant === null) {
      const available = await runtime.listTenantCodes();
      ctx.io.err(`create-user failed: unknown tenant "${tenantCode}"`);
      ctx.io.err(`available tenants: ${available.join(', ')}`);
      return 1;
    }

    // Never reuse an existing account: refuse if either login path is taken.
    if (username !== undefined && (await runtime.findUser(tenant.id, { username })) !== null) {
      ctx.io.err('create-user failed: a user with that username already exists in this tenant');
      return 1;
    }
    if (phone !== undefined && (await runtime.findUser(tenant.id, { phone })) !== null) {
      ctx.io.err('create-user failed: a user with that phone already exists in this tenant');
      return 1;
    }

    const kind = passwordKindForRoles([role]);
    const password = generatePassword(kind, identifier);
    const expiresAt = new Date(Date.now() + runtime.tempPasswordTtlHours * 3_600_000);
    const passwordHash = await runtime.passwords.hash(password);

    await runtime.createUserAndCredentials({
      tenantId: tenant.id,
      ...(username !== undefined ? { username } : {}),
      displayName,
      ...(phone !== undefined ? { phone } : {}),
      role,
      passwordHash,
      expiresAt,
    });

    printOneTimePassword(ctx.io, {
      tenantCode: tenant.code,
      login: loginLabel(username, phone, tenant.code),
      role,
      password,
      expiresAt,
    });
    return 0;
  } catch (error) {
    ctx.io.err(`create-user failed: ${safeMessage(error)}`);
    return 1;
  } finally {
    if (runtime !== undefined) {
      await runtime.close();
    }
  }
}

export async function runResetPassword(argv: string[], ctx: CliContext): Promise<number> {
  if (productionRefused(argv, ctx)) {
    return 2;
  }

  const parsed = parseFlags(argv, RESET_PASSWORD_FLAGS, BOOLEAN_FLAGS);
  if (!parsed.ok) {
    return usageError(ctx, [parsed.error, ...RESET_PASSWORD_USAGE]);
  }
  const { values } = parsed.flags;

  const tenantCode = values.get('--tenant');
  const username = values.get('--username');
  const phone = values.get('--phone');

  if (tenantCode === undefined) {
    return usageError(ctx, RESET_PASSWORD_USAGE);
  }
  if ((username === undefined) === (phone === undefined)) {
    return usageError(ctx, [
      'exactly one of --username or --phone is required',
      ...RESET_PASSWORD_USAGE,
    ]);
  }

  const identifier = username ?? phone;
  if (identifier === undefined) {
    return usageError(ctx, RESET_PASSWORD_USAGE);
  }

  let runtime: OperatorRuntime | undefined;
  try {
    const config = parseEnv(ctx.env);
    runtime = await createOperatorRuntime(config);

    const tenant = await runtime.findTenant(tenantCode);
    if (tenant === null) {
      const available = await runtime.listTenantCodes();
      ctx.io.err(`reset-password failed: unknown tenant "${tenantCode}"`);
      ctx.io.err(`available tenants: ${available.join(', ')}`);
      return 1;
    }

    const lookup = username !== undefined ? { username } : { phone: phone ?? '' };
    const user = await runtime.findUser(tenant.id, lookup);
    if (user === null) {
      ctx.io.err('reset-password failed: no matching user in this tenant');
      return 1;
    }
    if (!(await runtime.hasCredentials(tenant.id, user.id))) {
      ctx.io.err('reset-password failed: that user has no credential row to reset');
      return 1;
    }

    // The stored roles, not the lookup flag, decide the policy: a staff user
    // looked up by phone must still receive a staff-strength password.
    const kind = passwordKindForRoles(user.roles);
    const password = generatePassword(kind, identifier);
    const expiresAt = new Date(Date.now() + runtime.tempPasswordTtlHours * 3_600_000);
    const passwordHash = await runtime.passwords.hash(password);

    const outcome = await runtime.resetPassword(tenant.id, user.id, passwordHash, expiresAt);
    if (outcome !== 'ok') {
      ctx.io.err(
        outcome === 'missing'
          ? 'reset-password failed: that user has no credential row to reset'
          : 'reset-password failed: the password changed concurrently; run it again',
      );
      return 1;
    }

    printOneTimePassword(ctx.io, {
      tenantCode: tenant.code,
      login: loginLabel(username, phone, tenant.code),
      role: user.roles.join(',') || 'no-role',
      password,
      expiresAt,
    });
    return 0;
  } catch (error) {
    ctx.io.err(`reset-password failed: ${safeMessage(error)}`);
    return 1;
  } finally {
    if (runtime !== undefined) {
      await runtime.close();
    }
  }
}

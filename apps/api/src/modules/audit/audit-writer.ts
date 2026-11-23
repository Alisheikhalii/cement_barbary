import { Injectable } from '@nestjs/common';
import { v7 as uuidv7 } from 'uuid';

// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits AuditStore as the constructor param type for DI
import { AuditStore } from '../../db/audit-store.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits TenantContext as the constructor param type for DI
import { TenantContext } from '../../db/tenant-context.js';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits PiiService as the constructor param type for DI
import { buildAad, PiiService } from '../../security/pii/pii-crypto.js';
import { projectAuditSnapshot } from './audit-snapshot.js';

/**
 * Transactional audit append (ADR-009 L1a/L2, F1-06 T05).
 *
 * `append()` runs inside the caller's `TenantDb.run` transaction when one is
 * open (same scope), so a success row commits or rolls back with the change it
 * describes. The tenant always comes from the request context, never from the
 * entry; the row id is generated before the IP is encrypted because the PII
 * AAD binds `tenant:column:rowId`.
 *
 * The client IP is never stored in plaintext (owner Q2): `ip_enc` is the
 * AES-256-GCM blob with AAD `tenant:audit_logs.ip_enc:<rowId>` and `ip_hash` is
 * the keyed blind index `audit_logs.ip` — the same PII pattern as users.
 */

const ACTION_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
const RESOURCE_TYPE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const OUTCOMES = new Set(['success', 'failure', 'denied']);
const MAX_ACTION_LENGTH = 64;
const MAX_RESOURCE_ID_LENGTH = 128;
const MAX_REASON_LENGTH = 500;
const MAX_IP_LENGTH = 64;
const MAX_REQUEST_ID_LENGTH = 64;
const MAX_JSON_BYTES = 16_384;

export type AuditActorType = 'user' | 'system';
export type AuditAppendOutcome = 'success' | 'failure' | 'denied';

export interface AuditAppendEntry {
  readonly actorType: AuditActorType;
  readonly actorUserId: string | null;
  readonly actorSessionId?: string | null;
  /** Stable action name matching `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`. */
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId?: string | null;
  readonly outcome: AuditAppendOutcome;
  readonly httpStatus?: number | null;
  readonly reason?: string | null;
  readonly before?: unknown;
  readonly after?: unknown;
  readonly metadata?: unknown;
  /** Raw client IP for this write only; encrypted before it reaches the row. */
  readonly ip?: string | null;
  readonly requestId?: string | null;
}

/**
 * The DB CHECK is `octet_length(col::text) <= 16384`; PostgreSQL prints jsonb
 * with one space after every `:` and `,` outside strings, so JSON.stringify's
 * byte length alone UNDER-counts and a boundary payload would pass here then
 * abort the business transaction on the CHECK. Count the separators too.
 * Snapshot strings have C0 controls stripped in projectValue, so both sides
 * escape quotes/backslashes identically and this measure matches the DB.
 */
function jsonbTextBytes(json: string): number {
  let separators = 0;
  let inString = false;
  let escaped = false;
  for (const character of json) {
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === '\\') {
        escaped = true;
      } else if (character === '"') {
        inString = false;
      }
    } else if (character === '"') {
      inString = true;
    } else if (character === ':' || character === ',') {
      separators += 1;
    }
  }
  return Buffer.byteLength(json, 'utf8') + separators;
}

/** A well-formed string has no NUL and no lone surrogate (PostgreSQL rejects both). */
function isStorableString(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0) {
      return false;
    }
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      // charCodeAt past the end returns NaN; NaN comparisons are false, so a
      // trailing high surrogate needs the explicit guard.
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) {
        return false;
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * Rejects values whose JSON text length differs from PostgreSQL's jsonb text:
 * exponent numbers (`1e308` is 5 chars in JSON, 309 digits in jsonb) and
 * strings PostgreSQL cannot store (NUL, lone surrogate) would otherwise pass
 * the size guard and then abort the caller's transaction on the DB.
 */
function assertJsonbStorable(value: unknown): void {
  const stack: unknown[] = [value];
  let visited = 0;
  while (stack.length > 0) {
    visited += 1;
    if (visited > 10_000) {
      throw new Error('AUDIT_ENTRY_INVALID');
    }
    const current = stack.pop();
    if (typeof current === 'number') {
      if (!Number.isFinite(current) || /[eE]/.test(String(current))) {
        throw new Error('AUDIT_ENTRY_INVALID');
      }
    } else if (typeof current === 'string') {
      if (!isStorableString(current)) {
        throw new Error('AUDIT_ENTRY_INVALID');
      }
    } else if (Array.isArray(current)) {
      for (const item of current) {
        stack.push(item);
      }
    } else if (typeof current === 'object' && current !== null && !(current instanceof Date)) {
      for (const item of Object.values(current)) {
        stack.push(item);
      }
    }
  }
}

/** Mirrors the DB jsonb cap so an oversized snapshot fails locally, not as a 500. */
function boundedSnapshot(value: unknown): unknown {
  if (value === null || value === undefined) {
    return null;
  }
  const json = JSON.stringify(value);
  if (typeof json !== 'string') {
    throw new Error('AUDIT_ENTRY_INVALID');
  }
  // Validate the PARSED shape: JSON.stringify applies `toJSON`, so this is
  // exactly what PostgreSQL will receive, not the pre-serialization object.
  assertJsonbStorable(JSON.parse(json) as unknown);
  if (jsonbTextBytes(json) > MAX_JSON_BYTES) {
    throw new Error('AUDIT_ENTRY_INVALID');
  }
  return JSON.parse(json) as unknown;
}

function bounded(value: string | null | undefined, max: number): string | null {
  if (typeof value !== 'string' || value.length === 0) {
    return null;
  }
  return value.length > max ? value.slice(0, max) : value;
}

@Injectable()
export class AuditWriter {
  constructor(
    private readonly tenantContext: TenantContext,
    private readonly pii: PiiService,
    private readonly store: AuditStore,
  ) {}

  /** Appends the row and returns its id (needed by callers that must link it). */
  async append(entry: AuditAppendEntry): Promise<string> {
    const { tenantId } = this.tenantContext.require();
    this.assertValid(entry);

    const id = uuidv7();
    const ip = bounded(entry.ip, MAX_IP_LENGTH);
    const ipEnc =
      ip === null ? null : this.pii.encrypt(ip, buildAad(tenantId, 'audit_logs.ip_enc', id));
    const ipHash = ip === null ? null : this.pii.blindIndex('audit_logs.ip', tenantId, ip);

    await this.store.append({
      id,
      tenantId,
      actorType: entry.actorType,
      actorUserId: entry.actorType === 'user' ? entry.actorUserId : null,
      actorSessionId: entry.actorSessionId ?? null,
      action: entry.action,
      resourceType: entry.resourceType,
      resourceId: bounded(entry.resourceId, MAX_RESOURCE_ID_LENGTH),
      outcome: entry.outcome,
      httpStatus: entry.httpStatus ?? null,
      reason: entry.reason ?? null,
      // Never store a raw row: an unknown entity projects to null.
      before: boundedSnapshot(projectAuditSnapshot(entry.resourceType, entry.before)),
      after: boundedSnapshot(projectAuditSnapshot(entry.resourceType, entry.after)),
      metadata: boundedSnapshot(entry.metadata ?? null),
      ipEnc,
      ipHash,
      requestId: bounded(entry.requestId, MAX_REQUEST_ID_LENGTH),
    });
    return id;
  }

  /** Mirrors the DB checks so a programming bug fails here, before SQL. */
  private assertValid(entry: AuditAppendEntry): void {
    if (
      !ACTION_PATTERN.test(entry.action) ||
      entry.action.length > MAX_ACTION_LENGTH ||
      !RESOURCE_TYPE_PATTERN.test(entry.resourceType) ||
      !OUTCOMES.has(entry.outcome) ||
      (entry.actorType === 'user' && entry.actorUserId === null) ||
      // PostgreSQL `length()` counts characters (code points), not UTF-16
      // units: a 500-character Persian + emoji reason must stay valid.
      (typeof entry.reason === 'string' && [...entry.reason].length > MAX_REASON_LENGTH)
    ) {
      throw new Error('AUDIT_ENTRY_INVALID');
    }
    if (
      entry.httpStatus !== null &&
      entry.httpStatus !== undefined &&
      (!Number.isInteger(entry.httpStatus) || entry.httpStatus < 100 || entry.httpStatus > 599)
    ) {
      throw new Error('AUDIT_ENTRY_INVALID');
    }
  }
}

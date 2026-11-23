/** Outbox contracts shared by the producer, the worker and the adapters. */

export interface OutboxSettings {
  readonly workerEnabled: boolean;
  readonly mockEnabled: boolean;
  readonly pollMs: number;
  readonly batchSize: number;
  readonly leaseSeconds: number;
  readonly maxAttempts: number;
  readonly adapterTimeoutMs: number;
  readonly backoffBaseSeconds: number;
}

/** What an adapter receives; `outboxId` is its idempotency key. */
export interface OutboundMessage {
  readonly outboxId: string;
  readonly topic: string;
  /** Decrypted JSON payload. */
  readonly payload: string;
}

export interface OutboxAdapter {
  send(message: OutboundMessage): Promise<void>;
}

/** Optional metrics seam: a no-op provider is always bound (owner CP5 change 6). */
export interface OutboxMetrics {
  deadLetter(topic: string, errorCode: string): void;
}

export const OUTBOX_ADAPTER = Symbol('OUTBOX_ADAPTER');
export const OUTBOX_METRICS = Symbol('OUTBOX_METRICS');

/** Stable, allowlisted adapter failure codes. Provider text never escapes. */
export type OutboxAdapterErrorCode = 'ADAPTER_TIMEOUT' | 'ADAPTER_REJECTED' | 'ADAPTER_UNAVAILABLE';

export class OutboxAdapterError extends Error {
  constructor(readonly code: OutboxAdapterErrorCode) {
    super(code);
    this.name = 'OutboxAdapterError';
  }
}

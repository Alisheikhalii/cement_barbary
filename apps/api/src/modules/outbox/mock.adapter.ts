import { Injectable } from '@nestjs/common';

import type { OutboundMessage, OutboxAdapter } from './outbox.types.js';

/**
 * Development adapter (flagged, refused in production): records each effect
 * and dedupes on `outbox.id`, which is the contract every real provider must
 * implement too (ADR-010 L14). A second delivery of the same id is a no-op.
 */
@Injectable()
export class MockAdapter implements OutboxAdapter {
  readonly #delivered = new Set<string>();
  readonly #effects: { outboxId: string; topic: string; payload: string }[] = [];

  async send(message: OutboundMessage): Promise<void> {
    if (this.#delivered.has(message.outboxId)) {
      return;
    }
    this.#delivered.add(message.outboxId);
    this.#effects.push({
      outboxId: message.outboxId,
      topic: message.topic,
      payload: message.payload,
    });
  }

  /** Test-only observation: one entry per real effect. */
  effects(): readonly { outboxId: string; topic: string; payload: string }[] {
    return [...this.#effects];
  }

  reset(): void {
    this.#delivered.clear();
    this.#effects.length = 0;
  }
}

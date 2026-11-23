import { Injectable } from '@nestjs/common';

import { OutboxAdapterError, type OutboxAdapter } from './outbox.types.js';

/**
 * Bound when no provider is configured (v1 ships only the mock behind its
 * flag). A send fails with a stable code, so a row backs off and eventually
 * lands in `dead` instead of being silently dropped; F8 binds a real adapter
 * behind its own feature flag (GUIDELINES §12).
 */
@Injectable()
export class DisabledAdapter implements OutboxAdapter {
  async send(): Promise<void> {
    throw new OutboxAdapterError('ADAPTER_UNAVAILABLE');
  }
}

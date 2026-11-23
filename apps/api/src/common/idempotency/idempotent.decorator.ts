import { SetMetadata } from '@nestjs/common';

import { IDEMPOTENT_KEY } from './idempotency.constants.js';

/**
 * Marks a mutating route as idempotent (ADR-010 L9/L10).
 *
 * The marker is metadata only; the global `IdempotencyInterceptor` reads it and
 * enforces the key, the claim, the replay and the handler cap. Every
 * `@RequirePermission` POST/PUT/PATCH/DELETE route must carry it — the boot scan
 * and the route-scan test refuse to start/commit without it (opt-out list empty).
 *
 * Handlers behind this marker may only cause effects INSIDE the request
 * transaction (owner CP4 change 1): an outbox enqueue in the same transaction is
 * safe; a direct SMS/HTTP/payment call is not, because the cap aborts the
 * transaction but cannot cancel JS work that already left the process.
 */
export const Idempotent = (): MethodDecorator => SetMetadata(IDEMPOTENT_KEY, true);

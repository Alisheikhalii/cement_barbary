import type { Request } from 'express';

import { readAuthzContext } from '../../security/authz/access-scope.js';

/** Who performed a base-data write; audit only — never accepted from the client. */
export interface BaseDataWriteActor {
  readonly userId: string;
  readonly sessionId: string;
  readonly ip: string | null;
  readonly requestId: string | null;
}

/** Builds the audit actor from the verified principal + request metadata. */
export function writeActor(request: Request): BaseDataWriteActor {
  const { principal } = readAuthzContext(request);
  const id = (request as Request & { id?: unknown }).id;
  return {
    userId: principal.userId,
    sessionId: principal.sessionId,
    ip: typeof request.ip === 'string' && request.ip.length > 0 ? request.ip : null,
    requestId: typeof id === 'string' && id.length > 0 ? id : null,
  };
}

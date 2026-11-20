/**
 * Base class for all domain errors (GUIDELINES §3): a stable machine-readable
 * `code`, a Persian user-facing message, and technical details that stay out of
 * the message. HTTP mapping lives here so services never import HTTP types.
 */
export class DomainError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly statusCode: number,
    readonly details: Record<string, unknown> | undefined = undefined,
  ) {
    super(message);
    this.name = 'DomainError';
  }

  static badInput(details?: Record<string, unknown>): DomainError {
    return new DomainError('BAD_INPUT', 'ورودی نامعتبر است', 400, details);
  }

  /** Uniqueness conflict inside the tenant (phone, username, …) — 409. Message stays generic; details never echo the value. */
  static conflict(details?: Record<string, unknown>): DomainError {
    return new DomainError('CONFLICT', 'این مقدار قبلاً ثبت شده است', 409, details);
  }

  /** Unexpected internal failure (e.g. an untranslated DB error) — 500. Message and details never echo input data. */
  static internal(details?: Record<string, unknown>): DomainError {
    return new DomainError('INTERNAL', 'خطای داخلی سرور رخ داد', 500, details);
  }

  /** Tenant data was requested without an active tenant scope — always a server bug (fail closed). */
  static tenantContextMissing(): DomainError {
    return new DomainError('TENANT_CONTEXT_MISSING', 'خطای داخلی سرور رخ داد', 500);
  }
}

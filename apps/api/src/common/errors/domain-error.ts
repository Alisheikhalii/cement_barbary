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

  /** Missing/invalid bearer token — 401. Never says which part failed (A3). */
  static unauthorized(): DomainError {
    return new DomainError('UNAUTHORIZED', 'احراز هویت نامعتبر است', 401);
  }

  /**
   * The single generic credential failure (A3): unknown tenant/user/phone,
   * malformed identifier, wrong password, delayed, disabled, expired temp
   * password — identical status, code, message and shape. Never a reason.
   */
  static invalidCredentials(): DomainError {
    return new DomainError('INVALID_CREDENTIALS', 'اطلاعات ورود نامعتبر است', 401);
  }

  /** 429 with Retry-After (A11). Carries only the wait time, never bucket details. */
  static tooManyRequests(retryAfterSeconds: number): DomainError {
    return new DomainError('TOO_MANY_REQUESTS', 'تعداد درخواست‌ها بیش از حد مجاز است', 429, {
      retryAfterSeconds,
    });
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

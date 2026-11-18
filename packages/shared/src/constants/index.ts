/** Public REST API version prefix (GUIDELINES §3.1). */
export const API_VERSION = 'v1';
export const API_PREFIX = `/api/${API_VERSION}`;

/** Default page size for server-side pagination. */
export const DEFAULT_PAGE_SIZE = 50;

/** Minimum custom wallet top-up amount, in Rial (PRD §5.4). Amounts are always integers. */
export const MIN_WALLET_CHARGE_RIAL = 20_000;

/** Max priorities a driver can pick in a timed reservation window (PRD BR-09). */
export const DEFAULT_MAX_PRIORITIES = 3;

import { describe, expect, it } from 'vitest';

import {
  API_PREFIX,
  DEFAULT_MAX_PRIORITIES,
  DEFAULT_PAGE_SIZE,
  MIN_WALLET_CHARGE_RIAL,
} from './index.js';

describe('shared constants', () => {
  it('exposes the versioned API prefix', () => {
    expect(API_PREFIX).toBe('/api/v1');
  });

  it('keeps money values as safe integers (no floats)', () => {
    expect(Number.isSafeInteger(MIN_WALLET_CHARGE_RIAL)).toBe(true);
    expect(MIN_WALLET_CHARGE_RIAL).toBe(20_000);
  });

  it('uses business defaults from the PRD', () => {
    expect(DEFAULT_MAX_PRIORITIES).toBe(3);
    expect(DEFAULT_PAGE_SIZE).toBe(50);
  });
});

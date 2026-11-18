import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { colors, elevation, radius, spacing, typography } from './tokens.js';

const srcDir = fileURLToPath(new URL('.', import.meta.url));
const css = readFileSync(join(srcDir, 'tokens.css'), 'utf8');

function cssVar(name: string): string | undefined {
  const match = new RegExp(`--${name}:\\s*([^;]+);`).exec(css);
  return match?.[1]?.trim();
}

const kebab = (s: string): string => s.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);

describe('design tokens', () => {
  it('match the Design System spec for the core palette', () => {
    expect(colors.primary).toBe('#1E40AF');
    expect(colors.primaryLight).toBe('#3B82F6');
    expect(colors.primaryDark).toBe('#1E3A8A');
    expect(colors.success).toBe('#059669');
    expect(colors.warning).toBe('#D97706');
    expect(colors.danger).toBe('#DC2626');
    expect(colors.info).toBe('#0891B2');
    expect(colors.background).toBe('#F1F5F9');
    expect(colors.textPrimary).toBe('#0F172A');
  });

  it('keep every color in tokens.css in sync with tokens.ts', () => {
    for (const [key, value] of Object.entries(colors)) {
      expect(cssVar(`color-${kebab(key)}`), key).toBe(value.toLowerCase());
    }
  });

  it('keep elevation, radius and spacing in sync', () => {
    for (const [key, value] of Object.entries(elevation)) {
      expect(cssVar(`elevation-${key}`), `elevation-${key}`).toBe(value);
    }
    for (const [key, value] of Object.entries(radius)) {
      expect(cssVar(`radius-${key}`), `radius-${key}`).toBe(value);
    }
    spacing.forEach((px, i) => {
      expect(cssVar(`space-${i + 1}`)).toBe(`${px}px`);
    });
  });

  it('uses the 8-based spacing scale and spec font sizes', () => {
    expect(spacing).toEqual([4, 8, 12, 16, 20, 24, 32, 40, 48, 64]);
    expect(typography.pageTitle.size).toBe('24px');
    expect(typography.helper.size).toBe('12px');
  });

  it('references no external URL (no runtime dependency outside Iran)', () => {
    for (const file of readdirSync(srcDir)) {
      if (file.endsWith('.test.ts')) continue;
      const content = readFileSync(join(srcDir, file), 'utf8');
      expect(content, file).not.toMatch(/https?:\/\//);
      expect(content, file).not.toMatch(/@import/);
    }
  });
});

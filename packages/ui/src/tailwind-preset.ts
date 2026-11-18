// Tailwind preset (plain object; no Tailwind dependency until the web app exists, F1-12).
// Values point at the CSS variables in tokens.css so there is one source of truth.
import { spacing } from './tokens.js';

const v = (name: string): string => `var(--${name})`;

export const tailwindPreset = {
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: v('color-primary'),
          light: v('color-primary-light'),
          dark: v('color-primary-dark'),
        },
        success: {
          DEFAULT: v('color-success'),
          light: v('color-success-light'),
          dark: v('color-success-dark'),
        },
        warning: { DEFAULT: v('color-warning'), dark: v('color-warning-dark') },
        danger: { DEFAULT: v('color-danger'), dark: v('color-danger-dark') },
        info: v('color-info'),
        neutral: { DEFAULT: v('color-neutral'), dark: v('color-neutral-dark') },
        background: v('color-background'),
        surface: {
          DEFAULT: v('color-surface'),
          elevated: v('color-surface-elevated'),
          hover: v('color-surface-hover'),
        },
        border: { subtle: v('color-border-subtle') },
        text: {
          primary: v('color-text-primary'),
          body: v('color-text-body'),
          secondary: v('color-text-secondary'),
          muted: v('color-text-muted'),
        },
      },
      boxShadow: {
        'elevation-1': v('elevation-1'),
        'elevation-2': v('elevation-2'),
        'elevation-3': v('elevation-3'),
        'elevation-4': v('elevation-4'),
        'elevation-hover': v('elevation-hover'),
        modal: v('elevation-modal'),
      },
      borderRadius: {
        button: v('radius-button'),
        table: v('radius-table'),
        card: v('radius-card'),
        modal: v('radius-modal'),
        glass: v('radius-glass'),
      },
      spacing: Object.fromEntries(spacing.map((_, i) => [`ds-${i + 1}`, v(`space-${i + 1}`)])),
      fontFamily: { sans: [v('font-family')] },
      minHeight: { touch: v('touch-target') },
      minWidth: { touch: v('touch-target') },
    },
  },
} as const;

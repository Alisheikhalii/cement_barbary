// Design tokens from docs/specs/UI-UX-3D-Design-System.md (§2 colors, §3 elevation,
// §4 buttons, §5 radii, §8 typography, §9 spacing). Single source of truth:
// tokens.css mirrors these values and a test keeps them in sync.

export const colors = {
  primary: '#1E40AF',
  primaryLight: '#3B82F6',
  primaryDark: '#1E3A8A',
  success: '#059669',
  successLight: '#10B981',
  successDark: '#047857',
  warning: '#D97706',
  warningDark: '#B45309',
  danger: '#DC2626',
  dangerDark: '#B91C1C',
  info: '#0891B2',
  neutral: '#64748B',
  neutralDark: '#475569',
  background: '#F1F5F9',
  surface: '#FFFFFF',
  surfaceElevated: '#FFFFFF',
  surfaceHover: '#F8FAFC',
  borderSubtle: '#E2E8F0',
  textPrimary: '#0F172A',
  textBody: '#334155',
  textSecondary: '#475569',
  textMuted: '#94A3B8',
} as const;

export const gradients = {
  header: 'linear-gradient(135deg, #1E40AF 0%, #1E3A8A 100%)',
  highlight: 'linear-gradient(135deg, #EFF6FF 0%, #DBEAFE 100%)',
  debt: 'linear-gradient(135deg, #ECFDF5 0%, #D1FAE5 100%)',
  buttonPrimary: 'linear-gradient(180deg, #3B82F6 0%, #1E40AF 100%)',
} as const;

export const elevation = {
  0: 'none',
  1: '0 1px 3px rgba(15, 23, 42, 0.06), 0 4px 8px rgba(15, 23, 42, 0.04)',
  2: '0 4px 6px rgba(15, 23, 42, 0.07), 0 10px 20px rgba(15, 23, 42, 0.06)',
  3: '0 10px 25px rgba(15, 23, 42, 0.1), 0 20px 40px rgba(15, 23, 42, 0.08)',
  4: '0 20px 40px rgba(15, 23, 42, 0.12), 0 30px 60px rgba(15, 23, 42, 0.1)',
  hover: '0 8px 16px rgba(15, 23, 42, 0.08), 0 16px 32px rgba(15, 23, 42, 0.06)',
  modal: '0 25px 50px rgba(15, 23, 42, 0.15), 0 15px 30px rgba(15, 23, 42, 0.1)',
} as const;

export const radius = {
  button: '12px',
  table: '12px',
  card: '16px',
  modal: '20px',
  glass: '20px',
  full: '9999px',
} as const;

/** 8-based spacing scale (§9), in px. */
export const spacing = [4, 8, 12, 16, 20, 24, 32, 40, 48, 64] as const;

export const typography = {
  fontFamily: "'Vazirmatn', system-ui, sans-serif",
  pageTitle: { size: '24px', weight: 700, color: colors.textPrimary },
  sectionTitle: { size: '18px', weight: 600, color: colors.primary },
  cardTitle: { size: '16px', weight: 600, color: colors.textPrimary },
  body: { size: '14px', weight: 400, color: colors.textBody },
  label: { size: '13px', weight: 500, color: colors.textSecondary },
  helper: { size: '12px', weight: 400, color: colors.textMuted },
} as const;

export const motion = {
  easeStandard: 'cubic-bezier(0.4, 0, 0.2, 1)',
  easeModal: 'cubic-bezier(0.16, 1, 0.3, 1)',
  durationFast: '0.15s',
  durationBase: '0.25s',
  durationModal: '0.3s',
} as const;

/** Minimum touch target (§4.1 circle button). */
export const touchTarget = '44px';

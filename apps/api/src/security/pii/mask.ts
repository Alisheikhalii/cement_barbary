/**
 * Display masks for personal data (ADR-006 U11). These are the only shapes in
 * which a phone or national ID may ever appear in a UI, log or support reply.
 */

/** `09120000001` → `0912***0001` (allowlisted synthetic example, U17). Non-canonical input is fully hidden. */
export function maskPhone(normalizedPhone: string): string {
  if (!/^09\d{9}$/.test(normalizedPhone)) {
    return '***********';
  }
  return `${normalizedPhone.slice(0, 4)}***${normalizedPhone.slice(-4)}`;
}

/** Keeps only the last 4 digits (`******5678` shape); no literal example — national IDs are runtime-generated in tests (U17). Anything shorter is fully hidden. */
export function maskNationalId(nationalId: string): string {
  const digits = nationalId.replace(/\D/g, '');
  if (digits.length < 4) {
    return '**********';
  }
  return `******${digits.slice(-4)}`;
}

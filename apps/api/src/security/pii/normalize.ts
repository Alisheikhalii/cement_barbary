import { DomainError } from '../../common/errors/domain-error.js';

/**
 * Normalization of personal data BEFORE hashing or encryption (ADR-006 U9):
 * the same value written two ways must produce one canonical form, so the
 * blind index and the uniqueness constraint actually work. Error messages
 * never echo the input (U11).
 */

const PERSIAN_ZERO = 0x06f0; // ۰
const ARABIC_ZERO = 0x0660; // ٠

/** Converts Persian (۰-۹) and Arabic-Indic (٠-٩) digits to ASCII; leaves everything else untouched. */
export function toAsciiDigits(input: string): string {
  let out = '';
  for (const ch of input) {
    const code = ch.codePointAt(0) ?? 0;
    if (code >= PERSIAN_ZERO && code <= PERSIAN_ZERO + 9) {
      out += String(code - PERSIAN_ZERO);
    } else if (code >= ARABIC_ZERO && code <= ARABIC_ZERO + 9) {
      out += String(code - ARABIC_ZERO);
    } else {
      out += ch;
    }
  }
  return out;
}

const PHONE_RE = /^09\d{9}$/;
const NATIONAL_ID_RE = /^\d{10}$/;

/**
 * Canonical Iranian mobile: `09XXXXXXXXX`. Accepts the common forms
 * `+989…`, `00989…`, `989…`, `9…`, `09…` (with spaces/dashes/parentheses and
 * non-ASCII digits). Anything else is rejected.
 */
export function normalizePhone(input: unknown): string {
  if (typeof input !== 'string') {
    throw DomainError.badInput({ field: 'phone' });
  }
  let phone = toAsciiDigits(input).replace(/[\s\-().]/g, '');
  if (phone.startsWith('+98')) phone = `0${phone.slice(3)}`;
  else if (phone.startsWith('0098')) phone = `0${phone.slice(4)}`;
  else if (phone.startsWith('98')) phone = `0${phone.slice(2)}`;
  else if (phone.startsWith('9')) phone = `0${phone}`;
  if (!PHONE_RE.test(phone)) {
    throw DomainError.badInput({ field: 'phone' });
  }
  return phone;
}

/**
 * Canonical Iranian national ID: 10 ASCII digits with the official checksum.
 * All-identical digits (e.g. 1111111111) are not valid IDs.
 */
export function normalizeNationalId(input: unknown): string {
  if (typeof input !== 'string') {
    throw DomainError.badInput({ field: 'nationalId' });
  }
  const id = toAsciiDigits(input).replace(/[\s-]/g, '');
  if (!NATIONAL_ID_RE.test(id) || /^(\d)\1{9}$/.test(id)) {
    throw DomainError.badInput({ field: 'nationalId' });
  }
  let sum = 0;
  for (let i = 0; i < 9; i += 1) {
    sum += Number(id[i]) * (10 - i);
  }
  const remainder = sum % 11;
  const checkDigit = Number(id[9]);
  const valid = remainder < 2 ? checkDigit === remainder : checkDigit === 11 - remainder;
  if (!valid) {
    throw DomainError.badInput({ field: 'nationalId' });
  }
  return id;
}

import { randomInt } from 'node:crypto';

/**
 * Runtime generator for synthetic Iranian national IDs with a valid checksum
 * (ADR-006 U17): tests must never contain national-ID literals. The generated
 * values are random per run and carry no real person's data.
 */
export function randomNationalId(): string {
  for (;;) {
    const digits = Array.from({ length: 9 }, () => randomInt(0, 10));
    // All-identical digits are not valid IDs.
    if (digits.every((d) => d === digits[0])) {
      continue;
    }
    const sum = digits.reduce((acc, digit, i) => acc + digit * (10 - i), 0);
    const remainder = sum % 11;
    const checkDigit = remainder < 2 ? remainder : 11 - remainder;
    return digits.join('') + String(checkDigit);
  }
}

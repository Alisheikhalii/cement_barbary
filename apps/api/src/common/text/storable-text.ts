/**
 * PostgreSQL text/`varchar` cannot store U+0000 or an unpaired UTF-16
 * surrogate. Passing one to the driver fails with SQLSTATE 22021 ("invalid
 * byte sequence"), which would surface as a 500 after the request already
 * passed Zod validation. Every client string that can reach a text column is
 * checked here, so such input is a 400 at the boundary instead.
 *
 * Other C0 controls are storable and are not rejected here; `nameInputSchema`
 * still collapses whitespace, and the audit projection strips controls.
 */
export function isStorableText(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0) {
      return false;
    }
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      // charCodeAt past the end is NaN; a trailing high surrogate has no pair.
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) {
        return false;
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * M10-c regex-based forbidden-key guard. Complements the deop-protocol
 * `assertNoForbiddenPlaintextFields` (which is an exact normalized-name
 * allowlist) by adding a stricter pattern-based filter for the
 * balance-decryption / normalize surfaces where keys like `plaintextBalance`,
 * `balanceChunks`, `dkShare`, `decryptionKey`, `merklePath`, `commitmentHex`,
 * `leafIndex`, and `sender` would leak witness or structural information even
 * though not all are raw scalars.
 *
 * The regex MUST stay aligned with the plan's M10-c spec — extending it
 * requires the corresponding test in `coordinator/tests/balance_decrypt_route.test.ts`.
 *
 * Pattern groups (all case-insensitive, full-token):
 *   - `amount`, `secret`, `nullifier`, `sender`            → exact tokens
 *   - `plaintext*`, `*balance*chunks*`, `*blind*`, `*dkShare*`,
 *     `*decryption*key*`, `merkle.*`, `.*Path`             → wildcard forms
 *   - `dk`, `inverse`, `commitmentHex`, `leafIndex`        → exact tokens
 *
 * Throws `Error("forbidden_field:<path>")` on the first offending key the
 * recursive visitor encounters. Path uses `$.foo.bar[0].baz` notation so the
 * caller can pinpoint exactly where the leak originates.
 */

export const FORBIDDEN_KEY_RE =
  /^(amount|.*amount.*chunks.*|secret|.*secret.*|nullifier|plaintext.*|.*plaintext.*|balanceChunks|.*balance.*chunks.*|.*blind.*|dk|.*dkShare.*|decryptionKey|.*decryption.*key.*|inverse|commitmentHex|leafIndex|merkle.*|.*Path|sender)$/i;

/**
 * Recursively walk `obj` and throw on the first key that matches
 * `FORBIDDEN_KEY_RE`. Arrays are indexed with `[i]` in the error path; object
 * keys are joined with `.`.
 *
 * The check applies to OBJECT KEYS, not to primitive values — a string value
 * `"amount"` somewhere in the tree is fine; an object key `amount` is not.
 *
 * The visitor short-circuits on the first violation by throwing; callers that
 * want to collect all violations must catch and continue (none currently do).
 */
export function assertNoForbiddenKeys(obj: unknown, path = "$"): void {
  if (obj === null || obj === undefined) return;
  if (typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i += 1) {
      assertNoForbiddenKeys(obj[i], `${path}[${i}]`);
    }
    return;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (FORBIDDEN_KEY_RE.test(k)) {
      throw new Error(`forbidden_field:${path}.${k}`);
    }
    assertNoForbiddenKeys(v, `${path}.${k}`);
  }
}

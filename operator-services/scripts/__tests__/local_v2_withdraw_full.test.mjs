// operator-services/scripts/__tests__/local_v2_withdraw_full.test.mjs
//
// M10-f — privacy regression tests for the public `withdraw_tree_context`
// side-car artifact emitted by `scripts/local_v2_withdraw_full.mjs`.
//
// Background (codex P1 finding on M9):
//   The previous side-car (`withdraw_tree_context_v1`) wrote two fields that
//   directly linked the spent leaf in the multi-leaf anonymity set to the
//   withdraw:
//     - commitmentHex   (the exact deposit commitment hex)
//     - leafIndex       (its index in the Merkle tree)
//   Both make deposit↔withdraw linkable with a single grep over a public
//   0o644 file — defeating the entire M9 anonymity guarantee.
//
//   M10-f strips both fields, bumps schema to `withdraw_tree_context_v2`,
//   and strengthens the in-script FORBIDDEN regex so future authors who
//   accidentally re-add an equivalent key get a process.exit(34) hard-fail.
//
// What we test here:
//   1. Reading the side-car write block in the orchestrator confirms the
//      live source-of-truth schema is v2, the two forbidden keys are gone,
//      and the FORBIDDEN regex has been broadened.
//   2. The strengthened regex rejects every name we expect it to reject and
//      lets through every name we expect it to keep.
//   3. The exit-34 hard-fail path trips when a forbidden key is injected
//      into a side-car-shaped ctx object before the write — proves the
//      regex is wired to the failure branch and not a no-op.
//
// Why source-string reads rather than driving the script as a subprocess:
//   The side-car write sits ~770 lines into a 1000-line orchestrator after
//   coordinator round1/round2, RistrettoPoint math, and the witness
//   sub-process. M10-d's `--check-balance-only` flag intentionally exits
//   BEFORE the side-car is written (verified by
//   local_v2_withdraw_full_balance.test.mjs:452), so it cannot be used to
//   reach this code path.  A full end-to-end drive is what
//   `testnet:e2e` does — and it lives outside the unit-test layer. For a
//   focused privacy regression we anchor on (a) the literal source code we
//   shipped, and (b) the regex semantics in isolation. Both are sufficient
//   to catch the only failure mode that matters: a future edit that puts
//   commitmentHex / leafIndex / equivalent back into the side-car.
//
// Run via:
//
//     cd operator-services && node --test scripts/__tests__/local_v2_withdraw_full.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "local_v2_withdraw_full.mjs",
);

// Pull the live script source once — every test reads against it so that a
// future edit that drifts the side-car block can't silently make these tests
// pass against a stale snapshot.
const SCRIPT_SRC = readFileSync(SCRIPT_PATH, "utf8");

// The regex literal we expect the script to use, in canonical form. Keep this
// in lockstep with `FORBIDDEN_SIDECAR` in local_v2_withdraw_full.mjs.
//
// Substring-matching rather than fully anchored — the task M10-f Step f.3 test
// list includes `depositSender`, `secretSeed`, `dkUser`, `blindFactor`, and
// `nullifierHash`. An anchored `^...$` regex would let those through (they
// have extra characters beyond the bare token). To preserve the privacy
// guarantee against future authors who add a wrapper field, we substring-match
// each token, with two surgical refinements:
//   - `sender(?!s)`  — exempts the legitimate plural `distinctDepositSenders`
//                      (an anonymity-set aggregate, not a per-deposit leak).
//   - `\bdk`         — anchors `dk` to a word boundary so it only matches
//                      identifier-prefix occurrences (`dkUser`, `dkInverse`),
//                      not arbitrary `..dk..` substrings inside unrelated names.
const EXPECTED_FORBIDDEN_REGEX =
  /(amount|secret|nullifier|blind|\bdk|inverse|commitmentHex|leafIndex|merkle|Path|sender(?!s))/i;

test("M10-f: side-car write block declares schema withdraw_tree_context_v2", () => {
  // The schema string is the contract-level wire identifier consumers (the
  // final-report builder, future log scrapers) discriminate on. Bumping it to
  // v2 signals that v1-shaped files are stale and must not be trusted.
  assert.ok(
    SCRIPT_SRC.includes('schema: "withdraw_tree_context_v2"'),
    "side-car ctx must set schema: 'withdraw_tree_context_v2'",
  );
  assert.ok(
    !SCRIPT_SRC.includes('schema: "withdraw_tree_context_v1"'),
    "side-car ctx must NOT still set schema: 'withdraw_tree_context_v1'",
  );
});

test("M10-f: side-car ctx no longer assigns commitmentHex or leafIndex", () => {
  // The only places those two keys appeared in this script were:
  //   - the side-car ctx object (REMOVED)
  //   - the FORBIDDEN_SIDECAR regex (REQUIRED to remain)
  //   - the FORBIDDEN_DECRYPT_RESPONSE regex at line ~266 (REQUIRED to remain)
  //   - prose comments
  // Therefore there must be NO assignment line of the form
  //   `commitmentHex: <expr>` or `leafIndex: <expr>` anywhere in the file.
  const commitmentHexAssign = /\bcommitmentHex\s*:\s*[^,/]/;
  const leafIndexAssign = /\bleafIndex\s*:\s*[^,/]/;
  assert.ok(
    !commitmentHexAssign.test(SCRIPT_SRC),
    "side-car ctx must not contain a `commitmentHex: <expr>` assignment",
  );
  assert.ok(
    !leafIndexAssign.test(SCRIPT_SRC),
    "side-car ctx must not contain a `leafIndex: <expr>` assignment",
  );
});

test("M10-f: FORBIDDEN_SIDECAR regex covers new identifiers in the script source", () => {
  // The strengthened regex must literally appear in the script so we
  // (a) get the runtime hard-fail and (b) make future code review trivial.
  assert.ok(
    SCRIPT_SRC.includes("FORBIDDEN_SIDECAR"),
    "script must declare FORBIDDEN_SIDECAR",
  );
  assert.ok(
    SCRIPT_SRC.includes(
      "/(amount|secret|nullifier|blind|\\bdk|inverse|commitmentHex|leafIndex|merkle|Path|sender(?!s))/i",
    ),
    "FORBIDDEN_SIDECAR regex must match the M10-f-strengthened form",
  );
});

test("M10-f: side-car write block keeps process.exit(34) on forbidden field", () => {
  // The exit-34 branch is the only mechanism that prevents a future author
  // from accidentally re-introducing a linkability field. If this string
  // disappears, the regex is decorative.
  const sideCarBlock = SCRIPT_SRC.slice(
    SCRIPT_SRC.indexOf("Persist PUBLIC withdraw_tree_context side-car"),
    SCRIPT_SRC.indexOf("const proofOutPath ="),
  );
  assert.ok(
    sideCarBlock.includes("FORBIDDEN_SIDECAR.test(k)"),
    "side-car block must check every ctx key against FORBIDDEN_SIDECAR",
  );
  assert.ok(
    sideCarBlock.includes("process.exit(34)"),
    "side-car block must exit(34) on forbidden field",
  );
});

test("M10-f: forbidden-field regex rejects every known linkability key", () => {
  // Mirrors task M10-f Step f.3 's test case. Each key here is either the
  // exact field codex flagged, a syntactic variant we want to forbid
  // preemptively, or a deposit-witness field that must never leak.
  const mustReject = [
    "commitmentHex",
    "leafIndex",
    "merklePath",
    "merkle_path",
    "merklepath",
    "merkleSiblings",
    "merklesiblings",
    "MERKLEINDICES",
    "sender",
    "depositSender",
    "amount",
    "secretSeed",
    "dkUser",
    "blindFactor",
    "depositBlind",
    "nullifierHash",
    "inverseShare",
  ];
  for (const k of mustReject) {
    assert.ok(
      EXPECTED_FORBIDDEN_REGEX.test(k),
      `FORBIDDEN_SIDECAR must reject ${k}`,
    );
  }
});

test("M10-f: forbidden-field regex permits the legitimate side-car keys", () => {
  // Sanity test: the regex must NOT accidentally swallow the v2 schema's own
  // legitimate keys. If any of these starts matching, the strengthened regex
  // would brick the writer at runtime with exit(34).
  const mustAccept = [
    "schema",
    "requestId",
    "rootHex",
    "treeTranscriptHash",
    "anonymitySetSize",
    "distinctDepositSenders",
    "mode",
    "depositorWitnessSchemaVersion",
    "createdAtUnixMs",
  ];
  for (const k of mustAccept) {
    assert.ok(
      !EXPECTED_FORBIDDEN_REGEX.test(k),
      `FORBIDDEN_SIDECAR must NOT reject legitimate key ${k}`,
    );
  }
});

test("M10-f: injecting a forbidden key into ctx trips the exit-34 branch", () => {
  // Re-run the FORBIDDEN_SIDECAR check on a hypothetical malformed ctx to
  // prove the failure branch fires. We don't actually call process.exit
  // (that would tear down the test runner) — we assert that the regex
  // match returns true on the exact key the script would exit on, AND
  // confirm via source-read that the script's failure branch reaches
  // process.exit(34) and not a silent log-and-continue.
  const malformedCtx = {
    schema: "withdraw_tree_context_v2",
    requestId: "req-test",
    rootHex: "00".repeat(32),
    // Injected forbidden field: simulates a future author re-adding it.
    commitmentHex: "deadbeef".repeat(8),
  };
  let triggeredOn = null;
  for (const k of Object.keys(malformedCtx)) {
    if (EXPECTED_FORBIDDEN_REGEX.test(k)) {
      triggeredOn = k;
      break;
    }
  }
  assert.equal(
    triggeredOn,
    "commitmentHex",
    "FORBIDDEN_SIDECAR must trigger on commitmentHex",
  );

  // Cross-check the script source actually wires the failure to exit(34),
  // not a console.error-and-return.
  const guardSnippet = SCRIPT_SRC.slice(
    SCRIPT_SRC.indexOf("FORBIDDEN_SIDECAR.test(k)"),
    SCRIPT_SRC.indexOf("FORBIDDEN_SIDECAR.test(k)") + 300,
  );
  assert.match(
    guardSnippet,
    /process\.exit\(34\)/,
    "FORBIDDEN_SIDECAR match must lead to process.exit(34)",
  );
});

test("M10-f: side-car write block still emits the anonymity-set aggregate fields", () => {
  // Defensive — if a future refactor accidentally drops anonymitySetSize or
  // distinctDepositSenders the report builder loses the only legitimate
  // signal it has. These must remain in the ctx.
  const sideCarBlock = SCRIPT_SRC.slice(
    SCRIPT_SRC.indexOf("Persist PUBLIC withdraw_tree_context side-car"),
    SCRIPT_SRC.indexOf("const proofOutPath ="),
  );
  for (const required of [
    "anonymitySetSize",
    "distinctDepositSenders",
    "treeTranscriptHash",
    "rootHex",
    "requestId",
  ]) {
    assert.ok(
      sideCarBlock.includes(required),
      `side-car ctx must still emit ${required}`,
    );
  }
});

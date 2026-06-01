// LeanIMT JS helper self-consistency tests (node --test).
// Asserts buildLeanIMT / leanIMTPath / leanIMTRootFromPath agree — the same convention the
// circuit HardenedLeanIMTInclusion enforces (propagate on empty sibling, carry above depth).
import test from "node:test";
import assert from "node:assert/strict";
import {
  buildLeanIMT,
  leanIMTPath,
  leanIMTRootFromPath,
  LEANIMT_MAX_DEPTH,
} from "../leanimt.mjs";

const leavesOf = (n) => Array.from({ length: n }, (_, i) => BigInt(i + 1));

test("root-from-path equals tree root for every leaf (varied sizes incl. odd/propagate)", async () => {
  for (const n of [2, 3, 5, 8, 9, 13, 16, 17]) {
    const leaves = leavesOf(n);
    const { root, levels, depth } = await buildLeanIMT(leaves);
    assert.ok(depth >= 1, `depth>=1 for n=${n}`);
    for (let li = 0; li < n; li++) {
      const { siblings, actualDepth } = leanIMTPath(levels, li, LEANIMT_MAX_DEPTH);
      assert.equal(actualDepth, depth, `actualDepth==depth n=${n} li=${li}`);
      assert.equal(siblings.length, LEANIMT_MAX_DEPTH);
      // siblings above actualDepth must be 0 (the circuit hardening requires this)
      for (let i = actualDepth; i < LEANIMT_MAX_DEPTH; i++) {
        assert.equal(siblings[i], 0n, `sibling[${i}]==0 above depth n=${n} li=${li}`);
      }
      const r = await leanIMTRootFromPath(leaves[li], siblings, li, actualDepth);
      assert.equal(r, root, `root-from-path matches n=${n} li=${li}`);
    }
  }
});

test("leafIndex fits within actualDepth (high path bits are 0)", async () => {
  const leaves = leavesOf(8); // depth 3
  const { levels, depth } = await buildLeanIMT(leaves);
  for (let li = 0; li < 8; li++) {
    const { actualDepth } = leanIMTPath(levels, li, LEANIMT_MAX_DEPTH);
    assert.equal(actualDepth, 3);
    assert.ok(li < (1 << actualDepth), `leafIndex ${li} < 2^${actualDepth}`);
  }
});

test("a wrong sibling produces a different root (soundness sanity)", async () => {
  const leaves = leavesOf(8);
  const { root, levels } = await buildLeanIMT(leaves);
  const { siblings, actualDepth } = leanIMTPath(levels, 3, LEANIMT_MAX_DEPTH);
  const tampered = siblings.slice();
  tampered[0] = tampered[0] + 1n; // flip a real sibling
  const r = await leanIMTRootFromPath(leaves[3], tampered, 3, actualDepth);
  assert.notEqual(r, root, "tampered sibling must change the root");
});

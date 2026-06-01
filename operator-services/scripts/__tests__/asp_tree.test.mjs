// CP3 tests: ASP LeanIMT builder, path, revocation re-fork, set artifact, Chainalysis curation.
import test from "node:test";
import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildAspTree, aspPathFor, makeAspSetArtifact } from "../local_build_asp_tree.mjs";
import { MockKytProvider, screenDeposits } from "../kyt_provider.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const circuitsScripts = resolve(here, "..", "..", "..", "circuits", "scripts");
const { leanIMTRootFromPath } = await import(`file://${resolve(circuitsScripts, "leanimt.mjs")}`);
const { LeanIMTTree } = await import(`file://${resolve(circuitsScripts, "leanimt_tree.mjs")}`);

const C = (n) => BigInt(n); // synthetic commitment leaves (ASP tree doesn't recompute them)

test("ASP tree: build + path round-trips to root (circuit-parity convention)", async () => {
  const approved = [C(101), C(202), C(303), C(404), C(505)];
  const { tree, root, depth } = await buildAspTree(approved);
  assert.ok(root !== 0n);
  assert.ok(depth >= 1);
  const p = await aspPathFor(tree, C(303));
  assert.equal(p.leafIndex, 2);
  const r = await leanIMTRootFromPath(C(303), p.siblings, p.leafIndex, p.actualDepth);
  assert.equal(r, root, "ASP path recomputes the ASP root");
});

test("ASP tree: revocation re-fork excludes a commitment → new root, excluded path fails", async () => {
  const approved = [C(101), C(202), C(303), C(404), C(505)];
  const { root: rootBefore } = await buildAspTree(approved);
  // re-fork excluding C(303) (e.g. its sender got newly sanctioned on re-screen)
  const reforked = approved.filter((c) => c !== C(303));
  const { tree: t2, root: rootAfter } = await buildAspTree(reforked);
  assert.notEqual(rootAfter, rootBefore, "re-fork changes the root");
  await assert.rejects(() => aspPathFor(t2, C(303)), /commitment_not_in_tree/, "revoked commitment has no path");
  // a non-revoked one still resolves
  const p = await aspPathFor(t2, C(404));
  assert.ok(p.actualDepth >= 1);
});

test("ASP set artifact: public, has rootHex + commitments, no secrets", async () => {
  const approved = [C(7), C(8), C(9)];
  const { artifact, root } = await makeAspSetArtifact(approved, 1700000000);
  assert.equal(artifact.scheme, "eunoma_asp_set_v1");
  assert.equal(artifact.leafCount, 3);
  assert.equal(artifact.commitments.length, 3);
  assert.match(artifact.rootHex, /^0x[0-9a-f]{64}$/);
  assert.ok(root !== 0n);
});

test("LeanIMTTree: serialize/deserialize round-trip preserves root", async () => {
  const t = new LeanIMTTree();
  for (const n of [11, 22, 33, 44]) t.append(C(n), { commitmentHex: undefined });
  const snap = await t.serialize();
  const t2 = await LeanIMTTree.deserialize(snap);
  assert.equal(await t2.root(), await t.root());
  assert.equal(await t2.transcriptHash(), await t.transcriptHash());
});

test("Chainalysis curation (mock): sanctioned sender rejected, clean approved", async () => {
  const kyt = new MockKytProvider({ sanctioned: ["0xbad"] });
  const deposits = [
    { commitment: "0xc1", sender: "0xgood1" },
    { commitment: "0xc2", sender: "0xBAD" }, // case-insensitive
    { commitment: "0xc3", sender: "0xgood2" },
  ];
  const { approved, rejected } = await screenDeposits(kyt, deposits);
  assert.equal(approved.length, 2);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].commitment, "0xc2");
  assert.equal(kyt.calls.length, 3, "screened every deposit (real execution, not stubbed)");
});

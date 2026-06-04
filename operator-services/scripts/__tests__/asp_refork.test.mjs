// CP3 test: ASP re-fork epoch orchestrator (screen → approve → re-fork → revoke-on-rescreen).
import test from "node:test";
import assert from "node:assert/strict";
import { runAspReforkEpoch, aspRecordCliArgs } from "../local_asp_refork.mjs";
import { MockKytProvider } from "../kyt_provider.mjs";

const fakeIpfs = { publish: async () => ({ cid: "bafytestcid", source: "test-fake" }) };
const cm = (s) => "0x" + s.padStart(64, "0"); // realistic 32-byte commitment hex

test("epoch 1: clean approved, sanctioned rejected; root + cid produced", async () => {
  const kyt = new MockKytProvider({ sanctioned: ["0xbadb"] });
  const r = await runAspReforkEpoch({
    state: { approved: [] },
    newDeposits: [
      { commitment: cm("c1"), sender: "0xgoodA" },
      { commitment: cm("c2"), sender: "0xbadB" },
      { commitment: cm("c3"), sender: "0xgoodC" },
    ],
    opts: { kyt, ipfs: fakeIpfs, nowUnix: 1700000000 },
  });
  assert.equal(r.approved.length, 2);
  assert.equal(r.rejectedNew.length, 1);
  assert.equal(r.rejectedNew[0].commitment, cm("c2"));
  assert.match(r.rootHex, /^0x[0-9a-f]{64}$/);
  assert.equal(r.cid, "bafytestcid");
  assert.equal(r.artifact.commitments.length, 2);
});

test("epoch 2: re-screen revokes a previously-approved sender (newly sanctioned)", async () => {
  const kyt = new MockKytProvider({ sanctioned: [] });
  const e1 = await runAspReforkEpoch({
    state: { approved: [] },
    newDeposits: [
      { commitment: cm("c1"), sender: "0xgoodA" },
      { commitment: cm("c3"), sender: "0xgoodC" },
    ],
    opts: { kyt, ipfs: fakeIpfs, nowUnix: 1700000000 },
  });
  assert.equal(e1.approved.length, 2);
  const rootBefore = e1.rootHex;

  // goodC gets newly sanctioned → epoch 2 re-screen must revoke c3
  kyt.flag("0xgoodC");
  const e2 = await runAspReforkEpoch({
    state: { approved: e1.approved },
    newDeposits: [{ commitment: cm("c4"), sender: "0xgoodD" }],
    opts: { kyt, ipfs: fakeIpfs, nowUnix: 1700000100 },
  });
  assert.equal(e2.revoked.length, 1);
  assert.equal(e2.revoked[0].commitment, cm("c3"));
  assert.deepEqual(e2.approved.map((a) => a.commitment).sort(), [cm("c1"), cm("c4")].sort());
  assert.notEqual(e2.rootHex, rootBefore, "re-fork changed the root after revocation");
});

test("aspRecordCliArgs builds the delegate record call", () => {
  const args = aspRecordCliArgs({ bridgeAddr: "0xabc", rootHex: "0x" + "11".repeat(32), cid: "bafyabc" });
  assert.ok(args.includes("--function-id"));
  assert.ok(args.some((a) => a.includes("record_asp_root_via_delegate")));
  assert.ok(args.some((a) => a.startsWith("hex:0x")));
});

// ── OB5 KYT-seam invariant ────────────────────────────────────────────────────────────────────
// HARD INVARIANT: zero withdraw-side KYT. A partial-withdraw CHANGE note inherits its parent's ASP
// approval (the parent's withdraw proof already proved parent ∈ ASP) and must NEVER trigger a
// screenAddress call. This test attributes EVERY screenAddress call in a partial-withdraw+change-note
// epoch and asserts the change/withdraw paths contribute ZERO — only genuinely-NEW deposit senders
// are screened. If a future refactor leaks a screenAddress onto the change-note merge or a withdraw
// path, kyt.calls grows and this fails.
test("OB5: partial-withdraw+change-note epoch screens ONLY new deposit senders (change/withdraw = 0 KYT calls)", async () => {
  const kyt = new MockKytProvider({ sanctioned: [] });

  // Epoch 1 — fresh state (no re-screen): approve a parent deposit + one unrelated deposit. The ONLY
  // screenAddress calls here are the two NEW deposit senders.
  const parentCommitment = cm("p0");
  const parentLabel = cm("lab0"); // deposit-scoped stable label shared by parent + all descendants
  const e1 = await runAspReforkEpoch({
    state: { approved: [] },
    newDeposits: [
      { commitment: parentCommitment, sender: "0xdepA", label: parentLabel },
      { commitment: cm("u1"), sender: "0xdepB", label: cm("labU") },
    ],
    changeNotes: [],
    opts: { kyt, ipfs: fakeIpfs, nowUnix: 1700000000 },
  });
  assert.equal(e1.approved.length, 2);
  // Exactly the two new deposit senders were screened — nothing else.
  assert.deepEqual(kyt.calls.slice().sort(), ["0xdepa", "0xdepb"].sort(),
    "epoch 1 screened ONLY the new deposit senders");

  const callsAfterE1 = kyt.calls.length; // 2

  // Epoch 2 — the partial-withdraw epoch: ONE genuinely-new deposit + ONE change note inheriting the
  // parent's label. The change note carries NO sender and is merged by LABEL INHERITANCE.
  const changeNote = { commitment: cm("chg0"), label: parentLabel, parentCommitment };
  const e2 = await runAspReforkEpoch({
    state: { approved: e1.approved },          // carries 0xdepA + 0xdepB → both re-screened for revocation
    newDeposits: [{ commitment: cm("n2"), sender: "0xdepC", label: cm("labN") }], // 1 NEW deposit sender
    changeNotes: [changeNote],                 // inherited — must add ZERO screenAddress calls
    opts: { kyt, ipfs: fakeIpfs, nowUnix: 1700000100 },
  });

  // The change note entered the approved set (its parent label is live) …
  assert.ok(e2.approved.some((a) => a.commitment === changeNote.commitment),
    "change note merged by inheritance");
  assert.equal(e2.changeNotesRejected.length, 0, "change note not rejected (parent label is live)");
  // … the change note carries the parent's label (descendants share ONE label) and NO sender …
  const mergedChange = e2.approved.find((a) => a.commitment === changeNote.commitment);
  assert.equal(mergedChange.label.toLowerCase(), parentLabel.toLowerCase());
  assert.equal(mergedChange.sender, "", "change note has NO plaintext sender (never screened)");

  // ── THE INVARIANT ── attribute every NEW screenAddress call made during epoch 2.
  const e2Calls = kyt.calls.slice(callsAfterE1);
  // Re-screen of the two carried approved senders (revocation check) + the ONE new deposit sender.
  // The change note attributes ZERO calls — it is NOT screened.
  assert.deepEqual(e2Calls.slice().sort(), ["0xdepa", "0xdepb", "0xdepc"].sort(),
    "epoch 2 KYT calls = {re-screen approved senders} ∪ {new deposit sender}; change note adds 0");

  // The change note's parent commitment / label NEVER appears as a screened subject.
  assert.ok(!kyt.calls.includes(parentCommitment.toLowerCase()),
    "parent COMMITMENT was never screened (we screen SENDERS, not commitments)");
  assert.ok(!kyt.calls.includes(parentLabel.toLowerCase()),
    "the inherited LABEL was never screened");
  assert.ok(!kyt.calls.includes(changeNote.commitment.toLowerCase()),
    "the change-note COMMITMENT was never screened");

  // The published artifact pins the LABEL-set (OB6): labels present, parent + change share ONE label.
  assert.ok(Array.isArray(e2.labels) && e2.labels.includes(parentLabel.toLowerCase()),
    "LABEL-set artifact includes the deposit-scoped label");
  assert.equal(e2.labelByCommitment[changeNote.commitment.toLowerCase()], parentLabel.toLowerCase(),
    "change note maps to its parent's label in the pinned set");
});

// ── OB5 revocation propagates to descendants via the LABEL, still 0 change-note KYT ─────────────
test("OB5: revoking a parent sender drops its change-note descendant by LABEL (no change-note KYT call)", async () => {
  const kyt = new MockKytProvider({ sanctioned: [] });
  const parentLabel = cm("labX");
  const e1 = await runAspReforkEpoch({
    state: { approved: [] },
    newDeposits: [{ commitment: cm("px"), sender: "0xdepX", label: parentLabel }],
    changeNotes: [],
    opts: { kyt, ipfs: fakeIpfs, nowUnix: 1700000000 },
  });
  // change note minted from the parent enters in epoch 2
  const e2 = await runAspReforkEpoch({
    state: { approved: e1.approved },
    newDeposits: [],
    changeNotes: [{ commitment: cm("cx"), label: parentLabel, parentCommitment: cm("px") }],
    opts: { kyt, ipfs: fakeIpfs, nowUnix: 1700000100 },
  });
  assert.equal(e2.approved.length, 2, "parent + change present");

  const callsBeforeE3 = kyt.calls.length;
  // epoch 3: parent sender newly sanctioned → its LABEL is revoked → BOTH parent and change drop.
  kyt.flag("0xdepX");
  const e3 = await runAspReforkEpoch({
    state: { approved: e2.approved },
    newDeposits: [],
    changeNotes: [],
    opts: { kyt, ipfs: fakeIpfs, nowUnix: 1700000200 },
  });
  // parent + descendant change both gone (revocation by label, descendants die together).
  assert.equal(e3.approved.length, 0, "revoked label drops parent AND its change descendant");
  assert.ok(e3.revokedLabels.map((l) => l.toLowerCase()).includes(parentLabel.toLowerCase()));

  // epoch 3 screened only the carried SENDER (0xdepX, re-screen). The change note (no sender) added 0.
  const e3Calls = kyt.calls.slice(callsBeforeE3);
  assert.deepEqual(e3Calls, ["0xdepx"],
    "revocation epoch screened ONLY the carried deposit sender; the change descendant added 0 KYT calls");
});

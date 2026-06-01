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

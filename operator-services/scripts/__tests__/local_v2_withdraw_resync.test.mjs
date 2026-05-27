// operator-services/scripts/__tests__/local_v2_withdraw_resync.test.mjs
//
// M11 — unit tests for the orchestrator's vault-resync client helpers
// (scripts/_lib/vault_resync_client.mjs). Run with Node's built-in test runner (NOT vitest):
//
//     cd operator-services && node --test scripts/__tests__/local_v2_withdraw_resync.test.mjs
//
// These cover the NON-I/O logic: withdraw event parsing bound to the trusted package, the
// pre/post-increment sequence semantics, lagging-slot computation, and the public-hash-only
// resync body (no forbidden plaintext keys). The fetch/fs glue around them is exercised live by
// the testnet:e2e run; the worker (tests/vault_resync_v2.rs) and coordinator
// (tests/vault_resync_route.test.ts) cover the server side.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  parseWithdrawEventV2FromTx,
  pickInitializedMin,
  buildResyncBody,
  assertNoForbiddenResyncKeys,
  normAddr,
} from "../_lib/vault_resync_client.mjs";

const PKG = "0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1";

function withdrawTx(pkg, seq, success = true, eventName = "WithdrawEventV2") {
  return {
    success,
    vm_status: success ? "Executed successfully" : "ABORTED",
    events: [
      { type: "0x1::coin::WithdrawEvent", data: { amount: "5" } },
      {
        type: `${pkg}::eunoma_bridge::${eventName}`,
        data: {
          root: "0xaa",
          nullifier_hash: "0xbb",
          recipient: "0x554cd51d",
          recipient_hash: "0xcc",
          amount_tag: "0xdd",
          ca_payload_hash: "0xee",
          request_hash: "0xff",
          vault_sequence: seq,
        },
      },
    ],
  };
}

test("parseWithdrawEventV2FromTx extracts the binding and parses string vault_sequence", () => {
  const b = parseWithdrawEventV2FromTx(withdrawTx(PKG, "1"), PKG);
  assert.equal(b.eventVaultSequence, 1);
  assert.equal(b.root, "0xaa");
  assert.equal(b.nullifierHash, "0xbb");
  assert.equal(b.recipientHash, "0xcc");
  assert.equal(b.requestHash, "0xff");
  assert.equal(b.success, true);
});

test("parseWithdrawEventV2FromTx accepts a numeric vault_sequence", () => {
  assert.equal(parseWithdrawEventV2FromTx(withdrawTx(PKG, 2), PKG).eventVaultSequence, 2);
});

test("parseWithdrawEventV2FromTx accepts privacy-hardened WithdrawEventV3", () => {
  assert.equal(parseWithdrawEventV2FromTx(withdrawTx(PKG, "3", true, "WithdrawEventV3"), PKG).eventVaultSequence, 3);
});

test("parseWithdrawEventV2FromTx ignores a WithdrawEventV2 from a non-trusted package", () => {
  const tx = withdrawTx("0xdeadbeef", "1");
  assert.throws(() => parseWithdrawEventV2FromTx(tx, PKG), /not found/);
  // ...but matches when searched with the actual emitting package.
  assert.equal(parseWithdrawEventV2FromTx(tx, "0xdeadbeef").eventVaultSequence, 1);
});

test("parseWithdrawEventV2FromTx surfaces a failed tx + throws on missing event", () => {
  assert.equal(parseWithdrawEventV2FromTx(withdrawTx(PKG, "1", false), PKG).success, false);
  assert.throws(
    () => parseWithdrawEventV2FromTx({ success: true, events: [{ type: "0x1::coin::W", data: {} }] }, PKG),
    /not found/,
  );
});

test("normAddr left-pads + lowercases; address-equivalence under 0x/casing", () => {
  assert.equal(normAddr("0xA"), "a".padStart(64, "0"));
  assert.equal(normAddr("0xA08850B1CA22CC5AA3A3A3FB1179CF3F1F169312CEA8038FF1B1E3B4ACE79EC1"), normAddr(PKG));
});

test("pickInitializedMin computes the lagging min over initialized slots only", () => {
  const { initializedSlots, workerMin } = pickInitializedMin({ 0: 1, 1: 1, 2: 2, 5: null, 6: null });
  assert.deepEqual(initializedSlots, [0, 1, 2]);
  assert.equal(workerMin, 1);
});

test("pickInitializedMin returns null min when no slot is initialized", () => {
  const { initializedSlots, workerMin } = pickInitializedMin({ 5: null, 6: null });
  assert.deepEqual(initializedSlots, []);
  assert.equal(workerMin, null);
});

test("buildResyncBody emits camelCase public-hash body with expectedNextSequence = event + 1", () => {
  const binding = parseWithdrawEventV2FromTx(withdrawTx(PKG, "1"), PKG);
  const body = buildResyncBody({
    dkgEpoch: "1",
    requestId: "rid",
    txHash: "0x7e77",
    bridgePackage: PKG,
    vault: "0x554c",
    assetType: "0xa",
    binding,
    trigger: "before_round1",
  });
  assert.equal(body.eventVaultSequence, 1);
  assert.equal(body.expectedNextSequence, 2);
  assert.equal(body.nullifierHash, "bb"); // 0x-stripped, lowercase
  assert.equal(body.trigger, "before_round1");
  // The body must carry NO forbidden plaintext keys (build asserts this internally too).
  assert.doesNotThrow(() => assertNoForbiddenResyncKeys(body));
});

test("assertNoForbiddenResyncKeys rejects a bare `nullifier` key but allows nullifierHash", () => {
  assert.throws(() => assertNoForbiddenResyncKeys({ nullifier: "x" }), /forbidden_field/);
  assert.throws(() => assertNoForbiddenResyncKeys({ amount: 1 }), /forbidden_field/);
  assert.throws(() => assertNoForbiddenResyncKeys({ meta: { leafIndex: 3 } }), /forbidden_field/);
  assert.doesNotThrow(() =>
    assertNoForbiddenResyncKeys({ nullifierHash: "x", recipientHash: "y", requestHash: "z" }),
  );
});

// operator-services/scripts/__tests__/sigma_position_17_parity.test.mjs
//
// Plan task M10-a — empirically confirm the M9 balance-witness diagnosis.
//
// Run with Node's built-in test runner (NOT vitest):
//
//     cd operator-services && node --test scripts/__tests__/sigma_position_17_parity.test.mjs
//
// What this test proves:
//   1. The σ-position-17 balance-equation identity verifies when the prover
//      supplies a TRUTHFUL `newAmountChunks = balance_chunks - transfer_chunks`
//      (with borrow propagation), for synthetic chain states representing 1,
//      2, and 8 cumulative deposits.
//   2. The same identity FAILS at position 17 (and only at position 17 in the
//      regression check) when the orchestrator hardcodes `newBalanceChunks =
//      [0, 0, ..., 0]` for an 8-deposit chain state — replicating the M9
//      hard-stop. This refutes the M9 fake-dk cross-term diagnosis and pins
//      the bug on the witness vector.
//
// Reference sources mirrored:
//   * Rust verifier:     operator-services/crypto-worker-rust/src/transfer_sigma_reference.rs
//                        (psi_transfer @363, f_transfer @448)
//   * SDK statement:     operator-services/node_modules/@aptos-labs/
//                        confidential-asset/src/crypto/sigmaProtocolTransfer.ts
//                        (makeTransferPsi @311, makeTransferF @405)
//   * SDK Fiat-Shamir:   operator-services/node_modules/@aptos-labs/
//                        confidential-asset/src/crypto/sigmaProtocol.ts @171

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import {
  proveTransfer,
  TwistedEd25519PrivateKey,
  TwistedElGamal,
  ChunkedAmount,
  AVAILABLE_BALANCE_CHUNK_COUNT as ELL,
  TRANSFER_AMOUNT_CHUNK_COUNT as N,
} from "@aptos-labs/confidential-asset";
import { ed25519 } from "@noble/curves/ed25519";

import { runReferenceVerifier } from "../sigma_reference_verifier.mjs";
import { chunkSubtract, padToEll } from "../_lib/chunk_arithmetic.mjs";

const ED_N = ed25519.CURVE.n;

// Generate a random nonzero scalar mod ℓ. Matches `randScalar()` in
// local_v2_withdraw_full.mjs:99-106.
function randScalar() {
  while (true) {
    const buf = randomBytes(32);
    buf[31] &= 0x7f; // clear the high bit so the value fits below 2^255
    let v = 0n;
    for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(buf[i]);
    if (v < ED_N && v !== 0n) return v;
  }
}

function encryptChunks(chunks, pk, randomness) {
  return chunks.map((c, i) => TwistedElGamal.encryptWithPK(c, pk, randomness[i]));
}

const CHAIN_ID = 2; // Aptos testnet chain id (matches existing diagnostic scripts)

/**
 * Drive the SDK prover with a TRUTHFUL or OVERRIDDEN newBalanceChunks vector
 * and run the reference verifier. Returns the per-position fail mask plus
 * derived debug values.
 *
 * Truthful path: newBalanceChunks = balance_chunks - pad(transferChunks, ell)
 * Override path: caller passes `newBalanceChunksOverride` (e.g., zero vector
 *                to replicate the M9 hardcoded-zero bug).
 */
async function runParity({ totalOctas, transferOctas, newBalanceChunksOverride = null }) {
  // ---- fresh sender/recipient keypairs --------------------------------------
  const dkSender = TwistedEd25519PrivateKey.generate();
  const dkRecipient = TwistedEd25519PrivateKey.generate();
  const ekSender = dkSender.publicKey();
  const ekRecipient = dkRecipient.publicKey();

  // ---- synthetic chain state: oldBalance ciphertexts at `totalOctas` --------
  const balanceChunks = ChunkedAmount.fromAmount(totalOctas).amountChunks;
  assert.equal(balanceChunks.length, ELL, "ChunkedAmount.fromAmount returned wrong chunk count");

  const oldBalanceRandomness = Array.from({ length: ELL }, () => randScalar());
  const oldBalanceCt = encryptChunks(balanceChunks, ekSender, oldBalanceRandomness);

  // ---- transfer amount ciphertexts ------------------------------------------
  const transferChunks = ChunkedAmount.createTransferAmount(transferOctas).amountChunks;
  assert.equal(transferChunks.length, N, "ChunkedAmount.createTransferAmount returned wrong chunk count");

  const transferRandomness = Array.from({ length: N }, () => randScalar());
  // Per the SDK semantics, the SAME randomness is reused so the recipient's D
  // (= r · ek_rid) carries the same scalar r as the sender's. See
  // proveTransfer in sigmaProtocolTransfer.ts:217-218 and the consumer
  // pattern in local_v2_withdraw_full.mjs:236-237.
  const transferSenderCt = encryptChunks(transferChunks, ekSender, transferRandomness);
  const transferRecipientCt = encryptChunks(transferChunks, ekRecipient, transferRandomness);

  // ---- newBalance chunks: truthful by default, override if caller asks ------
  const truthfulNewBalanceChunks = chunkSubtract(balanceChunks, padToEll(transferChunks, ELL));
  const newBalanceChunks = newBalanceChunksOverride ?? truthfulNewBalanceChunks;
  if (newBalanceChunks.length !== ELL) {
    throw new Error(`newBalanceChunks length ${newBalanceChunks.length} != ELL=${ELL}`);
  }

  const newBalanceRandomness = Array.from({ length: ELL }, () => randScalar());
  const newBalanceCt = encryptChunks(newBalanceChunks, ekSender, newBalanceRandomness);

  // ---- produce the σ-proof via SDK proveTransfer ----------------------------
  const senderAddress = new Uint8Array(32);
  const recipientAddress = new Uint8Array(32);
  const tokenAddress = new Uint8Array(32);
  const proof = proveTransfer({
    dk: dkSender,
    senderAddress,
    recipientAddress,
    tokenAddress,
    chainId: CHAIN_ID,
    senderEncryptionKey: ekSender,
    recipientEncryptionKey: ekRecipient,
    oldBalanceC: oldBalanceCt.map((x) => x.C),
    oldBalanceD: oldBalanceCt.map((x) => x.D),
    newBalanceC: newBalanceCt.map((x) => x.C),
    newBalanceD: newBalanceCt.map((x) => x.D),
    newAmountChunks: newBalanceChunks,
    newRandomness: newBalanceRandomness,
    transferAmountC: transferSenderCt.map((x) => x.C),
    transferAmountDSender: transferSenderCt.map((x) => x.D),
    transferAmountDRecipient: transferRecipientCt.map((x) => x.D),
    transferAmountChunks: transferChunks,
    transferRandomness,
    hasEffectiveAuditor: false,
  });

  // ---- run the reference verifier ------------------------------------------
  const result = runReferenceVerifier({
    proof,
    oldBalanceCt,
    newBalanceCt,
    transferSenderCt,
    transferRecipientCt,
    ekSender,
    ekRecipient,
    chainId: CHAIN_ID,
    senderAddress,
    recipientAddress,
    tokenAddress,
  });

  return {
    ...result,
    debug: {
      balanceChunks,
      transferChunks,
      newBalanceChunks,
      truthfulNewBalanceChunks,
    },
  };
}

// =============================================================================
// Happy-path: position 17 verifies AND every other position verifies.
// =============================================================================

test("position 17 verifies for deposit_count=1 (M8 case) with correct new_a", async () => {
  const result = await runParity({ totalOctas: 100n, transferOctas: 100n });
  assert.equal(
    result.failsByPosition[17], 0,
    `position 17 must verify; failsByPosition=${JSON.stringify(result.failsByPosition)}`,
  );
  assert.equal(
    result.allPass, true,
    `all 30 positions must verify; failsByPosition=${JSON.stringify(result.failsByPosition)}`,
  );
});

test("position 17 verifies for deposit_count=2 with correct new_a", async () => {
  // Synthetic 2-deposit aggregate: 150 + 100 = 250.
  const result = await runParity({ totalOctas: 250n, transferOctas: 100n });
  assert.equal(
    result.failsByPosition[17], 0,
    `position 17 must verify; failsByPosition=${JSON.stringify(result.failsByPosition)}`,
  );
  assert.equal(
    result.allPass, true,
    `all 30 positions must verify; failsByPosition=${JSON.stringify(result.failsByPosition)}`,
  );
});

test("position 17 verifies for deposit_count=8 with correct new_a", async () => {
  // Aggregate from 8 deposits of 100..107 octas: 100+101+...+107 = 828.
  const total = 100n + 101n + 102n + 103n + 104n + 105n + 106n + 107n;
  assert.equal(total, 828n, "sanity: 8-deposit cumulative");
  const result = await runParity({ totalOctas: total, transferOctas: 100n });
  assert.equal(
    result.failsByPosition[17], 0,
    `position 17 must verify; failsByPosition=${JSON.stringify(result.failsByPosition)}`,
  );
  assert.equal(
    result.allPass, true,
    `all 30 positions must verify; failsByPosition=${JSON.stringify(result.failsByPosition)}`,
  );
});

// =============================================================================
// Regression guard — M9 hardcoded-zero newBalanceChunks must fail position 17.
// If this test fails (i.e., position 17 verifies despite new_a=0 at 8 deposits),
// the M10 balance-witness diagnosis is REFUTED and the plan must re-baseline.
// =============================================================================

test("REGRESSION GUARD: M9-style new_a=0 with deposit_count=8 FAILS at position 17", async () => {
  const result = await runParity({
    totalOctas: 828n,
    transferOctas: 100n,
    newBalanceChunksOverride: new Array(ELL).fill(0n),
  });
  assert.equal(
    result.failsByPosition[17], 1,
    `M9 hardcoded-zero case must fail position 17; failsByPosition=${JSON.stringify(result.failsByPosition)}`,
  );
});

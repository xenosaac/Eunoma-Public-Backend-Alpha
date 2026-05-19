// operator-services/scripts/gen_sigma_position_17_rust_fixtures.mjs
//
// Plan task M10-g, Step g.1 — fixture generator for the rust reference verifier
// parity test. Mirrors the M10-a JS parity test
// (scripts/__tests__/sigma_position_17_parity.test.mjs) but writes the
// generated σ-proofs + statement bytes + JS reference verifier's per-position
// fail mask to JSON files under
// operator-services/crypto-worker-rust/tests/fixtures/sigma_17/ for the rust
// integration test to consume.
//
// Determinism contract:
//   The script installs a SHA-256 counter-mode PRNG over
//   `globalThis.crypto.getRandomValues` BEFORE the SDK imports execute (same
//   hook pattern as deop-protocol/tests/aptos_ca_transfer_parity.test.ts).
//   Each fixture seeds the PRNG with a distinct, hard-coded string so the four
//   fixtures are independent but each is byte-stable across runs.
//
// Cross-references:
//   * M10-a JS parity test:    operator-services/scripts/__tests__/
//                              sigma_position_17_parity.test.mjs
//   * JS reference verifier:   operator-services/scripts/sigma_reference_verifier.mjs
//   * Rust reference verifier: operator-services/crypto-worker-rust/src/
//                              transfer_sigma_reference.rs
//
// Run:
//   cd operator-services && node scripts/gen_sigma_position_17_rust_fixtures.mjs
//
// Output (4 files):
//   operator-services/crypto-worker-rust/tests/fixtures/sigma_17/
//     1_deposit_happy_path.json
//     2_deposit_happy_path.json
//     8_deposit_happy_path.json
//     8_deposit_zero_new_a_regression.json

import { writeFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha256";

// =============================================================================
// Deterministic PRNG — installed BEFORE the SDK imports so all SDK randomness
// (noble randomBytes for σ-protocol α and ElGamal blinding, WASM-init for the
// bulletproofs RNG) is drawn from a stable counter-mode SHA-256 stream.
// =============================================================================

let prngSeedBytes = new Uint8Array(0);
const prngBlocks = [];
let prngConsumed = 0;

function setPrngSeed(seedStr) {
  prngSeedBytes = new TextEncoder().encode(seedStr);
  prngBlocks.length = 0;
  prngConsumed = 0;
}

function ensurePrngBlock(idx) {
  while (prngBlocks.length <= idx) {
    const counter = new Uint8Array(8);
    new DataView(counter.buffer).setBigUint64(0, BigInt(prngBlocks.length), false);
    const combined = new Uint8Array(prngSeedBytes.length + counter.length);
    combined.set(prngSeedBytes, 0);
    combined.set(counter, prngSeedBytes.length);
    prngBlocks.push(sha256(combined));
  }
}

function prngFill(buf) {
  for (let i = 0; i < buf.length; i++) {
    const blockIdx = Math.floor(prngConsumed / 32);
    const inBlock = prngConsumed % 32;
    ensurePrngBlock(blockIdx);
    buf[i] = prngBlocks[blockIdx][inBlock];
    prngConsumed += 1;
  }
  return buf;
}

Object.defineProperty(globalThis.crypto, "getRandomValues", {
  value: function deterministicGetRandomValues(buf) {
    return prngFill(buf);
  },
  writable: true,
  configurable: true,
});

// =============================================================================
// SDK imports (must follow PRNG install)
// =============================================================================

const {
  proveTransfer,
  TwistedEd25519PrivateKey,
  TwistedElGamal,
  ChunkedAmount,
  AVAILABLE_BALANCE_CHUNK_COUNT: ELL,
  TRANSFER_AMOUNT_CHUNK_COUNT: N,
} = await import("@aptos-labs/confidential-asset");

const { runReferenceVerifier } = await import("./sigma_reference_verifier.mjs");
const { chunkSubtract, padToEll } = await import("./_lib/chunk_arithmetic.mjs");

// =============================================================================
// Helpers
// =============================================================================

const CHAIN_ID = 2; // Aptos testnet — same constant the M10-a test uses.

function hexEncode(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function encryptChunks(chunks, pk, randomness) {
  return chunks.map((c, i) => TwistedElGamal.encryptWithPK(c, pk, randomness[i]));
}

// =============================================================================
// Fixture builder
//
// Generates one fixture by:
//   1. seeding the PRNG with `seedStr` so the whole computation is byte-stable;
//   2. allocating sender/recipient keypairs via the SDK (which pulls from the
//      seeded PRNG);
//   3. encrypting synthetic oldBalance / newBalance / transfer ciphertexts with
//      explicit randomness drawn from the same PRNG;
//   4. calling SDK `proveTransfer({...})` to produce the σ-proof;
//   5. running the JS reference verifier (`runReferenceVerifier`) to capture
//      the ground-truth `failsByPosition` vector that the rust test will
//      cross-check against.
//
// Returns a plain JSON-serialisable object (no Uint8Arrays — all bytes are
// 64-char hex strings) so the rust side can parse via serde + hex-decode.
// =============================================================================

async function buildFixture({
  name,
  seedStr,
  totalOctas,
  transferOctas,
  newBalanceChunksOverride = null,
  description,
}) {
  setPrngSeed(seedStr);

  // ---- keypairs (consume from PRNG; deterministic given seedStr) ------------
  const dkSender = TwistedEd25519PrivateKey.generate();
  const dkRecipient = TwistedEd25519PrivateKey.generate();
  const ekSender = dkSender.publicKey();
  const ekRecipient = dkRecipient.publicKey();

  // ---- chain state: oldBalance encrypts `totalOctas` ------------------------
  const balanceChunks = ChunkedAmount.fromAmount(totalOctas).amountChunks;
  if (balanceChunks.length !== ELL) {
    throw new Error(`balanceChunks length ${balanceChunks.length} != ELL=${ELL}`);
  }
  const oldBalanceRandomness = Array.from({ length: ELL }, () => randScalar());
  const oldBalanceCt = encryptChunks(balanceChunks, ekSender, oldBalanceRandomness);

  // ---- transfer ciphertexts -------------------------------------------------
  const transferChunks = ChunkedAmount.createTransferAmount(transferOctas).amountChunks;
  if (transferChunks.length !== N) {
    throw new Error(`transferChunks length ${transferChunks.length} != N=${N}`);
  }
  const transferRandomness = Array.from({ length: N }, () => randScalar());
  const transferSenderCt = encryptChunks(transferChunks, ekSender, transferRandomness);
  const transferRecipientCt = encryptChunks(transferChunks, ekRecipient, transferRandomness);

  // ---- new-balance chunks: truthful by default, override on demand ----------
  const truthfulNewBalanceChunks = chunkSubtract(balanceChunks, padToEll(transferChunks, ELL));
  const newBalanceChunks = newBalanceChunksOverride ?? truthfulNewBalanceChunks;
  if (newBalanceChunks.length !== ELL) {
    throw new Error(`newBalanceChunks length ${newBalanceChunks.length} != ELL=${ELL}`);
  }
  const newBalanceRandomness = Array.from({ length: ELL }, () => randScalar());
  const newBalanceCt = encryptChunks(newBalanceChunks, ekSender, newBalanceRandomness);

  // ---- σ-proof via SDK -------------------------------------------------------
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

  // ---- ground-truth: JS reference verifier per-position fail mask -----------
  const refResult = runReferenceVerifier({
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

  // ---- fixture object (JSON-friendly: every byte buffer → hex string) -------
  return {
    meta: {
      name,
      description,
      seedStr,
      totalOctas: totalOctas.toString(),
      transferOctas: transferOctas.toString(),
      ell: ELL,
      n: N,
      chainId: CHAIN_ID,
      hasEffectiveAuditor: false,
      numVolunAuditors: 0,
      generatedAt: new Date().toISOString(),
      jsReferenceVerifier: {
        allPass: refResult.allPass,
        failsByPosition: refResult.failsByPosition,
        challengeHex: refResult.challengeHex,
      },
    },
    statement: {
      senderAddressHex: hexEncode(senderAddress),
      recipientAddressHex: hexEncode(recipientAddress),
      tokenAddressHex: hexEncode(tokenAddress),
      senderEkHex: hexEncode(ekSender.toUint8Array()),
      recipientEkHex: hexEncode(ekRecipient.toUint8Array()),
      oldBalanceC: oldBalanceCt.map((x) => hexEncode(x.C.toRawBytes())),
      oldBalanceD: oldBalanceCt.map((x) => hexEncode(x.D.toRawBytes())),
      newBalanceC: newBalanceCt.map((x) => hexEncode(x.C.toRawBytes())),
      newBalanceD: newBalanceCt.map((x) => hexEncode(x.D.toRawBytes())),
      transferAmountC: transferSenderCt.map((x) => hexEncode(x.C.toRawBytes())),
      transferAmountDSender: transferSenderCt.map((x) => hexEncode(x.D.toRawBytes())),
      transferAmountDRecipient: transferRecipientCt.map((x) => hexEncode(x.D.toRawBytes())),
    },
    sigmaProof: {
      commitment: proof.commitment.map((b) => hexEncode(b)),
      response: proof.response.map((b) => hexEncode(b)),
    },
    debug: {
      balanceChunks: balanceChunks.map((b) => b.toString()),
      transferChunks: transferChunks.map((b) => b.toString()),
      newBalanceChunks: newBalanceChunks.map((b) => b.toString()),
      truthfulNewBalanceChunks: truthfulNewBalanceChunks.map((b) => b.toString()),
      overrideApplied: newBalanceChunksOverride !== null,
    },
  };
}

// =============================================================================
// Scalar generation — pulls from the seeded PRNG so it's deterministic.
// Mirrors the `randScalar()` in scripts/__tests__/sigma_position_17_parity.test.mjs
// but draws bytes via the installed `getRandomValues` hook (which routes
// through the SHA-256-counter PRNG).
// =============================================================================

function randScalar() {
  const ED_N = (() => {
    // ed25519 group order ℓ (LE / decimal — same constant `@noble/curves`
    // exposes via ed25519.CURVE.n; hard-coded so this helper has no SDK
    // dependency before the SDK loads).
    return 2n ** 252n + 27742317777372353535851937790883648493n;
  })();
  while (true) {
    const buf = new Uint8Array(32);
    globalThis.crypto.getRandomValues(buf);
    buf[31] &= 0x7f;
    let v = 0n;
    for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(buf[i]);
    if (v < ED_N && v !== 0n) return v;
  }
}

// =============================================================================
// Main — produce 4 fixtures and write them under
// operator-services/crypto-worker-rust/tests/fixtures/sigma_17/
// =============================================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURE_DIR = resolve(
  __dirname,
  "../crypto-worker-rust/tests/fixtures/sigma_17",
);

mkdirSync(FIXTURE_DIR, { recursive: true });

const SPEC = [
  {
    name: "1_deposit_happy_path",
    seedStr: "EUNOMA_M10G_SIGMA_POS17_1_DEPOSIT_HAPPY_v1",
    totalOctas: 100n,
    transferOctas: 100n,
    description:
      "M10-g g.4: 1-deposit baseline (M8 case). Truthful new_a = balance - transfer. " +
      "All 30 positions must verify rust-side and JS-side.",
  },
  {
    name: "2_deposit_happy_path",
    seedStr: "EUNOMA_M10G_SIGMA_POS17_2_DEPOSIT_HAPPY_v1",
    totalOctas: 250n,
    transferOctas: 100n,
    description:
      "M10-g g.3: 2-deposit aggregate (150+100=250). Truthful new_a. " +
      "All 30 positions must verify.",
  },
  {
    name: "8_deposit_happy_path",
    seedStr: "EUNOMA_M10G_SIGMA_POS17_8_DEPOSIT_HAPPY_v1",
    totalOctas: 100n + 101n + 102n + 103n + 104n + 105n + 106n + 107n,
    transferOctas: 100n,
    description:
      "M10-g g.1: 8-deposit aggregate (100+101+...+107=828). Truthful new_a. " +
      "All 30 positions must verify — confirms σ position-17 verifies for " +
      "multi-deposit chain state when the witness is truthful.",
  },
  {
    name: "8_deposit_zero_new_a_regression",
    seedStr: "EUNOMA_M10G_SIGMA_POS17_8_DEPOSIT_ZERO_NEWA_v1",
    totalOctas: 828n,
    transferOctas: 100n,
    newBalanceChunksOverrideZero: true,
    description:
      "M10-g g.2: REGRESSION GUARD. Same 828-octa 8-deposit chain state and " +
      "100-octa transfer but new_a is HARD-CODED to [0; ELL] (replicating the " +
      "M9 bug). σ position-17 MUST fail (witness new_a=0 mismatches statement " +
      "old_P which encrypts the truthful 828 octas). All other positions " +
      "verify because dk, transfer randomness, and new_r/new_balance_C are " +
      "internally consistent (the ciphertexts encode the same zero new_a the " +
      "prover commits to; only the balance-equation cross-term at pos 17 breaks).",
  },
];

const fixtureSummaries = [];
let total = 0;
for (const spec of SPEC) {
  const override = spec.newBalanceChunksOverrideZero
    ? new Array(ELL).fill(0n)
    : null;
  const fix = await buildFixture({
    name: spec.name,
    seedStr: spec.seedStr,
    totalOctas: spec.totalOctas,
    transferOctas: spec.transferOctas,
    newBalanceChunksOverride: override,
    description: spec.description,
  });

  const path = resolve(FIXTURE_DIR, `${spec.name}.json`);

  // If a previously committed fixture exists, assert byte-identical regeneration
  // (proves determinism contract holds). To rotate intentionally, set
  // EUNOMA_REGENERATE_FIXTURES=1.
  const newJson = JSON.stringify(fix, null, 2) + "\n";
  if (existsSync(path) && process.env.EUNOMA_REGENERATE_FIXTURES !== "1") {
    const onDisk = readFileSync(path, "utf8");
    // Strip the timestamp from BOTH before comparing (it's the only volatile
    // field by design — re-running shouldn't fail just because clock ticked).
    const stripTimestamp = (s) =>
      s.replace(/"generatedAt": "[^"]+"/, '"generatedAt": "<elided>"');
    if (stripTimestamp(onDisk) !== stripTimestamp(newJson)) {
      throw new Error(
        `M10-g fixture drift at ${path}: regenerated bytes differ from committed bytes.\n` +
          `If you intentionally rotated the seed or SDK pinned version, set ` +
          `EUNOMA_REGENERATE_FIXTURES=1 and re-run, then re-commit.`,
      );
    }
    console.log(`[ok] ${spec.name} — committed fixture matches regenerated bytes`);
  } else {
    writeFileSync(path, newJson);
    console.log(`[write] ${path}`);
  }

  fixtureSummaries.push({
    name: spec.name,
    allPass: fix.meta.jsReferenceVerifier.allPass,
    failsByPosition: fix.meta.jsReferenceVerifier.failsByPosition,
  });
  total++;
}

console.log(`\nGenerated ${total} fixtures:`);
for (const s of fixtureSummaries) {
  const failedPositions = s.failsByPosition
    .map((v, i) => (v ? i : -1))
    .filter((i) => i >= 0);
  console.log(
    `  - ${s.name}: allPass=${s.allPass}, failedPositions=[${failedPositions.join(",")}]`,
  );
}

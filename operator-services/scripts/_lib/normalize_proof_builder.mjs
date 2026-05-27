// operator-services/scripts/_lib/normalize_proof_builder.mjs
//
// Build a complete `normalize_raw` proof bundle for an Eunoma vault, using the
// fake-witness + threshold-s[0]-substitute trick that local_v2_withdraw_full.mjs
// already uses for the TRANSFER protocol (see lines 607-704 in that file) —
// but with a CRITICAL TWIST for the WITHDRAWAL/NORMALIZATION protocol.
//
// Why this exists: the Aptos CA framework's `normalize_raw` entry requires a
// σ-protocol proof whose witness includes the vault dk. But the Eunoma vault
// dk is NEVER reconstructed in any single place — it lives only as 5-of-7
// Shamir shares across the worker quorum.
//
// =============================================================================
// WITHDRAWAL ≠ TRANSFER on fake-dk semantics — critical divergence
// =============================================================================
//
// For the TRANSFER protocol the SDK's `proveTransfer` accepts a SEPARATE
// `senderEncryptionKey` argument:
//
//   proveTransfer({ dk: dk_user_fake, senderEncryptionKey: ek_vault_real, ... })
//
// So we can pass a fake witness dk WHILE the statement still embeds the real
// vault ek — the Fiat-Shamir transcript hashes ek_vault_real, and after
// substitution `s0_threshold = α[0] + e · dk_REAL` is what the chain σ-verifier
// expects (because ψ[0] = ek_real · sigma_0 == A_0 + e · H, which holds iff
// sigma_0 was computed against dk_REAL).
//
// For the WITHDRAWAL / NORMALIZE protocol the SDK's `proveWithdrawal` derives
// ek IMPLICITLY from the input dk (sigmaProtocolWithdraw.ts:284:
//   `const ekBytes = dk.publicKey().toUint8Array();`).
// So calling proveWithdrawal({dk: dk_user_fake, ...}) forces ek_user_fake into
// the statement → the Fiat-Shamir e_fake derived from that transcript is
// DIFFERENT from the e_chain the chain verifier would compute with ek_real,
// and the substitution `s0_threshold = α[0] + e_chain · dk_REAL` does NOT
// satisfy ψ[0] = ek_real · sigma_0 == A_0 + e_chain · H.
//
// **Solution**: bypass `proveWithdrawal` entirely. Call `sigmaProtocolProve`
// directly with a hand-built statement that embeds ek_REAL, and supply a fake
// witness vector `[dk_user_fake, new_a[ell], new_r[ell]]`. The SDK's generic
// prover will:
//   1. Compute the Fiat-Shamir challenge `e` from the (real-ek-embedded)
//      transcript — this is the SAME e the chain verifier will compute.
//   2. Produce response[0] = α[0] + e · dk_user_fake (mod ℓ).
// We extract α[0] = response[0] - e · dk_user_fake (mod ℓ) and ship it to the
// coordinator; the workers add e · dk_REAL_share_i in the exponent (Shamir),
// the coordinator Lagrange-aggregates to `s0_threshold = α[0] + e · dk_REAL`,
// and that replaces our fake response[0] before chain submission.
//
// At chain verify time:
//   ψ(σ)[0] = ek_real · sigma_0_final
//           = ek_real · (α[0] + e · dk_REAL)
//           = ek_real · α[0] + e · (ek_real · dk_REAL)
//           = A[0] + e · H                              (Twisted Ed25519: ek · dk = H)
// matches f[0] = H. ✓ No party ever sees dk_REAL standalone.
//
// References:
//   * Existing TRANSFER trick (template):
//       operator-services/scripts/local_v2_withdraw_full.mjs:546-704
//   * SDK normalize/withdraw prover (reference for what `normalize_raw` wants):
//       node_modules/@aptos-labs/confidential-asset/src/crypto/sigmaProtocolWithdraw.ts
//       node_modules/@aptos-labs/confidential-asset/src/crypto/confidentialNormalization.ts
//   * SDK generic σ-prover (used directly here, bypassing the dk→ek
//     derivation in proveWithdrawal):
//       node_modules/@aptos-labs/confidential-asset/src/crypto/sigmaProtocol.ts:257
//   * Twisted Ed25519 ek-derivation: `ek = H · dk⁻¹` so `ek · dk = H`:
//       node_modules/@aptos-labs/confidential-asset/src/crypto/twistedEd25519.ts:215-220
//   * JS reference verifier (mirror of the Move verifier; we reuse its
//     `psiWithdraw` as the homomorphism for the SDK prover):
//       operator-services/scripts/_lib/withdraw_sigma_reference.mjs

import {
  RistrettoPoint,
  H_RISTRETTO,
  TwistedEd25519PrivateKey,
  TwistedElGamal,
  bcsSerializeWithdrawSession,
  sigmaProtocolProve,
  sigmaProtocolFiatShamir,
  APTOS_FRAMEWORK_ADDRESS,
} from "@aptos-labs/confidential-asset";
import { batchRangeProof } from "@aptos-labs/confidential-asset-bindings";
import { ed25519 } from "@noble/curves/ed25519";
import { numberToBytesLE, bytesToNumberLE } from "@noble/curves/abstract/utils";
import { mod } from "@noble/curves/abstract/modular";
import { utf8ToBytes } from "@noble/hashes/utils";
import { randomBytes } from "node:crypto";

import { psiWithdraw } from "./withdraw_sigma_reference.mjs";

const ED_N = ed25519.CURVE.n;
const CHUNK_BITS_NEW = 16; // matches CHUNK_BITS in @aptos-labs/confidential-asset
export const NORMALIZE_ALPHA_SHARE_INFO = "EUNOMA_NORMALIZE_ALPHA_SHARE_V1";

// =============================================================================
// Helpers
// =============================================================================

function modN(x) {
  return mod(x, ED_N);
}

/**
 * Generate a uniform-random nonzero scalar mod ℓ via rejection sampling.
 * Mirrors `randScalar()` in local_v2_withdraw_full.mjs:99-106 and matches
 * the witness blinds generated by `ed25519GenRandom()` in the SDK.
 */
function randScalar() {
  while (true) {
    const buf = randomBytes(32);
    buf[31] &= 0x7f; // clear top bit so the LE value fits below 2^255
    let v = 0n;
    for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(buf[i]);
    if (v < ED_N && v !== 0n) return v;
  }
}

/**
 * Parse a 32-byte LE scalar buffer to a bigint mod ℓ.
 * Matches `bytesToBigLE` + `modN` in local_v2_withdraw_full.mjs:117-122.
 */
function bytesToScalarLE(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("bytesToScalarLE: expected Uint8Array");
  }
  if (bytes.length !== 32) {
    throw new RangeError(`bytesToScalarLE: expected 32 bytes, got ${bytes.length}`);
  }
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return modN(v);
}

/**
 * Encode a bigint scalar into a 32-byte LE buffer (canonical σ-response shape).
 * Wraps `numberToBytesLE` to add a defensive mod-ℓ reduction.
 */
function scalarToBytesLE(s) {
  return numberToBytesLE(modN(s), 32);
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function normalizeHexString(value) {
  return String(value ?? "").replace(/^0x/i, "").toLowerCase();
}

function normalizeSelectedSlots(selectedSlots) {
  if (!Array.isArray(selectedSlots) || selectedSlots.length === 0) {
    throw new TypeError("selectedSlots must be a non-empty array");
  }
  const out = selectedSlots.map((slot) => {
    if (!Number.isInteger(slot) || slot < 0) {
      throw new RangeError(`selectedSlots contains invalid slot ${slot}`);
    }
    return slot;
  });
  for (let i = 1; i < out.length; i += 1) {
    if (out[i - 1] >= out[i]) {
      throw new Error("selectedSlots must be strictly ascending");
    }
  }
  return out;
}

/**
 * Canonical AAD for the user→worker HPKE seal that carries one additive
 * alpha[0] share. The exact string is mirrored in the Rust worker.
 */
export function normalizeAlphaShareAad({
  requestId,
  dkgEpoch,
  rosterHash,
  vaultAddress,
  assetType,
  fiatShamirChallengeHex,
  selectedSlots,
  slot,
}) {
  const slots = normalizeSelectedSlots(selectedSlots);
  if (!slots.includes(slot)) {
    throw new Error(`slot ${slot} is not in selectedSlots`);
  }
  if (typeof requestId !== "string" || requestId.length === 0) {
    throw new Error("requestId is required");
  }
  if (typeof dkgEpoch !== "string" || dkgEpoch.length === 0) {
    throw new Error("dkgEpoch is required");
  }
  const challenge = normalizeHexString(fiatShamirChallengeHex);
  if (!/^[0-9a-f]{64}$/.test(challenge)) {
    throw new Error("fiatShamirChallengeHex must be 32-byte hex");
  }
  return new TextEncoder().encode(
    [
      `domain=${NORMALIZE_ALPHA_SHARE_INFO}`,
      `request=${requestId}`,
      `dkg=${dkgEpoch}`,
      `roster=${normalizeHexString(rosterHash)}`,
      `vault=${normalizeHexString(vaultAddress)}`,
      `asset=${normalizeHexString(assetType)}`,
      `challenge=${challenge}`,
      `slots=${slots.join(",")}`,
      `slot=${slot}`,
    ].join("|"),
  );
}

/**
 * Split alpha[0] into additive shares over the Ed25519 scalar field. The shares
 * are ordered to match selectedSlots; their scalar sum equals alphaZero.
 */
export function splitNormalizeAlphaShares(alphaZeroBytes, selectedSlots) {
  const slots = normalizeSelectedSlots(selectedSlots);
  const alphaZero = bytesToScalarLE(ensureUint8(alphaZeroBytes, "alphaZeroBytes", 32));
  const shares = [];
  let sum = 0n;
  for (let i = 0; i < slots.length - 1; i += 1) {
    const share = randScalar();
    shares.push(share);
    sum = modN(sum + share);
  }
  shares.push(modN(alphaZero - sum));
  const sumCheck = shares.reduce((acc, item) => modN(acc + item), 0n);
  if (sumCheck !== alphaZero) {
    throw new Error("normalize alpha share sum check failed");
  }
  return shares.map((share, i) => ({
    slot: slots[i],
    alphaShare: scalarToBytesLE(share),
    alphaShareHex: bytesToHex(scalarToBytesLE(share)),
  }));
}

function ensureUint8(buf, label, expectLen = null) {
  if (!(buf instanceof Uint8Array)) {
    throw new TypeError(`${label}: expected Uint8Array, got ${typeof buf}`);
  }
  if (expectLen !== null && buf.length !== expectLen) {
    throw new RangeError(`${label}: expected ${expectLen} bytes, got ${buf.length}`);
  }
  return buf;
}

function ensureChunksFitChunkBits(chunks, label) {
  const max = 1n << BigInt(CHUNK_BITS_NEW);
  for (let i = 0; i < chunks.length; i++) {
    if (chunks[i] < 0n || chunks[i] >= max) {
      throw new RangeError(
        `${label}[${i}] = ${chunks[i]} is out of range [0, 2^${CHUNK_BITS_NEW})`,
      );
    }
  }
}

// =============================================================================
// Main builder — produce the 6-vector Move payload plus the α[0] / e tuple
// =============================================================================

/**
 * Build the inputs for `normalize_raw` (Move) when the vault dk is NOT
 * available to the caller — i.e., the Eunoma path where dk is sharded across
 * workers. The caller is responsible for:
 *
 *   1. Splitting `sigmaRespS0NeedsThreshold.alphaZero` into additive shares,
 *      HPKE-sealing one share per selected worker with
 *      `EUNOMA_NORMALIZE_ALPHA_SHARE_V1`, then POSTing only the sealed shares
 *      plus `.fiatShamirChallenge` to the coordinator's normalize endpoint.
 *   2. Building the final `response[]` array as
 *      `[s0_threshold, ...sigmaRespS0NeedsThreshold.responseTail]`
 *      and submitting `(newBalanceP[], newBalanceR[], newBalanceRAud[],
 *      zkrpNewBalance, sigmaCommHex[], response[])` to chain.
 *
 * @param {object} args
 * @param {import("@aptos-labs/confidential-asset").RistPoint[]} args.oldBalanceC
 *   Chain `available_balance.C[]` — length ell.
 * @param {import("@aptos-labs/confidential-asset").RistPoint[]} args.oldBalanceD
 *   Chain `available_balance.D[]` — length ell. These two together are the
 *   ciphertext that re-encrypts (under the SAME plaintext) into the new C/D.
 *
 * @param {bigint[]} args.newBalanceChunks
 *   The plaintext chunks of the balance, re-chunked for the new normalize
 *   encoding. **Must have length ell** (the SDK + Move both pin the new chunk
 *   count to oldBalanceC.length). Each chunk must satisfy 0 ≤ chunk < 2^16.
 *   Derive from a threshold-decrypt of the chain ciphertext; do NOT hardcode.
 *
 * @param {import("@aptos-labs/confidential-asset").TwistedEd25519PublicKey} args.vaultEkPub
 *   The vault encryption key registered on-chain (== dk_REAL · G).
 * @param {import("@aptos-labs/confidential-asset").TwistedEd25519PublicKey | null} [args.auditorEkPub]
 *   Optional auditor encryption key. Pass null when no auditor (testnet APT).
 *
 * @param {Uint8Array} args.senderAddress  — 32-byte vault address (BCS DST).
 * @param {Uint8Array} args.tokenAddress   — 32-byte asset address (BCS DST).
 * @param {number}     args.chainId        — Aptos chain id (DST binding).
 *
 * @param {bigint[]} [args.newBalanceRandomness]
 *   Optional pre-chosen randomness vector (length ell, each < ℓ). If omitted,
 *   the builder generates fresh uniform random scalars internally. Provided
 *   for deterministic testing only — production should let the builder choose.
 *
 * @param {Uint8Array} [args.dkUserFakeSeed]
 *   Optional 32-byte fake-dk seed for deterministic boundary tests only.
 *
 * @returns {Promise<{
 *   newBalanceP: Uint8Array[],
 *   newBalanceR: Uint8Array[],
 *   newBalanceRAud: Uint8Array[],
 *   zkrpNewBalance: Uint8Array,
 *   sigmaCommHex: Uint8Array[],
 *   sigmaRespS0NeedsThreshold: {
 *     responseTail: Uint8Array[],
 *     alphaZero: Uint8Array,
 *     fiatShamirChallenge: Uint8Array,
 *     sessionBcs: Uint8Array,
 *   },
 * }>}
 */
export async function buildNormalizeProofBundle({
  oldBalanceC,
  oldBalanceD,
  newBalanceChunks,
  vaultEkPub,
  auditorEkPub = null,
  senderAddress,
  tokenAddress,
  chainId,
  newBalanceRandomness = null,
  dkUserFakeSeed = null,
}) {
  // -----------------------------
  // Argument validation
  // -----------------------------
  if (!Array.isArray(oldBalanceC) || !Array.isArray(oldBalanceD)) {
    throw new TypeError("buildNormalizeProofBundle: oldBalanceC and oldBalanceD must be arrays");
  }
  const ell = oldBalanceC.length;
  if (oldBalanceD.length !== ell) {
    throw new Error(
      `buildNormalizeProofBundle: oldBalanceD length ${oldBalanceD.length} != ell=${ell}`,
    );
  }
  if (!Array.isArray(newBalanceChunks) || newBalanceChunks.length !== ell) {
    // The SDK + Move both require new-chunk count == old-chunk count (= ell).
    // See sigmaProtocolWithdraw.ts:280 (`const ell = oldBalanceC.length`) and
    // the witness layout `[dk, new_a[ell], new_r[ell]]` at line 337.
    throw new Error(
      `buildNormalizeProofBundle: newBalanceChunks length ${newBalanceChunks?.length} != ell=${ell}`,
    );
  }
  ensureChunksFitChunkBits(newBalanceChunks, "newBalanceChunks");
  ensureUint8(senderAddress, "senderAddress", 32);
  ensureUint8(tokenAddress, "tokenAddress", 32);
  if (!Number.isInteger(chainId) || chainId < 0 || chainId > 255) {
    throw new RangeError(`buildNormalizeProofBundle: chainId=${chainId} out of [0,255]`);
  }
  if (!vaultEkPub || typeof vaultEkPub.toUint8Array !== "function") {
    throw new TypeError("buildNormalizeProofBundle: vaultEkPub must be TwistedEd25519PublicKey");
  }
  const hasAuditor = auditorEkPub !== null && auditorEkPub !== undefined;
  if (hasAuditor && typeof auditorEkPub.toUint8Array !== "function") {
    throw new TypeError("buildNormalizeProofBundle: auditorEkPub must be TwistedEd25519PublicKey or null");
  }

  // -----------------------------
  // Step 1: Fresh randomness for the new ciphertext (one scalar per chunk).
  //         The SAME randomness is reused for the auditor-encrypted variant
  //         (mirrors ConfidentialNormalization.create at line 92-97).
  // -----------------------------
  let randomness;
  if (newBalanceRandomness !== null) {
    if (!Array.isArray(newBalanceRandomness) || newBalanceRandomness.length !== ell) {
      throw new Error(
        `buildNormalizeProofBundle: newBalanceRandomness length ${newBalanceRandomness?.length} != ell=${ell}`,
      );
    }
    randomness = newBalanceRandomness.map((r) => {
      if (typeof r !== "bigint") {
        throw new TypeError("newBalanceRandomness entries must be bigint");
      }
      const reduced = modN(r);
      if (reduced === 0n) {
        throw new Error("newBalanceRandomness entries must be nonzero (mod ℓ)");
      }
      return reduced;
    });
  } else {
    randomness = Array.from({ length: ell }, () => randScalar());
  }

  // -----------------------------
  // Step 2: Encrypt each chunk under the vault encryption key.
  //         TwistedElGamalCiphertext.C and .D are *decompressed* RistrettoPoint
  //         objects (twistedElGamal.ts:194-197 calls `RistrettoPoint.fromHex`
  //         in the constructor). We surface BOTH forms downstream: the byte
  //         form for the Move payload, the point form for the SDK prover and
  //         the Fiat-Shamir re-derivation.
  // -----------------------------
  const newBalanceCt = newBalanceChunks.map((chunk, i) =>
    TwistedElGamal.encryptWithPK(chunk, vaultEkPub, randomness[i]),
  );
  const newBalanceCPoints = newBalanceCt.map((ct) => ct.C);
  const newBalanceDPoints = newBalanceCt.map((ct) => ct.D);
  const newBalanceP = newBalanceCPoints.map((p) => p.toRawBytes()); // Uint8Array(32) each
  const newBalanceR = newBalanceDPoints.map((p) => p.toRawBytes());

  // -----------------------------
  // Step 3 (optional auditor): re-encrypt same plaintext with same randomness
  //         under the auditor key, surface the D points only (Move uses
  //         `new_balance_A` for the auditor-encrypted D vector — same name
  //         pattern as transfer auditor structure).
  // -----------------------------
  let newBalanceRAud = [];
  let newBalanceDAudPoints = null;
  if (hasAuditor) {
    const newBalanceCtAud = newBalanceChunks.map((chunk, i) =>
      TwistedElGamal.encryptWithPK(chunk, auditorEkPub, randomness[i]),
    );
    newBalanceDAudPoints = newBalanceCtAud.map((ct) => ct.D);
    newBalanceRAud = newBalanceDAudPoints.map((p) => p.toRawBytes());
  }

  // -----------------------------
  // Step 4: Batch range proof — proves each new chunk < 2^CHUNK_BITS_NEW.
  //         The Pedersen commitments inside the bulletproof use (G, H) as
  //         (valBase, randBase) which matches Twisted ElGamal's C = m·G + r·H
  //         (the C points are the commitments the verifier consumes).
  //         Mirrors ConfidentialNormalization.genRangeProof at line 149-159.
  // -----------------------------
  const valBase = RistrettoPoint.BASE.toRawBytes();
  const randBase = H_RISTRETTO.toRawBytes();
  const rangeProofResult = await batchRangeProof({
    v: newBalanceChunks,
    rs: randomness.map((r) => numberToBytesLE(r, 32)),
    valBase,
    randBase,
    numBits: CHUNK_BITS_NEW,
  });
  const zkrpNewBalance = rangeProofResult.proof;

  // -----------------------------
  // Step 5: Ephemeral fake user dk for the σ-prover witness.
  //         We extract `dkUserFakeScalar = bytesToNumberLE(seed)` — matches
  //         the SDK's witness encoding (proveWithdrawInternal line 283).
  //         (We don't reduce mod ℓ here because the SDK doesn't either; the
  //         downstream `e * dkBigint` arithmetic in sigmaProtocolProve picks
  //         up the reduction via `ed25519modN` automatically.)
  // -----------------------------
  const fakeSeed =
    dkUserFakeSeed === null
      ? randomBytes(32)
      : ensureUint8(dkUserFakeSeed, "dkUserFakeSeed", 32);
  const dkUserFakeSeedHex = Array.from(fakeSeed)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const dkUserFake = new TwistedEd25519PrivateKey(`0x${dkUserFakeSeedHex}`);
  const dkUserFakeScalar = bytesToNumberLE(dkUserFake.toUint8Array());

  // -----------------------------
  // Step 6: Hand-build the σ-protocol statement embedding ek_REAL (the
  //         on-chain vault encryption key) — NOT dk_user_fake.publicKey().
  //         This is why we bypass `proveWithdrawal`: it derives ek from the
  //         input dk, which would force a fake ek into the Fiat-Shamir
  //         transcript, making the chain's e ≠ our e at substitution time.
  //
  //         Statement layout (mirrors proveWithdrawInternal lines 291-326):
  //           [G, H, ek_REAL,
  //            old_P[ell], old_R[ell], new_P[ell], new_R[ell],
  //            (optional) ek_aud, new_R_aud[ell]]
  // -----------------------------
  const G = RistrettoPoint.BASE;
  const HRist = H_RISTRETTO;
  const ekRealBytes = vaultEkPub.toUint8Array();
  const ekRealPoint = RistrettoPoint.fromHex(ekRealBytes);

  const stmtPoints = [G, HRist, ekRealPoint];
  const stmtCompressed = [G.toRawBytes(), HRist.toRawBytes(), ekRealBytes];
  const pushPoint = (p) => {
    stmtPoints.push(p);
    stmtCompressed.push(p.toRawBytes());
  };

  for (const p of oldBalanceC) pushPoint(p);
  for (const p of oldBalanceD) pushPoint(p);
  for (const p of newBalanceCPoints) pushPoint(p);
  for (const p of newBalanceDPoints) pushPoint(p);

  if (hasAuditor) {
    const ekAudBytes = auditorEkPub.toUint8Array();
    const ekAudPoint = RistrettoPoint.fromHex(ekAudBytes);
    stmtPoints.push(ekAudPoint);
    stmtCompressed.push(ekAudBytes);
    for (const p of newBalanceDAudPoints) pushPoint(p);
  }

  // Statement scalars: `[v]` as 32-byte LE — for normalize v=0.
  // Matches sigmaProtocolWithdraw.ts:329-334 and the verifier path at line 478.
  const vScalar = numberToBytesLE(0n, 32);
  const stmt = {
    points: stmtPoints,
    compressedPoints: stmtCompressed,
    scalars: [vScalar],
  };

  const sessionBcs = bcsSerializeWithdrawSession(senderAddress, tokenAddress, ell, hasAuditor);
  const dst = {
    contractAddress: APTOS_FRAMEWORK_ADDRESS,
    chainId,
    protocolId: utf8ToBytes("AptosConfidentialAsset/WithdrawalV1"),
    sessionId: sessionBcs,
  };
  const TYPE_NAME = "0x1::sigma_protocol_withdraw::Withdrawal";

  // -----------------------------
  // Step 7: Build the witness vector [dk_user_fake, new_a[ell], new_r[ell]]
  //         and call `sigmaProtocolProve` directly. We pass the same psi
  //         function the chain verifier (and our reference verifier) use —
  //         imported from withdraw_sigma_reference.mjs.
  //
  //         Because the statement embeds ek_REAL, the prover commits to
  //           A[0] = ek_REAL · α[0]
  //         and the resulting Fiat-Shamir e is the SAME e the chain will
  //         compute. The response[0] = α[0] + e · dk_user_fake is then
  //         strippable by the coordinator: knowing e and dk_user_fake we
  //         compute α[0] = response[0] - e · dk_user_fake, send α[0] to the
  //         worker quorum, and they aggregate s0_threshold = α[0] + e · dk_REAL.
  // -----------------------------
  const witness = [dkUserFakeScalar, ...newBalanceChunks, ...randomness];

  // psiWithdraw signature: (stmt, witness, ell, hasAuditor) → RistPoint[]
  const psi = (s, w) => psiWithdraw(s, w, ell, hasAuditor);
  const sigmaProof = sigmaProtocolProve(dst, TYPE_NAME, psi, stmt, witness);

  // Shape check on the prover output.
  const expectedCommitmentLen = hasAuditor ? 2 + 3 * ell : 2 + 2 * ell;
  const expectedResponseLen = 1 + 2 * ell;
  if (sigmaProof.commitment.length !== expectedCommitmentLen) {
    throw new Error(
      `buildNormalizeProofBundle: sigmaProof.commitment length ${sigmaProof.commitment.length} != ` +
        `${expectedCommitmentLen} (ell=${ell}, hasAuditor=${hasAuditor})`,
    );
  }
  if (sigmaProof.response.length !== expectedResponseLen) {
    throw new Error(
      `buildNormalizeProofBundle: sigmaProof.response length ${sigmaProof.response.length} != ` +
        `${expectedResponseLen} (ell=${ell})`,
    );
  }

  // -----------------------------
  // Step 8: Re-derive the Fiat-Shamir challenge e to extract α[0].
  //         `sigmaProtocolProve` doesn't return e — it's a deterministic
  //         function of (dst, stmt, commitment) so we recompute it here.
  // -----------------------------
  const { e: feShChallenge } = sigmaProtocolFiatShamir(
    dst,
    TYPE_NAME,
    stmt,
    sigmaProof.commitment,
    expectedResponseLen, // k
  );

  // -----------------------------
  // Step 9: Extract α[0] = response[0] - e · dk_user_fake_scalar (mod ℓ).
  //         Matches the TRANSFER trick at local_v2_withdraw_full.mjs:702-704.
  //         The workers will compute  s0_threshold = α[0] + e · dk_REAL,
  //         which the σ-verifier then sees as the legitimate response[0].
  // -----------------------------
  const responseZeroScalar = bytesToScalarLE(sigmaProof.response[0]);
  const alphaZeroScalar = modN(responseZeroScalar - modN(feShChallenge * dkUserFakeScalar));

  // -----------------------------
  // Step 10: Package outputs.
  //   * sigmaCommHex      = sigmaProof.commitment (already 32-byte Uint8Arrays)
  //   * responseTail      = response[1..] — the chunks the coordinator does NOT
  //                         need to substitute (these are α[i] + e·new_a[i-1]
  //                         etc., all derived from witness scalars the prover
  //                         actually knows; only response[0] involves dk).
  //   * alphaZero         = α[0] for coordinator submission (32-byte LE)
  //   * fiatShamirChallenge = e for worker partial computation (32-byte LE)
  //   * sessionBcs        = full BCS-encoded WithdrawSession (traceability)
  // -----------------------------
  return {
    newBalanceP,                       // Uint8Array[ell], each 32 bytes
    newBalanceR,                       // Uint8Array[ell], each 32 bytes
    newBalanceRAud,                    // Uint8Array[ell] | Uint8Array[0]
    zkrpNewBalance,                    // single Uint8Array (Bulletproof blob)
    sigmaCommHex: sigmaProof.commitment, // Uint8Array[expectedCommitmentLen]
    sigmaRespS0NeedsThreshold: {
      responseTail: sigmaProof.response.slice(1), // Uint8Array[expectedResponseLen - 1]
      alphaZero: scalarToBytesLE(alphaZeroScalar), // 32-byte LE
      fiatShamirChallenge: scalarToBytesLE(feShChallenge), // 32-byte LE
      sessionBcs,                                // Uint8Array (DST traceability)
    },
  };
}

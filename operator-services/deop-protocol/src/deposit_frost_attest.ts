// =================================================================================================
// V2 deposit FROST attestation — depositor-side ↔ coordinator-side wire shapes and parser.
//
// Goal.md required-work item 2: build the depositor-side V2 deposit path. The coordinator
// FROST-attests over DepositAttestationV2Message; the depositor supplies all message fields
// directly in one request (unlike withdraw, deposits do NOT have prior round1/round2/finalize
// ceremonies because amount + balance state stay depositor-side — the deoperator quorum only
// signs the bridge identity envelope).
//
// Privacy contract: the depositor MUST NOT POST any forbidden plaintext fields. The request
// only carries public chain identifiers + commitments + hashes + the deposit nonce. Nullifier
// seed, plaintext amount, secret, deposit blind never leave the depositor's process.
// =================================================================================================

import { bytesToHex, hexToBytes, normalizeHex } from "@eunoma/shared";
import type { HexString } from "@eunoma/shared";

import { assertNoForbiddenPlaintextFields } from "./forbidden.js";
import { DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD } from "./constants.js";

/**
 * V2 deposit FROST attestation request — submitted by the depositor (or a depositor-side CLI
 * acting on their behalf) to `POST /v2/deposit/frost-attest`.
 *
 * The coordinator constructs a `DepositAttestationV2Message` from these fields, BCS-encodes it
 * via `bcsEncodeDepositAttestationV2`, runs the same 3-phase FROST signing pipeline used by the
 * withdraw attestation flow over the 5 selected slots, and returns the FROST group signature
 * (plus the assembled message bytes for audit).
 */
export interface DepositFrostAttestRequest {
  /** Caller-supplied safe id. The coordinator embeds it into per-request FS paths. */
  requestId: string;
  /** Decimal string. Must match the CA DKG V2 roster's dkg_epoch and the on-chain
   *  DeoperatorConfigV2.dkg_epoch. */
  dkgEpoch: string;
  /** 32-byte hex. Must equal the coordinator's caDkgV2RosterHash. */
  rosterHash: HexString;
  /** Exactly DEOPERATOR_THRESHOLD (5) distinct slots, each in [0, DEOPERATOR_COUNT-1]. */
  selectedSlots: number[];

  // ----- Chain-side attestation context (must match on-chain BridgeVault + DeoperatorConfigV2) -----
  /** 32-byte hex (Aptos bridge package address). */
  bridge: HexString;
  /** 32-byte hex (BridgeVault.vault_addr resource account). */
  vault: HexString;
  /** 32-byte hex (Aptos Object<Metadata> asset address). */
  assetType: HexString;
  /** u8 (Aptos chain id: 2 for testnet). */
  chainId: number;
  /** Decimal string. */
  operatorSetVersion: string;
  /** 32-byte hex (compressed Ed25519 group public key from DeoperatorConfigV2). */
  frostGroupPubkey: HexString;
  /** 32-byte hex (DeoperatorConfigV2.circuit_versions_hash). */
  circuitVersionsHash: HexString;

  // ----- Deposit-specific public envelope fields (committed to chain in DepositConfirmedV2) -----
  /** 32-byte hex. Poseidon-derived note commitment binding (nullifier, secret, asset_id,
   *  amount, pool_id). The depositor computes this locally; the deoperator quorum only signs
   *  the envelope containing it. */
  commitment: HexString;
  /** 32-byte hex. Poseidon-derived tag binding (depositor private witness components,
   *  asset_id, vault_addr_hash, chain_id). Same privacy story as commitment. */
  amountTag: HexString;
  /** 32-byte hex. Fr-safe ca_payload_hash derived via `caPayloadHashFrV2(payload)`. */
  caPayloadHash: HexString;
  /** 32-byte hex. Unique per deposit; bridge enforces no-replay via `used_deposit_nonces`. */
  depositNonce: HexString;
  /** Decimal string. Unix-seconds-since-epoch deadline after which the attestation MUST NOT
   *  be accepted by `deposit_with_commitment_v2`. */
  expirySecs: string;
}

export class DepositFrostAttestError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "DepositFrostAttestError";
  }
}

export function parseDepositFrostAttestRequest(body: unknown): DepositFrostAttestRequest {
  // 1. Forbidden-plaintext-field guard FIRST. This is the same guard used by
  //    parseMpccaWithdrawBaseRequest; it ensures fields like `amount`, `blind`, `secret`,
  //    `dk*`, `nullifier` never reach the coordinator even by accident.
  assertNoForbiddenPlaintextFields(body);

  const obj = objectBody(body);

  const requestId = requireString(obj, "requestId");
  const dkgEpoch = requireDecimalString(obj, "dkgEpoch");
  const rosterHash = requireHex(obj, "rosterHash", 32);
  const selectedSlots = requireSelectedSlots(obj, "selectedSlots");
  const bridge = requireHex(obj, "bridge", 32);
  const vault = requireHex(obj, "vault", 32);
  const assetType = requireHex(obj, "assetType", 32);
  const chainId = requireInt(obj, "chainId", 0, 255);
  const operatorSetVersion = requireDecimalString(obj, "operatorSetVersion");
  const frostGroupPubkey = requireHex(obj, "frostGroupPubkey", 32);
  const circuitVersionsHash = requireHex(obj, "circuitVersionsHash", 32);
  const commitment = requireHex(obj, "commitment", 32);
  const amountTag = requireHex(obj, "amountTag", 32);
  const caPayloadHash = requireHex(obj, "caPayloadHash", 32);
  const depositNonce = requireHex(obj, "depositNonce", 32);
  const expirySecs = requireDecimalString(obj, "expirySecs");

  return {
    requestId,
    dkgEpoch,
    rosterHash,
    selectedSlots,
    bridge,
    vault,
    assetType,
    chainId,
    operatorSetVersion,
    frostGroupPubkey,
    circuitVersionsHash,
    commitment,
    amountTag,
    caPayloadHash,
    depositNonce,
    expirySecs,
  };
}

/**
 * Per-deposit-attestation persistence record. The coordinator writes this to
 * `<stateRoot>/coordinator/deposit_frost_attest/<dkgEpoch>__<requestId>.json` after the FROST
 * fanout completes, for audit + post-mortem.
 *
 * Privacy contract: every field is a public chain identifier or hash. No plaintext witness
 * components, no envelope keys, no decryption-key shares.
 */
export interface DepositFrostAttestArtifact {
  scheme: "deposit_frost_attest_v2";
  dkgEpoch: string;
  requestId: string;
  rosterHash: HexString;
  selectedSlots: number[];
  messageBytesHex: HexString;
  groupSignature: HexString;
  /** Per-slot transcript hashes from the worker FROST nonce + partial rounds, sorted by slot. */
  perSlotTranscriptHashes: Array<{ slot: number; nonceTranscriptHash: HexString; partialTranscriptHash: HexString }>;
  /** Computed `keccak256(messageBytes || groupSignature)` for transcript anchoring. */
  attestationTranscriptHash: HexString;
  createdAtUnixMs: number;
}

// =================================================================================================
// Internal helpers — duplicated from mpcca_withdraw_v2.ts so this module stays self-contained
// (single import of public exports rather than reaching into private functions). Kept narrow:
// only the validators we need for the 15 deposit-attest fields.
// =================================================================================================

function objectBody(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new DepositFrostAttestError("INVALID_BODY", "request body must be a JSON object");
  }
  return body as Record<string, unknown>;
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new DepositFrostAttestError(
      "INVALID_FIELD",
      `${key} must be a non-empty string`,
    );
  }
  return v;
}

function requireDecimalString(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v)) {
    throw new DepositFrostAttestError(
      "INVALID_FIELD",
      `${key} must be a non-negative decimal string`,
    );
  }
  return v;
}

function requireHex(obj: Record<string, unknown>, key: string, bytes: number): HexString {
  const v = obj[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new DepositFrostAttestError(
      "INVALID_FIELD",
      `${key} must be a non-empty hex string`,
    );
  }
  const norm = normalizeHex(v);
  let decoded;
  try {
    decoded = hexToBytes(norm);
  } catch (err) {
    throw new DepositFrostAttestError(
      "INVALID_FIELD",
      `${key} must decode as hex; got ${(err as Error).message}`,
    );
  }
  if (decoded.length !== bytes) {
    throw new DepositFrostAttestError(
      "INVALID_FIELD",
      `${key} must be ${bytes}-byte hex (got ${decoded.length})`,
    );
  }
  return norm;
}

function requireInt(
  obj: Record<string, unknown>,
  key: string,
  min: number,
  max: number,
): number {
  const v = obj[key];
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) {
    throw new DepositFrostAttestError(
      "INVALID_FIELD",
      `${key} must be an integer in [${min}, ${max}]`,
    );
  }
  return v;
}

function requireSelectedSlots(obj: Record<string, unknown>, key: string): number[] {
  const v = obj[key];
  if (!Array.isArray(v)) {
    throw new DepositFrostAttestError(
      "INVALID_FIELD",
      `${key} must be an array of ${DEOPERATOR_THRESHOLD} distinct slots`,
    );
  }
  if (v.length !== DEOPERATOR_THRESHOLD) {
    throw new DepositFrostAttestError(
      "INVALID_FIELD",
      `${key} must have length ${DEOPERATOR_THRESHOLD} (got ${v.length})`,
    );
  }
  const seen = new Set<number>();
  for (const slot of v) {
    if (typeof slot !== "number" || !Number.isInteger(slot) || slot < 0 || slot >= DEOPERATOR_COUNT) {
      throw new DepositFrostAttestError(
        "INVALID_FIELD",
        `${key} entries must be integers in [0, ${DEOPERATOR_COUNT - 1}] (got ${JSON.stringify(slot)})`,
      );
    }
    if (seen.has(slot)) {
      throw new DepositFrostAttestError(
        "INVALID_FIELD",
        `${key} contains duplicate slot ${slot}`,
      );
    }
    seen.add(slot);
  }
  return [...(v as number[])];
}

/** Compute keccak256(messageBytes || groupSignature) — used as the audit transcript hash. */
export function depositAttestationTranscriptHash(
  messageBytesHex: HexString,
  groupSignatureHex: HexString,
): HexString {
  // Inline because this module avoids reaching into mpcca_withdraw_v2 internals. Use the
  // shared keccak256 helper directly via dynamic import-friendly shape.
  const mb = hexToBytes(messageBytesHex);
  const gs = hexToBytes(groupSignatureHex);
  const concat = new Uint8Array(mb.length + gs.length);
  concat.set(mb, 0);
  concat.set(gs, mb.length);
  return bytesToHex(keccak(concat));
}

// keccak256 helper — imported lazily to avoid cyclic deps. Mirrors @eunoma/shared keccak256.
import { keccak256 as keccak } from "@eunoma/shared";

// Structured argument validator for the Aptos Move entry function
//
//   eunoma_bridge::withdraw_to_recipient_v2(_relayer: &signer, ..27 fields..)
//
// The 27 fields below are in EXACT positional order matching
//   move/sources/eunoma_bridge.move:515-543
//
// This module is the relayer's source of truth for what an off-chain caller
// must POST to /v2/relayer/submit/withdraw. The validator:
//   1. Runs the recursive forbidden-plaintext-field gate FIRST (witness
//      defense-in-depth: amount*, blind*, secret*, vault_dk*, nullifier*,
//      dk_share*, shamir_share* etc. are rejected at the HTTP boundary even
//      if the caller mistakenly nested them under a sub-object).
//   2. Strictly validates each field's shape (hex evenness, byte length where
//      the Move side asserts `assert_hash`, decimal string for u64, bitmap
//      range 0..=255 for the fallback bitmap, depth-3 nesting for
//      amountRVolunAuds).
//   3. Enforces the M5a no-auditor invariant: the four auditor-only vectors
//      (newBalanceREffAud, amountREffAud, ekVolunAuds, amountRVolunAuds) MUST
//      be empty arrays. Eunoma is no-auditor today; Milestone 4d / future
//      hardening will introduce auditor support and relax this gate.
//   4. Returns a fully-typed WithdrawV2CallArgs ready for the CLI submitter
//      to encode via aptos_args.* helpers.
//
// The domain constant EUNOMA_WITHDRAW_V2_CALL_ARGS_V1 is exported for future
// transcript-binding use (M5b/5c) — keeping it here groups the version with
// the schema it describes.

import { hexToBytes } from "@eunoma/shared";
import type { HexString } from "@eunoma/shared";
import { FR_BYTES } from "./constants.js";
import { assertNoForbiddenPlaintextFields } from "./forbidden.js";

/**
 * Error raised when the call-args body fails structural validation in a way
 * that carries a stable error code (vs. a free-form parser message). The
 * relayer surfaces `code` over the wire so callers can branch on it.
 */
export class WithdrawV2CallArgsError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "WithdrawV2CallArgsError";
  }
}

export const EUNOMA_WITHDRAW_V2_DOMAIN = "EUNOMA_WITHDRAW_V2_CALL_ARGS_V1";

/**
 * Positional list of WithdrawV2CallArgs field names, in EXACT Move source order
 * (move/sources/eunoma_bridge.move:515-543, excluding the `_relayer: &signer`
 * which the CLI binds from the signing profile). The relayer submitter MUST
 * encode CLI args in this order, and the parser MUST list TS keys in this
 * order — both are checked by the killer test in
 * operator-services/relayer/tests/server.test.ts.
 */
export const WITHDRAW_V2_CALL_ARGS_ORDER = [
  "root",
  "nullifierHash",
  "recipient",
  "recipientHash",
  "amountTag",
  "caPayloadHash",
  "requestHash",
  "vaultSequence",
  "withdrawProof",
  "expirySecs",
  "groupSignature",
  "fallbackBitmap",
  "fallbackSignatures",
  "newBalanceP",
  "newBalanceR",
  "newBalanceREffAud",
  "amountP",
  "amountRSender",
  "amountRRecip",
  "amountREffAud",
  "ekVolunAuds",
  "amountRVolunAuds",
  "zkrpNewBalance",
  "zkrpAmount",
  "sigmaProtoComm",
  "sigmaProtoResp",
  "memo",
] as const;

export type WithdrawV2CallArgsKey = (typeof WITHDRAW_V2_CALL_ARGS_ORDER)[number];

/**
 * Strictly-typed positional argument bundle for
 * `eunoma_bridge::withdraw_to_recipient_v2`. Field order in this interface
 * mirrors the Move signature: do NOT reorder.
 */
export interface WithdrawV2CallArgs {
  /** 32-byte Fr hash. Move: `root: vector<u8>` + `assert_hash`. */
  root: HexString;
  /** 32-byte Fr hash. Move: `nullifier_hash: vector<u8>` + `assert_hash`. */
  nullifierHash: HexString;
  /** 32-byte Aptos address. Move: `recipient: address`. */
  recipient: HexString;
  /** 32-byte hash. Move: `recipient_hash: vector<u8>` + `assert_hash`. */
  recipientHash: HexString;
  /** 32-byte Fr hash. Move: `amount_tag: vector<u8>` + `assert_hash`. */
  amountTag: HexString;
  /** 32-byte Fr hash. Move: `ca_payload_hash: vector<u8>` + `assert_hash`. */
  caPayloadHash: HexString;
  /** 32-byte Fr hash. Move: `request_hash: vector<u8>` + `assert_hash`. */
  requestHash: HexString;
  /** Decimal string. Move: `vault_sequence: u64`. */
  vaultSequence: string;
  /** Variable-length Groth16 proof bytes. Move: `withdraw_proof: vector<u8>`. */
  withdrawProof: HexString;
  /** Decimal string. Move: `expiry_secs: u64`. */
  expirySecs: string;
  /** Variable-length FROST signature. Move: `group_signature: vector<u8>`. */
  groupSignature: HexString;
  /** 0..=255. Move: `fallback_bitmap: u8`. */
  fallbackBitmap: number;
  /** Move: `fallback_signatures: vector<vector<u8>>`. */
  fallbackSignatures: HexString[];
  /** Move: `new_balance_p: vector<vector<u8>>`. */
  newBalanceP: HexString[];
  /** Move: `new_balance_r: vector<vector<u8>>`. */
  newBalanceR: HexString[];
  /** Move: `new_balance_r_eff_aud: vector<vector<u8>>` (may be empty). */
  newBalanceREffAud: HexString[];
  /** Move: `amount_p: vector<vector<u8>>`. */
  amountP: HexString[];
  /** Move: `amount_r_sender: vector<vector<u8>>`. */
  amountRSender: HexString[];
  /** Move: `amount_r_recip: vector<vector<u8>>`. */
  amountRRecip: HexString[];
  /** Move: `amount_r_eff_aud: vector<vector<u8>>` (may be empty). */
  amountREffAud: HexString[];
  /** Move: `ek_volun_auds: vector<vector<u8>>` (may be empty). */
  ekVolunAuds: HexString[];
  /** Move: `amount_r_volun_auds: vector<vector<vector<u8>>>` (depth 3, may be empty). */
  amountRVolunAuds: HexString[][];
  /** Variable-length Bulletproofs proof. Move: `zkrp_new_balance: vector<u8>`. */
  zkrpNewBalance: HexString;
  /** Variable-length Bulletproofs proof. Move: `zkrp_amount: vector<u8>`. */
  zkrpAmount: HexString;
  /** Move: `sigma_proto_comm: vector<vector<u8>>`. */
  sigmaProtoComm: HexString[];
  /** Move: `sigma_proto_resp: vector<vector<u8>>`. */
  sigmaProtoResp: HexString[];
  /** Move: `memo: vector<u8>` (may be empty bytes). */
  memo: HexString;
}

/**
 * Parse and validate a WithdrawV2CallArgs body received over HTTP. Runs the
 * forbidden-plaintext-field gate FIRST so even malformed payloads with a
 * top-level `amount` or nested `secret_share` are rejected before any shape
 * checks burn cycles.
 *
 * Throws:
 *   - ForbiddenPlaintextFieldError on witness-field violations (handled by the
 *     route to surface a 400 `forbidden_plaintext_field`).
 *   - Error("...") with a descriptive message on every other validation failure.
 */
export function parseWithdrawV2CallArgs(raw: unknown): WithdrawV2CallArgs {
  assertNoForbiddenPlaintextFields(raw);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("WithdrawV2CallArgs body must be an object");
  }
  const obj = raw as Record<string, unknown>;
  const parsed: WithdrawV2CallArgs = {
    root: hexField(obj, "root", FR_BYTES),
    nullifierHash: hexField(obj, "nullifierHash", FR_BYTES),
    recipient: hexField(obj, "recipient", 32),
    recipientHash: hexField(obj, "recipientHash", FR_BYTES),
    amountTag: hexField(obj, "amountTag", FR_BYTES),
    caPayloadHash: hexField(obj, "caPayloadHash", FR_BYTES),
    requestHash: hexField(obj, "requestHash", FR_BYTES),
    vaultSequence: decimalU64Field(obj, "vaultSequence"),
    withdrawProof: hexField(obj, "withdrawProof", undefined, { allowEmpty: true }),
    expirySecs: decimalU64Field(obj, "expirySecs"),
    groupSignature: hexField(obj, "groupSignature"),
    fallbackBitmap: u8Field(obj, "fallbackBitmap"),
    fallbackSignatures: hexArrayField(obj, "fallbackSignatures", { allowEmpty: true }),
    newBalanceP: hexArrayField(obj, "newBalanceP", { allowEmpty: false }),
    newBalanceR: hexArrayField(obj, "newBalanceR", { allowEmpty: false }),
    newBalanceREffAud: hexArrayField(obj, "newBalanceREffAud", { allowEmpty: true }),
    amountP: hexArrayField(obj, "amountP", { allowEmpty: false }),
    amountRSender: hexArrayField(obj, "amountRSender", { allowEmpty: false }),
    amountRRecip: hexArrayField(obj, "amountRRecip", { allowEmpty: false }),
    amountREffAud: hexArrayField(obj, "amountREffAud", { allowEmpty: true }),
    ekVolunAuds: hexArrayField(obj, "ekVolunAuds", { allowEmpty: true }),
    amountRVolunAuds: hexVector3Field(obj, "amountRVolunAuds"),
    zkrpNewBalance: hexField(obj, "zkrpNewBalance"),
    zkrpAmount: hexField(obj, "zkrpAmount"),
    sigmaProtoComm: hexArrayField(obj, "sigmaProtoComm", { allowEmpty: false }),
    sigmaProtoResp: hexArrayField(obj, "sigmaProtoResp", { allowEmpty: false }),
    memo: hexField(obj, "memo", undefined, { allowEmpty: true }),
  };

  // M5a no-auditor invariant: every auditor-only vector MUST be empty. The
  // Move side will eventually accept non-empty auditor payloads (Milestone 4d
  // / future hardening) but for the alpha-testnet milestone we fail closed at
  // the HTTP boundary so a future "add auditors" feature can never be turned
  // on by accident from an upstream client.
  if (
    parsed.newBalanceREffAud.length !== 0 ||
    parsed.amountREffAud.length !== 0 ||
    parsed.ekVolunAuds.length !== 0 ||
    parsed.amountRVolunAuds.length !== 0
  ) {
    throw new WithdrawV2CallArgsError(
      "auditor_branch_not_supported_in_milestone_5a",
      "Eunoma is no-auditor today; auditor fields must be empty arrays. Milestone 4d / future hardening will introduce auditor support.",
    );
  }

  return parsed;
}

// ---------------------------------------------------------------------------
// Field validators
// ---------------------------------------------------------------------------

function hexField(
  obj: Record<string, unknown>,
  key: string,
  expectedBytes?: number,
  opts: { allowEmpty?: boolean } = {},
): string {
  const value = obj[key];
  if (typeof value !== "string") {
    throw new Error(`${key} must be a hex string`);
  }
  if (!opts.allowEmpty && value.length === 0) {
    throw new Error(`${key} must be a non-empty hex string`);
  }
  // hexToBytes throws if odd nibbles / non-hex chars.
  const bytes = hexToBytes(value);
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    throw new Error(`${key} must be ${expectedBytes} bytes`);
  }
  return value;
}

function decimalU64Field(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${key} must be a decimal string`);
  }
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${key} must be a decimal string`);
  }
  // Range-check against u64 max so encoding into the CLI cannot silently
  // overflow on the Move side.
  if (BigInt(value) > 18446744073709551615n) {
    throw new Error(`${key} must fit in u64`);
  }
  return value;
}

function u8Field(obj: Record<string, unknown>, key: string): number {
  const value = obj[key];
  if (!Number.isInteger(value)) {
    throw new Error(`${key} must be an integer 0..=255`);
  }
  const n = value as number;
  if (n < 0 || n > 255) {
    throw new Error(`${key} must be an integer 0..=255`);
  }
  return n;
}

function hexArrayField(
  obj: Record<string, unknown>,
  key: string,
  opts: { allowEmpty: boolean },
): string[] {
  const value = obj[key];
  if (!Array.isArray(value)) {
    throw new Error(`${key} must be an array`);
  }
  if (!opts.allowEmpty && value.length === 0) {
    throw new Error(`${key} must be a non-empty array`);
  }
  return value.map((item, idx) => {
    if (typeof item !== "string") {
      throw new Error(`${key}[${idx}] must be a hex string`);
    }
    // throws on bad hex
    hexToBytes(item);
    return item;
  });
}

function hexVector3Field(obj: Record<string, unknown>, key: string): string[][] {
  const value = obj[key];
  if (!Array.isArray(value)) {
    throw new Error(`${key} must be an array`);
  }
  return value.map((outer, outerIdx) => {
    if (!Array.isArray(outer)) {
      throw new Error(
        `${key}[${outerIdx}] must be an array of hex strings (vector<vector<u8>>)`,
      );
    }
    return outer.map((item, innerIdx) => {
      if (typeof item !== "string") {
        throw new Error(`${key}[${outerIdx}][${innerIdx}] must be a hex string`);
      }
      hexToBytes(item);
      return item;
    });
  });
}

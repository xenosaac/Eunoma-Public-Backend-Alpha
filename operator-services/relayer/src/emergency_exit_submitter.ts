// CP5 RC6(B): de-list 5-of-7 emergency-exit coordination for the relayer.
//
// When Aptos governance DE-LISTS an active confidential asset (is_confidentiality_enabled becomes
// false), the normal confidential withdraw / ragequit paths can no longer settle through the CA
// framework. The bridge's `emergency_exit_to_raw_v4` entry drains the vault's residual balance to
// PLAIN FA via the framework `withdraw_to_raw` primitive, authorized by the SAME 5-of-7 FROST
// attestation flow as every other privileged exit — recipient + amount are SIGNED bytes, so the
// low-privilege relayer that submits this tx can neither redirect the funds nor change the amount.
//
// This module is the relayer's source of truth for:
//   1. the positional CLI args of `emergency_exit_to_raw_v4`, mirroring the Move signature
//      eunoma_bridge.move:emergency_exit_to_raw_v4 EXACTLY (read positionally, never a guessed map);
//   2. classifying the on-chain abort into a STRUCTURED signal — most importantly surfacing the
//      framework-wide `is_emergency_paused()` halt as `framework_paused` (NOT a silent CLI error),
//      because a global confidential_asset emergency pause halts EVEN this de-list exit, and the UI
//      must tell the user "withdrawals are halted by a framework pause" rather than show an opaque
//      failure (2026-06-01-eunoma-v4-dormant-lifecycle-and-delist-exit-VERIFIED.md §3, residual).
//
// HARD INVARIANTS honored here:
//   - 5-of-7: the attestation is the SAME FROST group-sig OR fallback-bitmap form the withdraw path
//     uses; threshold = 5 is enforced ON-CHAIN (assert_deop_attestation_v2 -> cfg.threshold). This
//     module NEVER carries a threshold and NEVER a thresholdOverride.
//   - recipient + amount are PUBLIC, SIGNED fields. `amount` is the intentional de-list disclosure
//     (the residual is drained to plain FA) — so the confidential-path forbidden-`amount` gate is
//     deliberately NOT applied to emergency-exit args (it would reject a legitimate, signed,
//     governance-authorized field). The lineage.* / secret / nullifier bans are irrelevant here:
//     emergency-exit has no note witness at all.

import { hexToBytes } from "@eunoma/shared";
import type { HexString } from "@eunoma/shared";

/**
 * Positional argument names for `eunoma_bridge::emergency_exit_to_raw_v4`, in EXACT Move source
 * order (eunoma_bridge.move, excluding the leading `_relayer: &signer` the CLI binds from the
 * signing profile):
 *
 *   asset_addr, recipient, amount, expiry_secs,
 *   group_signature, fallback_bitmap, fallback_signatures,
 *   new_balance_p, new_balance_r, new_balance_r_aud,
 *   zkrp_new_balance, sigma_proto_comm, sigma_proto_resp
 *
 * NOTE the framework `withdraw_to_raw` CA args differ from the confidential-transfer path: there is
 * a SINGLE auditor vector `new_balance_r_aud` (not the `_eff_aud` + amount_* family), and there is
 * NO amount_* / ek_volun_auds / amount_r_volun_auds / zkrp_amount (withdraw_to_raw moves a known
 * plaintext amount out, so only the NEW available-balance proof is needed).
 */
export const EMERGENCY_EXIT_CALL_ARGS_ORDER = [
  "assetAddr",
  "recipient",
  "amount",
  "expirySecs",
  "groupSignature",
  "fallbackBitmap",
  "fallbackSignatures",
  "newBalanceP",
  "newBalanceR",
  "newBalanceRAud",
  "zkrpNewBalance",
  "sigmaProtoComm",
  "sigmaProtoResp",
] as const;

export type EmergencyExitCallArgsKey = (typeof EMERGENCY_EXIT_CALL_ARGS_ORDER)[number];

/**
 * Strictly-typed positional args for `eunoma_bridge::emergency_exit_to_raw_v4`. Field order mirrors
 * the Move signature — do NOT reorder.
 */
export interface EmergencyExitCallArgs {
  /** 32-byte Aptos address. Move: `asset_addr: address` — registry routing key (resolved on-chain). */
  assetAddr: HexString;
  /** 32-byte Aptos address. Move: `recipient: address` — SIGNED into the FROST attestation. */
  recipient: HexString;
  /**
   * Decimal u64 string. Move: `amount: u64` — the PLAINTEXT residual being drained to plain FA.
   * This is the intentional de-list emergency DISCLOSURE; it is a SIGNED field of the 5-of-7
   * attestation, NOT a confidential witness, so it is allowed (unlike the confidential withdraw
   * path where any plaintext amount is forbidden).
   */
  amount: string;
  /** Decimal u64 string. Move: `expiry_secs: u64`. */
  expirySecs: string;
  /** FROST group signature bytes (empty when using the fallback bitmap). Move: `group_signature`. */
  groupSignature: HexString;
  /** 0..=255. Move: `fallback_bitmap: u8` — which deoperators co-signed in the fallback path. */
  fallbackBitmap: number;
  /** Move: `fallback_signatures: vector<vector<u8>>` — per-signer ed25519 sigs (5-of-7 fallback). */
  fallbackSignatures: HexString[];
  /** Move: `new_balance_p: vector<vector<u8>>` — new available-balance ciphertext (withdraw_to_raw). */
  newBalanceP: HexString[];
  /** Move: `new_balance_r: vector<vector<u8>>`. */
  newBalanceR: HexString[];
  /** Move: `new_balance_r_aud: vector<vector<u8>>` (single auditor vector; may be empty). */
  newBalanceRAud: HexString[];
  /** Variable-length Bulletproofs range proof. Move: `zkrp_new_balance: vector<u8>`. */
  zkrpNewBalance: HexString;
  /** Move: `sigma_proto_comm: vector<vector<u8>>`. */
  sigmaProtoComm: HexString[];
  /** Move: `sigma_proto_resp: vector<vector<u8>>`. */
  sigmaProtoResp: HexString[];
}

export class EmergencyExitCallArgsError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "EmergencyExitCallArgsError";
  }
}

/**
 * Parse + validate an EmergencyExitCallArgs body. Mirrors the withdraw validator's shape checks but
 * does NOT run the confidential forbidden-field gate: `amount` is a legitimate signed disclosure
 * here. The M5a no-auditor invariant is preserved — `newBalanceRAud` MUST be empty.
 */
export function parseEmergencyExitCallArgs(raw: unknown): EmergencyExitCallArgs {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new EmergencyExitCallArgsError(
      "invalid_body",
      "EmergencyExitCallArgs body must be an object",
    );
  }
  const obj = raw as Record<string, unknown>;
  const parsed: EmergencyExitCallArgs = {
    assetAddr: addressField(obj, "assetAddr"),
    recipient: addressField(obj, "recipient"),
    amount: decimalU64Field(obj, "amount"),
    expirySecs: decimalU64Field(obj, "expirySecs"),
    groupSignature: hexField(obj, "groupSignature", { allowEmpty: true }),
    fallbackBitmap: u8Field(obj, "fallbackBitmap"),
    fallbackSignatures: hexArrayField(obj, "fallbackSignatures", { allowEmpty: true }),
    newBalanceP: hexArrayField(obj, "newBalanceP", { allowEmpty: false }),
    newBalanceR: hexArrayField(obj, "newBalanceR", { allowEmpty: false }),
    newBalanceRAud: hexArrayField(obj, "newBalanceRAud", { allowEmpty: true }),
    zkrpNewBalance: hexField(obj, "zkrpNewBalance", { allowEmpty: false }),
    sigmaProtoComm: hexArrayField(obj, "sigmaProtoComm", { allowEmpty: false }),
    sigmaProtoResp: hexArrayField(obj, "sigmaProtoResp", { allowEmpty: false }),
  };
  // M5a no-auditor invariant (same as the withdraw path): the auditor vector MUST be empty.
  if (parsed.newBalanceRAud.length !== 0) {
    throw new EmergencyExitCallArgsError(
      "auditor_branch_not_supported",
      "Eunoma is no-auditor today; newBalanceRAud must be an empty array.",
    );
  }
  // The FROST attestation MUST be present in SOME form (group sig OR a non-empty fallback set) —
  // an emergency drain with no 5-of-7 authorization can never be assembled here (the on-chain
  // assert_deop_attestation_v2 is the hard gate, but fail closed at the boundary too).
  if (parsed.groupSignature.length === 0 && parsed.fallbackSignatures.length === 0) {
    throw new EmergencyExitCallArgsError(
      "missing_frost_attestation",
      "emergency exit requires a FROST group signature or a non-empty fallback signature set (5-of-7).",
    );
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// Structured on-chain abort classification (the RC6(B) "never a silent error" surface).
// ---------------------------------------------------------------------------

/**
 * A structured classification of an emergency-exit submission outcome. `signal` is the stable,
 * UI-facing code; `detail` is a short human string (NEVER raw stderr — that stays in relayer logs).
 *
 *   framework_paused   — confidential_asset::is_emergency_paused() is true: a GLOBAL framework pause
 *                        halts EVERY CA primitive INCLUDING withdraw_to_raw, so even this de-list
 *                        exit cannot settle. The UI shows "withdrawals halted (framework pause)".
 *   not_delisted       — the asset is still CA-enabled (is_confidentiality_enabled == true): the
 *                        emergency path is refused (E_NOT_DELISTED); use the normal withdraw/ragequit.
 *   asset_not_active   — the registry row is DORMANT (E_ASSET_NOT_ACTIVE): nothing to drain.
 *   submit_error       — any other CLI/abort failure (opaque; details only in relayer logs).
 */
export type EmergencyExitSignal =
  | "framework_paused"
  | "not_delisted"
  | "asset_not_active"
  | "submit_error";

export interface EmergencyExitClassification {
  signal: EmergencyExitSignal;
  detail: string;
}

// confidential_asset::E_EMERGENCY_PAUSED = 20, raised via error::invalid_state(20). The framework
// uses aptos_std::error, which encodes a canonical abort code as (category << 16) + reason. The
// INVALID_STATE category is 0x3, so the abort the global is_emergency_paused() check produces
// renders as 0x30014 == decimal 196628 — NOT a bare 20. We match that canonical form.
//
// eunoma_bridge's OWN de-list codes use raw `assert!(..., E_X)` (no error:: wrapper), so they
// render as the bare numeric reason (44 / 40).
const FRAMEWORK_E_EMERGENCY_PAUSED_CANONICAL = (0x3 << 16) + 20; // 196628 / 0x30014
const BRIDGE_E_NOT_DELISTED = 44;
const BRIDGE_E_ASSET_NOT_ACTIVE = 40;

/**
 * Classify an aptos-CLI failure stderr (move abort) for the emergency-exit path into a structured
 * signal. The CLI prints a MoveAbort that names the location module and the abort code; we match the
 * confidential_asset framework emergency-pause code (20) and the bridge's own de-list codes. The
 * raw stderr is NEVER returned — only the stable signal + a short detail string.
 *
 * Detection is intentionally conservative: it keys on the (module, code) pair so an unrelated abort
 * sharing a numeric code in a different module is NOT mis-classified as framework_paused.
 */
export function classifyEmergencyExitAbort(stderrText: string): EmergencyExitClassification {
  const s = stderrText;
  // Framework emergency pause: confidential_asset module + the canonical invalid_state(20) abort,
  // rendered as 196628 (decimal) or 0x30014 (hex), OR the symbolic name. Keyed on the
  // confidential_asset location so an unrelated 196628 elsewhere is not mis-classified.
  const canonicalDec = String(FRAMEWORK_E_EMERGENCY_PAUSED_CANONICAL); // "196628"
  if (
    /confidential_asset/.test(s) &&
    (new RegExp(`\\b${canonicalDec}\\b`).test(s) ||
      /0x3_?0*14\b/i.test(s) ||
      /is_emergency_paused|E_EMERGENCY_PAUSED|EMERGENCY_PAUSED/.test(s))
  ) {
    return {
      signal: "framework_paused",
      detail:
        "confidential_asset framework emergency pause is active — all withdrawals (including the de-list exit) are halted.",
    };
  }
  if (matchesBridgeAbort(s, BRIDGE_E_NOT_DELISTED) || /E_NOT_DELISTED/.test(s)) {
    return {
      signal: "not_delisted",
      detail:
        "asset is still CA-enabled — use the normal confidential withdraw/ragequit; the emergency exit is only for a de-listed asset.",
    };
  }
  if (matchesBridgeAbort(s, BRIDGE_E_ASSET_NOT_ACTIVE) || /E_ASSET_NOT_ACTIVE/.test(s)) {
    return {
      signal: "asset_not_active",
      detail: "asset registry row is DORMANT — nothing to drain.",
    };
  }
  return {
    signal: "submit_error",
    detail: "emergency exit submission failed; see relayer logs for details.",
  };
}

function matchesBridgeAbort(s: string, code: number): boolean {
  return (
    /eunoma_bridge/.test(s) &&
    new RegExp(`(?:abort_code|MoveAbort).*?\\b${code}\\b`).test(s)
  );
}

// ---------------------------------------------------------------------------
// Field validators (local copies; emergency-exit has a distinct arg shape from withdraw).
// ---------------------------------------------------------------------------

function addressField(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== "string") {
    throw new EmergencyExitCallArgsError(`${key}_invalid`, `${key} must be a hex address string`);
  }
  const clean = value.replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length > 64) {
    throw new EmergencyExitCallArgsError(
      `${key}_invalid`,
      `${key} must be a 0x-prefixed hex address (≤32 bytes)`,
    );
  }
  return value;
}

function decimalU64Field(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value.length === 0 || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new EmergencyExitCallArgsError(`${key}_invalid`, `${key} must be a decimal string`);
  }
  if (BigInt(value) > 18446744073709551615n) {
    throw new EmergencyExitCallArgsError(`${key}_invalid`, `${key} must fit in u64`);
  }
  return value;
}

function u8Field(obj: Record<string, unknown>, key: string): number {
  const value = obj[key];
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 255) {
    throw new EmergencyExitCallArgsError(`${key}_invalid`, `${key} must be an integer 0..=255`);
  }
  return value as number;
}

function hexField(
  obj: Record<string, unknown>,
  key: string,
  opts: { allowEmpty?: boolean } = {},
): string {
  const value = obj[key];
  if (typeof value !== "string") {
    throw new EmergencyExitCallArgsError(`${key}_invalid`, `${key} must be a hex string`);
  }
  if (!opts.allowEmpty && value.length === 0) {
    throw new EmergencyExitCallArgsError(`${key}_invalid`, `${key} must be a non-empty hex string`);
  }
  hexToBytes(value); // throws on odd nibbles / non-hex chars
  return value;
}

function hexArrayField(
  obj: Record<string, unknown>,
  key: string,
  opts: { allowEmpty: boolean },
): string[] {
  const value = obj[key];
  if (!Array.isArray(value)) {
    throw new EmergencyExitCallArgsError(`${key}_invalid`, `${key} must be an array`);
  }
  if (!opts.allowEmpty && value.length === 0) {
    throw new EmergencyExitCallArgsError(`${key}_invalid`, `${key} must be a non-empty array`);
  }
  return value.map((item, idx) => {
    if (typeof item !== "string") {
      throw new EmergencyExitCallArgsError(`${key}_invalid`, `${key}[${idx}] must be a hex string`);
    }
    hexToBytes(item);
    return item;
  });
}

/**
 * Encode one EmergencyExitCallArgs into the positional aptos-CLI arg strings in EXACT Move order.
 * Address fields use `address:0x...`; hashes/proofs use `hex:`; u64 use `u64:`; the bitmap `u8:`;
 * vectors `hex:[...]`. Mirrors the relayer's withdraw encodeField conventions.
 */
export function encodeEmergencyExitArgs(args: EmergencyExitCallArgs): string[] {
  return EMERGENCY_EXIT_CALL_ARGS_ORDER.map((key) => encodeEmergencyExitField(key, args[key]));
}

export function encodeEmergencyExitField(
  key: EmergencyExitCallArgsKey,
  value: EmergencyExitCallArgs[EmergencyExitCallArgsKey],
): string {
  switch (key) {
    case "assetAddr":
    case "recipient": {
      const clean = String(value).replace(/^0x/i, "").toLowerCase();
      return `address:0x${clean.padStart(64, "0")}`;
    }
    case "amount":
    case "expirySecs":
      return `u64:${value as string}`;
    case "fallbackBitmap":
      return `u8:${value as number}`;
    case "groupSignature":
    case "zkrpNewBalance": {
      const v = String(value).replace(/^0x/i, "");
      return `hex:0x${v}`;
    }
    case "fallbackSignatures":
    case "newBalanceP":
    case "newBalanceR":
    case "newBalanceRAud":
    case "sigmaProtoComm":
    case "sigmaProtoResp": {
      const arr = (value as string[]).map((h) => `0x${h.replace(/^0x/i, "")}`);
      return `hex:[${arr.join(",")}]`;
    }
    default: {
      const exhaustive: never = key;
      throw new Error(`unhandled EmergencyExitCallArgs key: ${exhaustive as string}`);
    }
  }
}

// CP3: parser/validator for the /v3/relayer/submit/deposit request (DepositV3DelegateArgs).
//
// Runs the forbidden-plaintext-field guard FIRST (same privacy boundary as the withdraw + deposit-
// attest paths — amount/blind/secret/dk/nullifier must never reach the relayer), then shape-checks
// each field. The deposit-delegate path is fund-inert (the relayer only submits prepare + step2a;
// step2b — the user's own CA debit — is NOT relayer-submitted), so a bad request can at worst waste
// relayer gas, never lose funds. Validation still rejects garbage early and enforces the privacy guard.
import { ForbiddenPlaintextFieldError } from "@eunoma/deop-protocol";
import type { DepositV3DelegateArgs } from "./deposit_v3_submitter.js";

export class DepositV3ArgsError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "DepositV3ArgsError";
  }
}

// Re-implemented locally (the deop-protocol requireHex/etc. are not package exports). Mirrors the
// forbidden-field key set used by parseDepositFrostAttestRequest / parseWithdrawV2CallArgs.
const FORBIDDEN_KEYS = [
  "amount",
  "amount_octas",
  "amountoctas",
  "blind",
  "balance_chunks",
  "balancechunks",
  "plaintext_amount",
  "plaintextamount",
  "secret",
  "secret_share",
  "secretshare",
  "dk",
  "dk_share",
  "dkshare",
  "decryption_key",
  "decryptionkey",
  "nullifier",
];

function assertNoForbidden(value: unknown, path = ""): void {
  if (Array.isArray(value)) {
    value.forEach((v, i) => assertNoForbidden(v, `${path}[${i}]`));
    return;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const norm = k.toLowerCase().replace(/_/g, "");
      if (FORBIDDEN_KEYS.some((f) => f.replace(/_/g, "") === norm)) {
        throw new ForbiddenPlaintextFieldError(path ? `${path}.${k}` : k);
      }
      assertNoForbidden(v, path ? `${path}.${k}` : k);
    }
  }
}

function objectBody(body: unknown): Record<string, unknown> {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new DepositV3ArgsError("invalid_request", "body must be a JSON object");
  }
  return body as Record<string, unknown>;
}

/** Normalize to lowercase hex without 0x; optionally enforce an exact byte length. */
function hexStr(o: Record<string, unknown>, key: string, exactBytes?: number): string {
  const v = o[key];
  if (typeof v !== "string") {
    throw new DepositV3ArgsError("invalid_request", `${key} must be a hex string`);
  }
  const clean = v.replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new DepositV3ArgsError("invalid_request", `${key} must be byte-aligned hex`);
  }
  if (exactBytes !== undefined && clean.length !== exactBytes * 2) {
    throw new DepositV3ArgsError("invalid_request", `${key} must be exactly ${exactBytes} bytes`);
  }
  return clean;
}

function hexArr(o: Record<string, unknown>, key: string): string[] {
  const v = o[key];
  if (!Array.isArray(v)) {
    throw new DepositV3ArgsError("invalid_request", `${key} must be an array of hex strings`);
  }
  return v.map((item, i) => {
    if (typeof item !== "string") {
      throw new DepositV3ArgsError("invalid_request", `${key}[${i}] must be a hex string`);
    }
    const clean = item.replace(/^0x/i, "").toLowerCase();
    if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
      throw new DepositV3ArgsError("invalid_request", `${key}[${i}] must be byte-aligned hex`);
    }
    return clean;
  });
}

function hex3Arr(o: Record<string, unknown>, key: string): string[][] {
  const v = o[key];
  if (!Array.isArray(v)) {
    throw new DepositV3ArgsError("invalid_request", `${key} must be an array of arrays of hex`);
  }
  return v.map((inner, i) => {
    if (!Array.isArray(inner)) {
      throw new DepositV3ArgsError("invalid_request", `${key}[${i}] must be an array of hex`);
    }
    return inner.map((item, j) => {
      if (typeof item !== "string") {
        throw new DepositV3ArgsError("invalid_request", `${key}[${i}][${j}] must be a hex string`);
      }
      return item.replace(/^0x/i, "").toLowerCase();
    });
  });
}

function decimalStr(o: Record<string, unknown>, key: string): string {
  const v = o[key];
  if (typeof v !== "string" || !/^[0-9]+$/.test(v)) {
    throw new DepositV3ArgsError("invalid_request", `${key} must be a decimal string`);
  }
  return v;
}

function u8(o: Record<string, unknown>, key: string): number {
  const v = o[key];
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 255) {
    throw new DepositV3ArgsError("invalid_request", `${key} must be a u8 (0..255)`);
  }
  return v;
}

export function parseDepositV3DelegateArgs(body: unknown): DepositV3DelegateArgs {
  assertNoForbidden(body); // privacy guard FIRST — may throw ForbiddenPlaintextFieldError
  const o = objectBody(body);
  return {
    assetAddr: hexStr(o, "assetAddr", 32),
    userAddr: hexStr(o, "userAddr", 32),
    commitment: hexStr(o, "commitment", 32),
    amountTag: hexStr(o, "amountTag", 32),
    amountP: hexArr(o, "amountP"),
    depositBindingProof: hexStr(o, "depositBindingProof"),
    caPayloadHash: hexStr(o, "caPayloadHash", 32),
    depositNonce: hexStr(o, "depositNonce", 32),
    expirySecs: decimalStr(o, "expirySecs"),
    groupSignature: hexStr(o, "groupSignature"),
    fallbackBitmap: u8(o, "fallbackBitmap"),
    fallbackSignatures: hexArr(o, "fallbackSignatures"),
    newBalanceP: hexArr(o, "newBalanceP"),
    newBalanceR: hexArr(o, "newBalanceR"),
    newBalanceREffAud: hexArr(o, "newBalanceREffAud"),
    amountRSender: hexArr(o, "amountRSender"),
    amountRRecip: hexArr(o, "amountRRecip"),
    amountREffAud: hexArr(o, "amountREffAud"),
    ekVolunAuds: hexArr(o, "ekVolunAuds"),
    amountRVolunAuds: hex3Arr(o, "amountRVolunAuds"),
    zkrpNewBalance: hexStr(o, "zkrpNewBalance"),
    zkrpAmount: hexStr(o, "zkrpAmount"),
    sigmaProtoComm: hexArr(o, "sigmaProtoComm"),
    sigmaProtoResp: hexArr(o, "sigmaProtoResp"),
    memo: hexStr(o, "memo"),
  };
}

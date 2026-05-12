// Withdraw canonical helpers — single source of truth for the off-circuit
// recomputations that bind a withdraw request's amount to amount_tag / request_hash.
//
// Until now these lived inline inside `operator-services/scripts/build_testnet_withdraw_proof.ts`.
// The P0 backend withdraw-amount-binding work (plan-for-this-frolicking-wilkes.md) requires
// the main-operator finalize handler to recompute amount_tag / request_hash from server-side
// canonical state and the prover script to use the same logic; deduplicating into shared
// is the only way to guarantee byte equality.
//
// Domain string `APTOSHIELD_RECIPIENT_HASH_V1` is FROZEN. Move-side
// `eunoma_bridge.move:145` and the circuit-side recipient_hash binding both
// hardcode it. Changing it would invalidate every recipient_hash everywhere.
// Per project rebrand memo: on-chain symbols renamed aptosshield→eunoma BUT
// Poseidon domain bytes did not change.

import { hash2, hash3 } from "./poseidon_mirror.js";
import {
  bytesToFieldLe32,
  u64ToFieldLe32,
  u8ToFieldLe32,
} from "./hex.js";
import { FR_BYTES } from "./types.js";

export const POSEIDON_DOMAIN_RECIPIENT_HASH = new TextEncoder().encode(
  "APTOSHIELD_RECIPIENT_HASH_V1",
);

/// 6-input Poseidon compose: compose6(a,b,c,d,e,f) = hash2(hash3(a,b,c), hash3(d,e,f)).
/// Mirror of the withdraw circuit's `Compose6` template; byte-identical to
/// Move's recompute path because both sides use circomlibjs poseidon parameters.
export async function compose6(
  a: Uint8Array,
  b: Uint8Array,
  c: Uint8Array,
  d: Uint8Array,
  e: Uint8Array,
  f: Uint8Array,
): Promise<Uint8Array> {
  const lo = await hash3(a, b, c);
  const hi = await hash3(d, e, f);
  return hash2(lo, hi);
}

/// derive_recipient_hash mirror — Move source `eunoma_bridge.move:140-158`
/// (function `derive_recipient_hash`). Splits a 32-byte Aptos address into
/// the high 16 bytes and low 16 bytes (each zero-padded to 32-byte LE Fr),
/// then `hash3(domain, hi, lo)`.
export async function deriveRecipientHash(
  recipient: Uint8Array,
): Promise<Uint8Array> {
  if (recipient.length !== 32) {
    throw new Error(
      `deriveRecipientHash: expected 32-byte recipient, got ${recipient.length}`,
    );
  }
  const domain = bytesToFieldLe32(POSEIDON_DOMAIN_RECIPIENT_HASH);
  const hi = bytesToFieldLe32(recipient.slice(0, 16));
  const lo = bytesToFieldLe32(recipient.slice(16, 32));
  return hash3(domain, hi, lo);
}

/// Withdraw amount_tag = compose6(amount, withdraw_blind, recipient_hash,
///                                 asset_id_le32, chain_id_le32, vault_sequence_le32).
///
/// Order MUST match `withdrawal_proof.circom:198-206` (`tag.in[0..5]`). Server
/// canonical: every input here is server-derived from the WithdrawRequest row.
export async function deriveAmountTag(args: {
  amount: bigint; // u64
  withdraw_blind: Uint8Array; // 32-byte LE Fr (random per withdraw)
  recipient_hash: Uint8Array; // 32-byte LE Fr (output of deriveRecipientHash)
  asset_id_le32: Uint8Array; // 32-byte LE Fr (output of deriveAssetId)
  chain_id: number; // u8
  vault_sequence: bigint; // u64
}): Promise<Uint8Array> {
  assertFr32(args.withdraw_blind, "withdraw_blind");
  assertFr32(args.recipient_hash, "recipient_hash");
  assertFr32(args.asset_id_le32, "asset_id_le32");
  return compose6(
    u64ToFieldLe32(args.amount),
    args.withdraw_blind,
    args.recipient_hash,
    args.asset_id_le32,
    u8ToFieldLe32(args.chain_id),
    u64ToFieldLe32(args.vault_sequence),
  );
}

/// Withdraw request_hash = compose6(amount_tag, recipient_hash, ca_payload_hash,
///                                   asset_id_le32, vault_sequence_le32, chain_id_le32).
///
/// Order MUST match `withdrawal_proof.circom:209-216` (`req.in[0..5]`). Note
/// that vault_sequence comes BEFORE chain_id here, the opposite of amount_tag;
/// the circuit defines it that way so we mirror it exactly.
export async function deriveRequestHash(args: {
  amount_tag: Uint8Array; // 32-byte LE Fr
  recipient_hash: Uint8Array; // 32-byte LE Fr
  ca_payload_hash: Uint8Array; // 32-byte LE Fr-safe (high byte zeroed)
  asset_id_le32: Uint8Array; // 32-byte LE Fr
  vault_sequence: bigint; // u64
  chain_id: number; // u8
}): Promise<Uint8Array> {
  assertFr32(args.amount_tag, "amount_tag");
  assertFr32(args.recipient_hash, "recipient_hash");
  assertFr32(args.ca_payload_hash, "ca_payload_hash");
  assertFr32(args.asset_id_le32, "asset_id_le32");
  return compose6(
    args.amount_tag,
    args.recipient_hash,
    args.ca_payload_hash,
    args.asset_id_le32,
    u64ToFieldLe32(args.vault_sequence),
    u8ToFieldLe32(args.chain_id),
  );
}

// ---------------------------------------------------------------------------
// 32-byte LE Fr <-> snarkjs decimal-string helpers.
// snarkjs publicInputs / proof coordinates are decimal strings of BN254 Fr
// elements. The circuit + Move sides exchange the same scalars as 32-byte
// little-endian buffers.

export function le32ToDec(buf: Uint8Array): string {
  if (buf.length !== FR_BYTES) {
    throw new Error(`le32ToDec: expected ${FR_BYTES}-byte buffer, got ${buf.length}`);
  }
  let n = 0n;
  for (let i = buf.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(buf[i]);
  return n.toString();
}

export function decToLe32(dec: string): Uint8Array {
  let n = BigInt(dec);
  const out = new Uint8Array(FR_BYTES);
  for (let i = 0; i < FR_BYTES; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new Error(`decToLe32: Fr exceeds ${FR_BYTES} bytes: ${dec}`);
  return out;
}

/// Pack snarkjs G1 point `[x, y]` (decimal strings) into 64-byte LE buffer
/// matching Move's uncompressed representation (`x_le32 || y_le32`).
export function g1ToBytes(point: string[]): Uint8Array {
  if (!Array.isArray(point) || point.length < 2) {
    throw new Error(`g1ToBytes: expected [x, y] (or [x, y, "1"]), got ${JSON.stringify(point)}`);
  }
  const out = new Uint8Array(64);
  out.set(decToLe32(point[0]), 0);
  out.set(decToLe32(point[1]), 32);
  return out;
}

/// Pack snarkjs G2 point `[[x0, x1], [y0, y1]]` (decimal strings) into 128-byte LE buffer
/// matching Move's uncompressed representation (`x0_le32 || x1_le32 || y0_le32 || y1_le32`).
export function g2ToBytes(point: string[][]): Uint8Array {
  if (!Array.isArray(point) || point.length < 2) {
    throw new Error(`g2ToBytes: expected [[x0,x1],[y0,y1]] (or with z), got ${JSON.stringify(point)}`);
  }
  const [x, y] = point;
  const out = new Uint8Array(128);
  out.set(decToLe32(x[0]), 0);
  out.set(decToLe32(x[1]), 32);
  out.set(decToLe32(y[0]), 64);
  out.set(decToLe32(y[1]), 96);
  return out;
}

function assertFr32(b: Uint8Array, name: string): void {
  if (b.length !== FR_BYTES) {
    throw new Error(`${name}: expected ${FR_BYTES}-byte LE Fr, got ${b.length}`);
  }
}

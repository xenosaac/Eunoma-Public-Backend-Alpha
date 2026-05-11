// Poseidon BN254 mirror — produces 32-byte LE Fr digests byte-identical to
// `aptos_std::poseidon_bn254::hash_2` / `hash_3` in Move.
//
// Aptos's `poseidon_bn254` uses circomlibjs's reference parameters (BN254 with
// the standard MDS / round constants used by circomlib's `poseidon`). circomlibjs
// exposes `buildPoseidon()` which returns a callable `(inputs[, state]) => F` and
// helpers `F.toObject` / `F.fromObject`. We pass each 32-byte LE Fr buffer in via
// `F.fromRprLE` to stay byte-identical with Move's `fr_from_le`.

import { buildPoseidon } from "circomlibjs";
import {
  POSEIDON_DOMAIN_ASSET_ID,
  POSEIDON_DOMAIN_VAULT_ADDR_HASH,
  FR_BYTES,
} from "./types.js";
import { bytesToFieldLe32 } from "./hex.js";

type PoseidonFn = ((inputs: any[]) => any) & { F: any };

let poseidonInstance: PoseidonFn | null = null;

export async function getPoseidon(): Promise<PoseidonFn> {
  if (poseidonInstance) return poseidonInstance;
  const p = (await buildPoseidon()) as PoseidonFn;
  poseidonInstance = p;
  return p;
}

/// Convert a 32-byte LE buffer into a circomlibjs Fr "Montgomery" element.
function frFromLe(F: any, le: Uint8Array): any {
  if (le.length !== FR_BYTES) {
    throw new Error(`frFromLe: expected ${FR_BYTES}-byte buffer, got ${le.length}`);
  }
  // F.fromRprLE = read raw representation little-endian.
  return F.fromRprLE(le, 0);
}

/// Convert a circomlibjs Fr element into 32-byte LE bytes (matches Move's
/// `poseidon_bn254::hash_*` output convention — 32-byte LE Fr).
function frToLe(F: any, el: any): Uint8Array {
  // F.toRprLE writes Montgomery -> normal -> LE bytes.
  const out = new Uint8Array(FR_BYTES);
  F.toRprLE(out, 0, el);
  return out;
}

/// poseidon_bn254::hash_2(a, b) — inputs and output are 32-byte LE Fr buffers.
export async function hash2(a: Uint8Array, b: Uint8Array): Promise<Uint8Array> {
  const p = await getPoseidon();
  const F = p.F;
  const inputs = [frFromLe(F, a), frFromLe(F, b)];
  const out = p(inputs);
  return frToLe(F, out);
}

/// poseidon_bn254::hash_3(a, b, c) — inputs and output are 32-byte LE Fr buffers.
export async function hash3(
  a: Uint8Array,
  b: Uint8Array,
  c: Uint8Array,
): Promise<Uint8Array> {
  const p = await getPoseidon();
  const F = p.F;
  const inputs = [frFromLe(F, a), frFromLe(F, b), frFromLe(F, c)];
  const out = p(inputs);
  return frToLe(F, out);
}

/// derive_asset_id mirror (Move source: confidential_bridge.move:1005-1018).
///
///   asset_id = poseidon_bn254.hash_3(domain, addr_hi_16B, addr_lo_16B)
///
/// where domain = "APTOSHIELD_ASSET_ID_V1" zero-padded to 32-byte LE,
/// addr_hi_16B = bytes [0..16) of address zero-padded to 32-byte LE,
/// addr_lo_16B = bytes [16..32) similarly padded.
export async function deriveAssetId(addr32: Uint8Array): Promise<Uint8Array> {
  if (addr32.length !== 32) {
    throw new Error(`deriveAssetId: expected 32-byte address, got ${addr32.length}`);
  }
  const domain = bytesToFieldLe32(POSEIDON_DOMAIN_ASSET_ID);
  const hi = bytesToFieldLe32(addr32.slice(0, 16));
  const lo = bytesToFieldLe32(addr32.slice(16, 32));
  return hash3(domain, hi, lo);
}

/// derive_vault_addr_hash mirror (confidential_bridge.move:1026-1037).
export async function deriveVaultAddrHash(
  addr32: Uint8Array,
): Promise<Uint8Array> {
  if (addr32.length !== 32) {
    throw new Error(`deriveVaultAddrHash: expected 32-byte address, got ${addr32.length}`);
  }
  const domain = bytesToFieldLe32(POSEIDON_DOMAIN_VAULT_ADDR_HASH);
  const hi = bytesToFieldLe32(addr32.slice(0, 16));
  const lo = bytesToFieldLe32(addr32.slice(16, 32));
  return hash3(domain, hi, lo);
}

/// Compose5 recipe (Gate 4a circuit): hash_2(hash_3(a,b,c), hash_2(d,e)).
export async function compose5(
  a: Uint8Array,
  b: Uint8Array,
  c: Uint8Array,
  d: Uint8Array,
  e: Uint8Array,
): Promise<Uint8Array> {
  const left = await hash3(a, b, c);
  const right = await hash2(d, e);
  return hash2(left, right);
}

/// Recompute amount_tag from operator-side disclosed inputs.
///
///   amount_tag = compose5(amount, deposit_blind, asset_id, vault_addr_hash, chain_id)
///
/// Each input is encoded as a 32-byte LE Fr buffer.
export async function recomputeAmountTag(args: {
  amount: bigint; // u64
  deposit_blind_le32: Uint8Array; // 32-byte LE Fr
  asset_id_le32: Uint8Array; // 32-byte LE Fr (output of deriveAssetId)
  vault_addr_hash_le32: Uint8Array; // 32-byte LE Fr (output of deriveVaultAddrHash)
  chain_id: number; // u8
}): Promise<Uint8Array> {
  const { u64ToFieldLe32, u8ToFieldLe32 } = await import("./hex.js");
  const amount_le = u64ToFieldLe32(args.amount);
  const chain_id_le = u8ToFieldLe32(args.chain_id);
  return compose5(
    amount_le,
    args.deposit_blind_le32,
    args.asset_id_le32,
    args.vault_addr_hash_le32,
    chain_id_le,
  );
}

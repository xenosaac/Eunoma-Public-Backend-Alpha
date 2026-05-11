// keccak256 mirror for hash_confidential_transfer_payload (Gate 4b convention).
//
//   hash = keccak256(bcs(CAPayloadForHash{...}))
//
// Move uses `aptos_hash::keccak256` which is plain Ethereum-style Keccak-256
// (not SHA3-256). @noble/hashes exposes this as `keccak_256`.

import { keccak_256 } from "@noble/hashes/sha3";
import { bcsEncodeCAPayloadForHash } from "./bcs.js";
import { CAPayloadForHashStruct } from "./types.js";

export function keccak256(b: Uint8Array): Uint8Array {
  return keccak_256(b);
}

export function hashConfidentialTransferPayload(
  p: CAPayloadForHashStruct,
): Uint8Array {
  return keccak256(bcsEncodeCAPayloadForHash(p));
}

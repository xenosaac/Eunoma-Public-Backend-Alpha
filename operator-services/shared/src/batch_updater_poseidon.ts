// Sync-after-init Poseidon BN254 helpers — drop-in replacement for the
// spike's `Poseidon_Research/AptosShield_Spike/operator/batch_updater.ts`
// `initPoseidon` / `poseidon2` / `poseidon3` surface (Phase 4 W4).
//
// Why duplicate the wrappers when poseidon_mirror.ts already exposes async
// hash2/hash3? Because batch-updater code calls poseidon2 from inside loops
// (frontier insert/root walking) that were originally written sync. Async
// would cascade `await`s through every level of TREE_DEPTH; the spike's
// init-once-then-call-sync pattern keeps the merkle update tight.
//
// Both modules share circomlibjs's `buildPoseidon` underneath — there is
// only ONE Poseidon instance per process. Calling either `getPoseidon()`
// from poseidon_mirror OR `initPoseidon()` from here primes the same cache.

import { buildPoseidon } from "circomlibjs";

let poseidonInstance: any | null = null;

export async function initPoseidon(): Promise<void> {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
}

function bytesLEToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
}

export function poseidon2(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (!poseidonInstance) {
    throw new Error("poseidon not initialized — call initPoseidon() before any hash");
  }
  const out = poseidonInstance([bytesLEToBigInt(a), bytesLEToBigInt(b)]);
  const buf = new Uint8Array(32);
  poseidonInstance.F.toRprLE(buf, 0, out);
  return buf;
}

export function poseidon3(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array {
  if (!poseidonInstance) {
    throw new Error("poseidon not initialized — call initPoseidon() before any hash");
  }
  const out = poseidonInstance([
    bytesLEToBigInt(a),
    bytesLEToBigInt(b),
    bytesLEToBigInt(c),
  ]);
  const buf = new Uint8Array(32);
  poseidonInstance.F.toRprLE(buf, 0, out);
  return buf;
}

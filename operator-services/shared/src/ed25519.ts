// Ed25519 sign + verify wrappers using @noble/curves.
//
// Move-side verifier: `aptos_std::ed25519::signature_verify_strict(sig_bytes,
// pubkey_bytes, message_bytes)`. The Aptos verifier is "strict" — it rejects
// non-canonical signatures (RFC 8032 §5.1.7). @noble/curves's ed25519 produces
// canonical signatures by default, so cross-language interop holds without
// extra fiddling.
//
// HSM/KMS abstraction: the `Signer` interface lets the production code path
// swap in AWS/GCP KMS later without touching call-sites. The in-memory impl
// is used by tests + Gate 4c integration tests.

import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "node:crypto";

export interface Signer {
  publicKey(): Uint8Array; // 32 bytes
  sign(message: Uint8Array): Promise<Uint8Array>; // 64 bytes
}

export class InMemoryEd25519Signer implements Signer {
  private readonly _privateKey: Uint8Array; // 32 bytes (seed)
  private readonly _publicKey: Uint8Array; // 32 bytes

  constructor(privateKey?: Uint8Array) {
    if (privateKey) {
      if (privateKey.length !== 32) {
        throw new Error(`Ed25519 seed must be 32 bytes, got ${privateKey.length}`);
      }
      this._privateKey = privateKey;
    } else {
      // crypto.randomBytes is OS-CSPRNG sourced — DO NOT use Math.random.
      this._privateKey = new Uint8Array(randomBytes(32));
    }
    this._publicKey = ed25519.getPublicKey(this._privateKey);
  }

  static fromSeedHex(seedHex: string): InMemoryEd25519Signer {
    const h = seedHex.startsWith("0x") ? seedHex.slice(2) : seedHex;
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      out[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
    }
    return new InMemoryEd25519Signer(out);
  }

  publicKey(): Uint8Array {
    return this._publicKey;
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return ed25519.sign(message, this._privateKey);
  }

  // Test helper — real production HSM/KMS Signer impl will not expose this.
  privateKeyForTests(): Uint8Array {
    return this._privateKey;
  }
}

export function verifyEd25519(
  signature: Uint8Array,
  pubkey: Uint8Array,
  message: Uint8Array,
): boolean {
  if (signature.length !== 64) return false;
  if (pubkey.length !== 32) return false;
  try {
    return ed25519.verify(signature, message, pubkey);
  } catch {
    return false;
  }
}

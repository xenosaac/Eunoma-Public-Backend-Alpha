// Minimal pure BCS encoder mirroring Move's `bcs::to_bytes` for the structs we
// need — DepositAttestationMessage + CAPayloadForHash. No external dep so we
// can guarantee byte-for-byte parity without relying on aptos-ts-sdk version
// drift. Cross-checked against LOCAL_CONFIRMATION 8.6 + Aptos BCS spec:
//
//   * primitives are little-endian (u8, u16, u32, u64)
//   * `vector<T>` = ULEB128 length || elements
//   * `vector<u8>` = ULEB128 length || raw bytes
//   * structs are concatenation of fields in declared order
//   * `address` is 32 raw bytes (NO length prefix)
//
// For Move's `Object<Metadata>` BCS-encoding: Object is a `struct Object<T> { inner: address }`,
// so BCS-encodes to exactly 32 bytes (the inner address) — same as a bare address.
// (Aptos BCS is identical for Object<T> and address.)

import {
  CAPayloadForHashStruct,
  DepositAttestationMessageStruct,
} from "./types.js";

// ----- Primitive serializers -----

class Writer {
  private parts: number[] = [];

  writeBytesRaw(b: Uint8Array): void {
    for (let i = 0; i < b.length; i++) this.parts.push(b[i]);
  }

  writeU8(n: number): void {
    if (n < 0 || n > 0xff) throw new Error(`writeU8 oob: ${n}`);
    this.parts.push(n);
  }

  writeU64(n: bigint): void {
    if (n < 0n || n >= 1n << 64n) throw new Error(`writeU64 oob: ${n}`);
    let v = n;
    for (let i = 0; i < 8; i++) {
      this.parts.push(Number(v & 0xffn));
      v >>= 8n;
    }
  }

  writeUleb128(n: number): void {
    // ULEB128 little-endian variable-length unsigned int.
    if (n < 0) throw new Error(`writeUleb128 negative: ${n}`);
    let v = n;
    while (v >= 0x80) {
      this.parts.push((v & 0x7f) | 0x80);
      v >>>= 7;
    }
    this.parts.push(v & 0x7f);
  }

  // address = exactly 32 raw bytes, no length prefix.
  writeAddress(b: Uint8Array): void {
    if (b.length !== 32) throw new Error(`writeAddress: expected 32 bytes, got ${b.length}`);
    this.writeBytesRaw(b);
  }

  // vector<u8> = uleb128 length || raw bytes
  writeVecU8(b: Uint8Array): void {
    this.writeUleb128(b.length);
    this.writeBytesRaw(b);
  }

  // vector<vector<u8>> = uleb128 outer length || (each inner vector<u8>)
  writeVecVecU8(arr: Uint8Array[]): void {
    this.writeUleb128(arr.length);
    for (const inner of arr) this.writeVecU8(inner);
  }

  // vector<vector<vector<u8>>>
  writeVecVecVecU8(arr: Uint8Array[][]): void {
    this.writeUleb128(arr.length);
    for (const middle of arr) this.writeVecVecU8(middle);
  }

  finish(): Uint8Array {
    return new Uint8Array(this.parts);
  }
}

// ----- Encoders -----

export function bcsEncodeDepositAttestationMessage(
  msg: DepositAttestationMessageStruct,
): Uint8Array {
  // Field order: domain (vector<u8>), chain_id (u8), pool_id (vector<u8>),
  //   operator_set_version (u64), threshold (u64), vault_addr (address),
  //   asset_type (Object<Metadata> = address), commitment (vector<u8>),
  //   amount_tag (vector<u8>), ca_payload_hash (vector<u8>),
  //   deposit_nonce (vector<u8>), expiry_secs (u64).
  const w = new Writer();
  w.writeVecU8(msg.domain);
  w.writeU8(msg.chain_id);
  w.writeVecU8(msg.pool_id);
  w.writeU64(msg.operator_set_version);
  w.writeU64(msg.threshold);
  w.writeAddress(msg.vault_addr);
  w.writeAddress(msg.asset_type);
  w.writeVecU8(msg.commitment);
  w.writeVecU8(msg.amount_tag);
  w.writeVecU8(msg.ca_payload_hash);
  w.writeVecU8(msg.deposit_nonce);
  w.writeU64(msg.expiry_secs);
  return w.finish();
}

export function bcsEncodeCAPayloadForHash(p: CAPayloadForHashStruct): Uint8Array {
  // Field order: asset_type (Object = address), vault_addr (address),
  //   new_balance_p, new_balance_r, new_balance_r_eff_aud,
  //   amount_p, amount_r_sender, amount_r_recip, amount_r_eff_aud,
  //   ek_volun_auds (all vector<vector<u8>>),
  //   amount_r_volun_auds (vector<vector<vector<u8>>>),
  //   zkrp_new_balance, zkrp_amount (vector<u8>),
  //   sigma_proto_comm, sigma_proto_resp (vector<vector<u8>>),
  //   memo (vector<u8>).
  const w = new Writer();
  w.writeAddress(p.asset_type);
  w.writeAddress(p.vault_addr);
  w.writeVecVecU8(p.new_balance_p);
  w.writeVecVecU8(p.new_balance_r);
  w.writeVecVecU8(p.new_balance_r_eff_aud);
  w.writeVecVecU8(p.amount_p);
  w.writeVecVecU8(p.amount_r_sender);
  w.writeVecVecU8(p.amount_r_recip);
  w.writeVecVecU8(p.amount_r_eff_aud);
  w.writeVecVecU8(p.ek_volun_auds);
  w.writeVecVecVecU8(p.amount_r_volun_auds);
  w.writeVecU8(p.zkrp_new_balance);
  w.writeVecU8(p.zkrp_amount);
  w.writeVecVecU8(p.sigma_proto_comm);
  w.writeVecVecU8(p.sigma_proto_resp);
  w.writeVecU8(p.memo);
  return w.finish();
}

// Exposed for parity tests + lower-level use.
export { Writer };

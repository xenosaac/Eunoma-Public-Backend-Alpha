// Hex helpers — minimal, dependency-free, normalize 0x prefix.

export function hexToBytes(hex: string): Uint8Array {
  let h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) {
    throw new Error(`hexToBytes: odd-length hex string (${h.length} chars)`);
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(h.substring(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`hexToBytes: invalid hex at offset ${i * 2}: ${h.substring(i * 2, i * 2 + 2)}`);
    }
    out[i] = byte;
  }
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += b[i].toString(16).padStart(2, "0");
  }
  return s;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/// Pad/truncate `src` to 32-byte LE Fr-canonical buffer (mirror of Move's
/// `bytes_to_field_le32`). Throws if src.length > 32.
export function bytesToFieldLe32(src: Uint8Array): Uint8Array {
  if (src.length > 32) {
    throw new Error(`bytesToFieldLe32: source > 32 bytes (got ${src.length})`);
  }
  const out = new Uint8Array(32);
  out.set(src, 0); // remaining bytes already zero
  return out;
}

/// Encode u64 as 32-byte LE Fr-canonical buffer (mirror of Move's
/// `pool_id_to_fr_bytes`). Output is little-endian, 8 active bytes + 24 zeros.
export function u64ToFieldLe32(n: bigint): Uint8Array {
  if (n < 0n || n >= (1n << 64n)) {
    throw new Error(`u64ToFieldLe32: out of range: ${n}`);
  }
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/// Encode u8 as 32-byte LE Fr-canonical buffer (mirror of Move's
/// `chain_id_to_fr_bytes`).
export function u8ToFieldLe32(n: number): Uint8Array {
  if (n < 0 || n > 0xff || !Number.isInteger(n)) {
    throw new Error(`u8ToFieldLe32: invalid u8: ${n}`);
  }
  const out = new Uint8Array(32);
  out[0] = n;
  return out;
}

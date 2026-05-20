export type HexString = string;

export function stripHexPrefix(hex: HexString): string {
  return hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
}

export function normalizeHex(hex: HexString): string {
  const raw = stripHexPrefix(hex).toLowerCase();
  if (raw.length % 2 !== 0) {
    throw new Error("hex string must have an even number of nibbles");
  }
  if (!/^[0-9a-f]*$/.test(raw)) {
    throw new Error("hex string contains non-hex characters");
  }
  return raw;
}

export function hexToBytes(hex: HexString): Uint8Array {
  const raw = normalizeHex(hex);
  const out = new Uint8Array(raw.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(raw.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array, withPrefix = false): string {
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return withPrefix ? `0x${hex}` : hex;
}

export function expectByteLength(
  name: string,
  bytes: Uint8Array,
  expected: number,
): void {
  if (bytes.length !== expected) {
    throw new Error(`${name}: expected ${expected} bytes, got ${bytes.length}`);
  }
}

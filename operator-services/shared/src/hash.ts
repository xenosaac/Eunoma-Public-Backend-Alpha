import { createHash, randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import type * as JsSha3 from "js-sha3";

const require = createRequire(import.meta.url);
const { keccak_256 } = require("js-sha3") as typeof JsSha3;

export function sha3_256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha3-256").update(bytes).digest());
}

export function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

export function keccak256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(keccak_256.arrayBuffer(bytes));
}

export function randomBytes32(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

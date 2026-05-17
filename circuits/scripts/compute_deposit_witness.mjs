#!/usr/bin/env node
// =============================================================================================
// V2 deposit-binding circuit witness builder.
//
// Reads raw depositor inputs (nullifier, secret, amount, deposit_blind hex) + chain-derived
// public Fr values (asset_id, vault_addr_hash) and writes a circom witness JSON file
// matching the public-inputs-in-declaration-order shape expected by
// `operator-services/scripts/local_generate_deposit_proof.mjs`.
//
// Witness shape (deposit_binding.circom, nPublic=4):
//   {
//     "commitment":      "<decimal Fr>",   // public (computed)
//     "amount_tag":      "<decimal Fr>",   // public (computed)
//     "asset_id":        "<decimal Fr>",   // public (provided)
//     "vault_addr_hash": "<decimal Fr>",   // public (provided)
//     "nullifier":       "<decimal Fr>",   // private
//     "secret":          "<decimal Fr>",   // private
//     "amount":          "<decimal u64>",  // private
//     "deposit_blind":   "<decimal Fr>"    // private (V3 W3: blinding factor for amount_tag)
//   }
//
// commitment + amount_tag are computed via the same compose5() recipe the circuit uses:
//   compose5(a,b,c,d,e) = hash_2(hash_3(a,b,c), hash_2(d,e))
// where hash_2 / hash_3 are circomlibjs's reference Poseidon BN254 (byte-identical to
// `aptos_std::poseidon_bn254`).
//
// CHAIN_ID and POOL_ID are hardcoded compile-time constants in the circuit (Phase F W3):
//   CHAIN_ID = 2 (Aptos testnet), POOL_ID = 0 (frozen pool).
// They participate in compose5 inside this helper (so the off-chain commitment matches the
// in-circuit computation) but are NOT part of the witness JSON.
//
// Args:
//   --nullifier-hex      0x-prefixed 32-byte LE Fr
//   --secret-hex         0x-prefixed 32-byte LE Fr
//   --amount             decimal u64 (octas for APT)
//   --deposit-blind-hex  0x-prefixed 32-byte LE Fr
//   --asset-id-hex       0x-prefixed 32-byte LE Fr (VaultPublicInputsV2.asset_id_fr)
//   --vault-addr-hash-hex 0x-prefixed 32-byte LE Fr (VaultPublicInputsV2.vault_addr_hash_fr)
//   --output PATH        path to write witness JSON
//
// Also emits the computed commitment + amount_tag to stdout as JSON for the caller's audit.
// =============================================================================================
import { writeFileSync } from "node:fs";
import { buildPoseidon } from "circomlibjs";

const args = process.argv.slice(2);
function arg(name) {
  const idx = args.indexOf(name);
  if (idx < 0 || idx + 1 >= args.length) {
    console.error(`missing required arg: ${name}`);
    process.exit(2);
  }
  return args[idx + 1];
}

const nullifierHex = arg("--nullifier-hex");
const secretHex = arg("--secret-hex");
const amountStr = arg("--amount");
const depositBlindHex = arg("--deposit-blind-hex");
const assetIdHex = arg("--asset-id-hex");
const vaultAddrHashHex = arg("--vault-addr-hash-hex");
const outputPath = arg("--output");

const CHAIN_ID = 2;
const POOL_ID = 0;

function hexToLe32(hex) {
  const clean = String(hex).replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length !== 64) {
    throw new Error(`expected 32-byte hex (64 chars), got "${hex}" (${clean.length} chars)`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function u64ToLe32(decStr) {
  let n = BigInt(decStr);
  if (n < 0n || n >= 1n << 64n) {
    throw new Error(`u64 out of range: ${decStr}`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function u8ToLe32(value) {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    throw new Error(`u8 out of range: ${value}`);
  }
  const out = new Uint8Array(32);
  out[0] = value;
  return out;
}

function le32ToDec(buf) {
  let n = 0n;
  for (let i = buf.length - 1; i >= 0; i -= 1) {
    n = (n << 8n) | BigInt(buf[i]);
  }
  return n.toString();
}

const poseidon = await buildPoseidon();
const F = poseidon.F;

function frFromLe(le32) {
  return F.fromRprLE(le32, 0);
}

function frToLe(el) {
  const out = new Uint8Array(32);
  F.toRprLE(out, 0, el);
  return out;
}

function hash2(a, b) {
  return frToLe(poseidon([frFromLe(a), frFromLe(b)]));
}

function hash3(a, b, c) {
  return frToLe(poseidon([frFromLe(a), frFromLe(b), frFromLe(c)]));
}

function compose5(a, b, c, d, e) {
  return hash2(hash3(a, b, c), hash2(d, e));
}

const nullifierLe = hexToLe32(nullifierHex);
const secretLe = hexToLe32(secretHex);
const depositBlindLe = hexToLe32(depositBlindHex);
const assetIdLe = hexToLe32(assetIdHex);
const vaultAddrHashLe = hexToLe32(vaultAddrHashHex);
const amountLe = u64ToLe32(amountStr);
const chainIdLe = u8ToLe32(CHAIN_ID);
const poolIdLe = u8ToLe32(POOL_ID);

// commitment = compose5(nullifier, secret, asset_id, amount, POOL_ID)
const commitmentLe = compose5(nullifierLe, secretLe, assetIdLe, amountLe, poolIdLe);
// amount_tag = compose5(amount, deposit_blind, asset_id, vault_addr_hash, CHAIN_ID)
const amountTagLe = compose5(
  amountLe,
  depositBlindLe,
  assetIdLe,
  vaultAddrHashLe,
  chainIdLe,
);

const witness = {
  commitment: le32ToDec(commitmentLe),
  amount_tag: le32ToDec(amountTagLe),
  asset_id: le32ToDec(assetIdLe),
  vault_addr_hash: le32ToDec(vaultAddrHashLe),
  nullifier: le32ToDec(nullifierLe),
  secret: le32ToDec(secretLe),
  amount: amountStr,
  deposit_blind: le32ToDec(depositBlindLe),
};

writeFileSync(outputPath, JSON.stringify(witness, null, 2) + "\n");

function toHex(buf) {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}

console.log(
  JSON.stringify(
    {
      ok: true,
      witnessPath: outputPath,
      commitmentHex: toHex(commitmentLe),
      amountTagHex: toHex(amountTagLe),
    },
    null,
    2,
  ),
);

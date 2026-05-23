#!/usr/bin/env node
// =============================================================================================
// V2 deposit-binding circuit witness builder — A6 amount_p binding (2026-05-23).
//
// Reads raw depositor inputs + chain-derived public Fr values + amount_p (4 × 32B Ristretto
// compressed Pedersen commitments of amount chunks, computed off-circuit by SDK with
// deterministic HKDF(secret) randomness) and writes a circom witness JSON matching
// `circuits/deposit_binding.circom` (A6: 5 publics, 11 privates).
//
// Witness shape (matches input keys the circuit declares):
//   {
//     // publics (5, in declaration order):
//     "commitment":      "<decimal Fr>",
//     "amount_tag":      "<decimal Fr>",
//     "asset_id":        "<decimal Fr>",
//     "vault_addr_hash": "<decimal Fr>",
//     "amount_p_digest": "<decimal Fr>",
//     // privates (11):
//     "nullifier":       "<decimal Fr>",
//     "secret":          "<decimal Fr>",
//     "deposit_blind":   "<decimal Fr>",
//     "amount_p_limbs":  ["<decimal>", ...8]   // 4 × 32B amount_p split into 2 × 16B LE limbs each
//   }
//
// commitment + amount_tag are computed via the same Compose5() recipe the circuit uses:
//   compose5(a,b,c,d,e) = hash_2(hash_3(a,b,c), hash_2(d,e))
// commitment       = Compose5(nullifier, secret, asset_id, amount_p_digest, POOL_ID)
// amount_tag       = Compose5(amount_p_digest, deposit_blind, asset_id, vault_addr_hash, CHAIN_ID)
// amount_p_digest  = Poseidon8(amount_p_limbs[0..7])  where limbs are 2 × 128-bit halves of
//                    each compressed Ristretto point (4 × 32B = 8 × 16B = 8 BN254 Fr safely).
//
// Args:
//   --nullifier-hex      0x-prefixed 32-byte LE Fr
//   --secret-hex         0x-prefixed 32-byte LE Fr
//   --amount-p-hex       128 hex chars (4 × 32B amount_p compressed Ristretto, concatenated)
//                        OR 4 separate flags. Caller (orchestrator) computes via SDK
//                        ConfidentialTransfer.create with transferAmountRandomness = HKDF(secret).
//   --deposit-blind-hex  0x-prefixed 32-byte LE Fr
//   --asset-id-hex       0x-prefixed 32-byte LE Fr (VaultPublicInputsV2.asset_id_fr)
//   --vault-addr-hash-hex 0x-prefixed 32-byte LE Fr (VaultPublicInputsV2.vault_addr_hash_fr)
//   --output PATH        path to write witness JSON
//
// Emits commitment + amount_tag + amount_p_digest to stdout as JSON for the caller's audit.
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
const amountPHex = arg("--amount-p-hex");
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

// Parse 4 × 32B amount_p (128 hex chars total) into 8 × 16B little-endian limbs.
// Each limb is a BigInt < 2^128 (fits BN254 Fr trivially since 2^128 << 2^253.5).
// Order: [amount_p[0]_lo, amount_p[0]_hi, amount_p[1]_lo, amount_p[1]_hi, ...]
// where _lo = bytes[0..16] and _hi = bytes[16..32], both little-endian.
function amountPHexToLimbs(amountPHex) {
  const clean = String(amountPHex).replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length !== 256) {
    throw new Error(`--amount-p-hex must be 128-byte hex (256 chars; 4 × 32B amount_p concat), got ${clean.length} chars`);
  }
  const limbs = [];
  for (let pointIdx = 0; pointIdx < 4; pointIdx += 1) {
    const pointStart = pointIdx * 64; // 32B = 64 hex chars
    // Low 16 bytes (LE)
    let lo = 0n;
    for (let b = 0; b < 16; b += 1) {
      const byte = BigInt(parseInt(clean.slice(pointStart + b * 2, pointStart + b * 2 + 2), 16));
      lo |= byte << (8n * BigInt(b));
    }
    // High 16 bytes (LE)
    let hi = 0n;
    for (let b = 0; b < 16; b += 1) {
      const byte = BigInt(
        parseInt(clean.slice(pointStart + 32 + b * 2, pointStart + 32 + b * 2 + 2), 16),
      );
      hi |= byte << (8n * BigInt(b));
    }
    limbs.push(lo, hi);
  }
  return limbs;
}

function bigToLe32(value) {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
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

function hash8(le32x8) {
  const inputs = le32x8.map((b) => frFromLe(b));
  return frToLe(poseidon(inputs));
}

function compose5(a, b, c, d, e) {
  return hash2(hash3(a, b, c), hash2(d, e));
}

const nullifierLe = hexToLe32(nullifierHex);
const secretLe = hexToLe32(secretHex);
const depositBlindLe = hexToLe32(depositBlindHex);
const assetIdLe = hexToLe32(assetIdHex);
const vaultAddrHashLe = hexToLe32(vaultAddrHashHex);
const chainIdLe = u8ToLe32(CHAIN_ID);
const poolIdLe = u8ToLe32(POOL_ID);

// A6: parse amount_p (4 × 32B Ristretto) into 8 × 16B LE limbs.
const amountPLimbsBig = amountPHexToLimbs(amountPHex);
const amountPLimbsLe = amountPLimbsBig.map(bigToLe32);
const amountPDigestLe = hash8(amountPLimbsLe);

// commitment = Compose5(nullifier, secret, asset_id, amount_p_digest, POOL_ID)
const commitmentLe = compose5(nullifierLe, secretLe, assetIdLe, amountPDigestLe, poolIdLe);
// amount_tag = Compose5(amount_p_digest, deposit_blind, asset_id, vault_addr_hash, CHAIN_ID)
const amountTagLe = compose5(
  amountPDigestLe,
  depositBlindLe,
  assetIdLe,
  vaultAddrHashLe,
  chainIdLe,
);

const witness = {
  // publics (declaration order, must match circom file's component main public list)
  commitment: le32ToDec(commitmentLe),
  amount_tag: le32ToDec(amountTagLe),
  asset_id: le32ToDec(assetIdLe),
  vault_addr_hash: le32ToDec(vaultAddrHashLe),
  amount_p_digest: le32ToDec(amountPDigestLe),
  // privates
  nullifier: le32ToDec(nullifierLe),
  secret: le32ToDec(secretLe),
  deposit_blind: le32ToDec(depositBlindLe),
  amount_p_limbs: amountPLimbsBig.map((b) => b.toString()),
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
      amountPDigestHex: toHex(amountPDigestLe),
    },
    null,
    2,
  ),
);

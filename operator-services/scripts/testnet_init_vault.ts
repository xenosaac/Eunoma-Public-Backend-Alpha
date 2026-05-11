/**
 * Phase 3 — init_vault_with_ca_registration on testnet (Gate 4d-bis).
 *
 * Generates a real registration sigma proof (proveRegistration from the
 * singular @aptos-labs/confidential-asset@1.1.1 package), keyed to the
 * vault resource-account address (NOT the bridge-admin), then submits the
 * bridge's entry function `init_vault_with_ca_registration` via the aptos
 * CLI shell-out.
 *
 * Why the resource address (not admin) for the sigma proof:
 * The bridge calls `confidential_asset::register_raw(&vault_signer, ...)`.
 * Inside `register_raw`, the framework derives `senderAddress` from the
 * passed `&signer`. So the sigma proof's bound `senderAddress` MUST be
 * `vault_addr = create_resource_account(admin, vault_seed).addr`, otherwise
 * the on-chain Fiat-Shamir check fails (E_INVALID_PROOF / a sigma-protocol
 * abort).
 *
 * Run: cd operator-services && npx tsx scripts/testnet_init_vault.ts
 *
 * After this returns OK:
 *   testnet_state.json.vault is populated with vault_addr + init_tx + gas + ek_pub.
 *   .vault-ek.json holds the (private) TwistedEd25519 decryption key.
 */

import {
  Account,
  Ed25519PrivateKey,
  PrivateKey,
  PrivateKeyVariants,
  AccountAddress,
  Aptos,
  AptosConfig,
  Network,
} from '@aptos-labs/ts-sdk';
import {
  TwistedEd25519PrivateKey,
  proveRegistration,
} from '@aptos-labs/confidential-asset';
import { sha3_256 } from '@noble/hashes/sha3';
import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadOperatorKeys, loadSecretHex } from '../shared/src/secrets.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STATE_PATH = path.join(__dirname, 'testnet_state.json');

const BRIDGE_ADDR =
  '0x8268f56bdd9814d1cc925b861eaa1203d41c7f5425b3d2df887f618ffeb24820';
const APT_METADATA = '0xa'; // testnet APT FA metadata
const VAULT_SEED_HEX = '65756e6f6d612d627269646765'; // "eunoma-bridge"
const CHAIN_ID = 2; // testnet
const ATTESTATION_THRESHOLD = 4;
const MAIN_OPERATOR_INDEX = 0;

function hex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(s: string): Uint8Array {
  const h = s.startsWith('0x') ? s.slice(2) : s;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

/**
 * Compute the resource-account address per Aptos `create_resource_account`:
 *   addr = sha3_256(bcs(source_addr) || seed || 0xFF)
 * (DERIVE_RESOURCE_ACCOUNT_SCHEME = 255, see aptos-framework/sources/account/account.move)
 */
function deriveResourceAccountAddress(sourceAddrHex: string, seedHex: string): Uint8Array {
  const src = fromHex(sourceAddrHex);
  if (src.length !== 32) throw new Error(`expected 32-byte source addr; got ${src.length}`);
  const seed = fromHex(seedHex);
  const buf = new Uint8Array(src.length + seed.length + 1);
  buf.set(src, 0);
  buf.set(seed, src.length);
  buf[buf.length - 1] = 0xff;
  return sha3_256(buf);
}

async function main() {
  // ---- 1. Load operator keys from env (OPERATOR_KEYS_JSON_B64) ----
  const operatorKeys = loadOperatorKeys();
  const operatorPubkeysHex = operatorKeys.map((k) => k.public_key.replace(/^0x/, ''));

  // ---- 2. Compute vault resource address ----
  const vaultAddrBytes = deriveResourceAccountAddress(BRIDGE_ADDR, VAULT_SEED_HEX);
  const vaultAddrHex = '0x' + hex(vaultAddrBytes);
  console.log(`vault resource-account addr = ${vaultAddrHex}`);

  // ---- 3. Load vault TwistedEd25519 keypair from env ----
  // For first-time init: generate via `npx tsx scripts/generate_vault_ek.ts`,
  // add VAULT_DECRYPTION_KEY_HEX to .env, then re-run this script.
  const vaultDk = new TwistedEd25519PrivateKey(loadSecretHex('VAULT_DECRYPTION_KEY_HEX', 32));
  console.log('loaded vault TwistedEd25519 keypair from env');
  const vaultEkBytes = vaultDk.publicKey().toUint8Array();
  const vaultEkHex = hex(vaultEkBytes);
  console.log(`vault_ek (twisted-ed25519 pub) = 0x${vaultEkHex}`);

  // ---- 4. Generate registration sigma proof bound to (vault_addr, APT_metadata, chain_id) ----
  // proveRegistration is pure JS (no WASM) — see chunk-ZQARKQT2.mjs
  const aptMetadataBytes = AccountAddress.from(APT_METADATA).toUint8Array();
  const sigmaProof = proveRegistration({
    dk: vaultDk,
    senderAddress: vaultAddrBytes, // CRITICAL: vault address, NOT bridge-admin
    tokenAddress: aptMetadataBytes,
    chainId: CHAIN_ID,
  });
  console.log(
    `sigma proof: ${sigmaProof.commitment.length} commitment(s), ${sigmaProof.response.length} response(s)`,
  );

  // Sanity: registration sigma proof shape on testnet is 1 commitment + 1 response.
  if (sigmaProof.commitment.length !== 1 || sigmaProof.response.length !== 1) {
    console.warn(
      `WARN: unexpected proof shape (commitment=${sigmaProof.commitment.length}, response=${sigmaProof.response.length}); on-chain framework may abort. Proceeding.`,
    );
  }

  const sigmaCommHex = sigmaProof.commitment.map((b) => hex(b));
  const sigmaRespHex = sigmaProof.response.map((b) => hex(b));

  // ---- 5. Build aptos CLI --json-file payload ----
  const cliJson = {
    function_id: `${BRIDGE_ADDR}::eunoma_bridge::init_vault_with_ca_registration`,
    type_args: [],
    args: [
      { type: 'address', value: BRIDGE_ADDR }, // main_operator_addr — using bridge-admin as collator addr (not used for verify, just routing)
      { type: 'address', value: APT_METADATA }, // asset_type Object<Metadata>
      { type: 'hex', value: operatorPubkeysHex.map((h) => '0x' + h) }, // operator_pubkeys vector<vector<u8>>
      { type: 'u64', value: String(MAIN_OPERATOR_INDEX) },
      { type: 'u64', value: String(ATTESTATION_THRESHOLD) },
      { type: 'hex', value: '0x' + VAULT_SEED_HEX }, // vault_seed
      { type: 'hex', value: '0x' + vaultEkHex }, // vault_ek
      { type: 'hex', value: sigmaCommHex.map((h) => '0x' + h) }, // sigma comm vec<vec<u8>>
      { type: 'hex', value: sigmaRespHex.map((h) => '0x' + h) }, // sigma resp vec<vec<u8>>
    ],
  };

  const argsPath = path.join(__dirname, 'init_vault_args.json');
  fs.writeFileSync(argsPath, JSON.stringify(cliJson, null, 2));
  console.log(`wrote CLI args → ${argsPath}`);

  // ---- 6. Simulate FIRST via local-session (zero gas) ----
  console.log('\n[simulate] aptos move run --local ...');
  const simCmd = [
    'aptos',
    'move',
    'run',
    '--profile eunoma-admin',
    `--json-file '${argsPath}'`,
    '--local',
    '--assume-yes',
  ].join(' ');
  let simOut = '';
  try {
    simOut = execSync(simCmd, { encoding: 'utf-8', cwd: path.dirname(__dirname) });
  } catch (e: any) {
    simOut = (e.stdout || '') + (e.stderr || '');
    console.error(simOut);
    throw new Error('simulation failed — see output above');
  }
  console.log(simOut);
  // Parse simulation result; CLI prefixes "Simulating transaction locally..." text before JSON.
  const simJsonStart = simOut.indexOf('{');
  const simParsed = JSON.parse(simOut.slice(simJsonStart));
  if (simParsed.Result?.success === false) {
    throw new Error(`simulation reverted: ${JSON.stringify(simParsed.Result, null, 2)}`);
  }
  const simGas = simParsed.Result?.gas_used;
  console.log(`simulation OK — estimated gas = ${simGas}`);

  // ---- 7. Submit on-chain ----
  console.log('\n[submit] aptos move run ...');
  const subCmd = [
    'aptos',
    'move',
    'run',
    '--profile eunoma-admin',
    `--json-file '${argsPath}'`,
    '--assume-yes',
  ].join(' ');
  let subOut = '';
  try {
    subOut = execSync(subCmd, { encoding: 'utf-8', cwd: path.dirname(__dirname) });
  } catch (e: any) {
    subOut = (e.stdout || '') + (e.stderr || '');
    console.error(subOut);
    throw new Error('submission failed — see output above');
  }
  console.log(subOut);
  const subJsonStart = subOut.indexOf('{');
  const subParsed = JSON.parse(subOut.slice(subJsonStart));
  if (subParsed.Result?.success !== true) {
    throw new Error(`submission failed: ${JSON.stringify(subParsed.Result, null, 2)}`);
  }
  const txHash = subParsed.Result.transaction_hash;
  const gasUsed = subParsed.Result.gas_used;
  const gasUnitPrice = subParsed.Result.gas_unit_price;
  console.log(`\nINIT VAULT OK`);
  console.log(`  tx hash = ${txHash}`);
  console.log(`  gas_used = ${gasUsed}`);
  console.log(`  gas_unit_price = ${gasUnitPrice}`);

  // ---- 8. Persist to state ----
  const state = JSON.parse(fs.readFileSync(STATE_PATH, 'utf-8'));
  state.vault = state.vault || {};
  state.vault.address = vaultAddrHex;
  state.vault.asset_type = APT_METADATA;
  state.vault.init_tx = txHash;
  state.vault.init_gas_used = gasUsed;
  state.vault.init_gas_unit_price = gasUnitPrice;
  state.vault.main_operator_index = MAIN_OPERATOR_INDEX;
  state.vault.attestation_threshold = ATTESTATION_THRESHOLD;
  state.vault.operator_pubkeys_hex = operatorPubkeysHex;
  state.vault.vault_seed_hex = '0x' + VAULT_SEED_HEX;
  state.vault.vault_ek_hex = vaultEkHex;
  fs.writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));
  console.log(`\npersisted to ${STATE_PATH}`);
}

main().catch((e) => {
  console.error('FAILED:', e.message || e);
  process.exit(1);
});

/**
 * Phase 5 — register bridge-user's ConfidentialAsset store on testnet APT (FA 0xa)
 *           and veil 0.5 APT into pending balance via `deposit`. (Gate 4d-bis)
 *
 * Uses singular @aptos-labs/confidential-asset@1.1.1 (peers v6 SDK). Mounts
 * the CA helper at the testnet default `0x1::confidential_asset` module.
 *
 * Persists to:
 *   .user-ek.json         — bridge-user TwistedEd25519 keypair (gitignored)
 *   testnet_state.json    — register_tx, veil_deposit_tx, gas
 *
 * Run: cd operator-services && npx tsx scripts/testnet_register_user_ca.ts
 */

import {
  Account,
  Aptos,
  AptosConfig,
  Network,
  Ed25519PrivateKey,
  PrivateKey,
  PrivateKeyVariants,
} from '@aptos-labs/ts-sdk';
import {
  ConfidentialAsset,
  TwistedEd25519PrivateKey,
} from '@aptos-labs/confidential-asset';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadSecretHex } from '../shared/src/secrets.js';
import { targetDeployId, updateTargetDeploy } from './_lib/state.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEPLOY_ID = targetDeployId();

const APT_METADATA = '0xa';
const VEIL_AMOUNT_OCTAS = 50_000_000n; // 0.5 APT

// Read aptos config to get bridge-user private key
function getBridgeUserAccount(): Account {
  const configPath = path.join(__dirname, '..', '..', '.aptos', 'config.yaml');
  const yaml = fs.readFileSync(configPath, 'utf-8');
  // Simple parse: find bridge-user block, then the ed25519-priv-0x...
  const userMatch = yaml.match(
    /bridge-user:[\s\S]*?private_key:\s*(?:"|')?([^\s"']+)(?:"|')?/,
  );
  if (!userMatch) throw new Error('cannot find bridge-user private_key in config');
  let raw = userMatch[1].trim();
  // Strip aip-80 prefix if present
  raw = raw.replace(/^ed25519-priv-/, '');
  const pk = new Ed25519PrivateKey(raw);
  return Account.fromPrivateKey({ privateKey: pk });
}

async function main() {
  // Bridge-user account (already funded with 5 APT in Gate 4d).
  const userAccount = getBridgeUserAccount();
  console.log(`bridge-user addr = ${userAccount.accountAddress.toString()}`);

  // Set up Aptos client + CA helper.
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const ca = new ConfidentialAsset({ config: aptos.config });

  // ---- 1. Load user TwistedEd25519 keypair from env (generate via generate_twisted_ed25519_keypair.ts) ----
  const userDk = new TwistedEd25519PrivateKey(loadSecretHex('USER_ENCRYPTION_KEY_HEX', 32));
  console.log(`user_ek (twisted-ed25519 pub) = ${userDk.publicKey().toString()}`);

  // ---- 2. Check current state ----
  const alreadyRegistered = await ca.hasUserRegistered({
    accountAddress: userAccount.accountAddress,
    tokenAddress: APT_METADATA,
  });
  console.log(`hasUserRegistered = ${alreadyRegistered}`);

  let registerTxHash: string | null = null;
  let registerGas: number | null = null;
  if (!alreadyRegistered) {
    // ---- 3. Register CA balance ----
    console.log('\n[register] aptos.confidentialAsset.registerBalance ...');
    // W3 cap maxGasAmount — SDK default is 2M which exceeds fresh-address balance.
    const regResp = await ca.registerBalance({
      signer: userAccount,
      tokenAddress: APT_METADATA,
      decryptionKey: userDk,
      options: { maxGasAmount: 200_000, gasUnitPrice: 100 },
    });
    console.log(`  tx = ${regResp.hash}`);
    console.log(`  success = ${regResp.success}`);
    if (!regResp.success) {
      throw new Error(`registerBalance failed: ${regResp.vm_status}`);
    }
    registerTxHash = regResp.hash;
    registerGas = Number(regResp.gas_used ?? 0);
    console.log(`  gas_used = ${registerGas}`);
  } else {
    console.log('skipping register; user already has CA store');
  }

  // ---- 4. Veil 0.5 APT into pending balance ----
  console.log('\n[deposit] aptos.confidentialAsset.deposit (veil 0.5 APT) ...');
  const depResp = await ca.deposit({
    signer: userAccount,
    tokenAddress: APT_METADATA,
    amount: VEIL_AMOUNT_OCTAS,
    options: { maxGasAmount: 200_000, gasUnitPrice: 100 },
  });
  console.log(`  tx = ${depResp.hash}`);
  console.log(`  success = ${depResp.success}`);
  if (!depResp.success) {
    throw new Error(`deposit (veil) failed: ${depResp.vm_status}`);
  }
  const veilTxHash = depResp.hash;
  const veilGas = Number(depResp.gas_used ?? 0);
  console.log(`  gas_used = ${veilGas}`);

  // ---- 5. Verify balance > 0 ----
  // Pending balance after first deposit; needs rollover to be in `available`.
  // For our purposes we just want to confirm the veil registered.
  console.log('\n[verify] CA pending balance after veil...');
  // Skip getBalance — requires WASM; we'll just trust the deposit tx.

  // ---- 6. Persist to staged deploy slot ----
  updateTargetDeploy((d) => {
    d.user_ca ??= {};
    d.user_ca.user_address = userAccount.accountAddress.toString();
    d.user_ca.asset_type = APT_METADATA;
    d.user_ca.user_decryption_key_secret_hex = userDk.toString();
    d.user_ca.user_encryption_key_pub_hex = userDk.publicKey().toString();
    if (registerTxHash) {
      d.user_ca.register_tx = registerTxHash;
      d.user_ca.register_gas = registerGas;
    }
    d.user_ca.veil_deposit_tx = veilTxHash;
    d.user_ca.veil_deposit_gas = veilGas;
    d.user_ca.veil_amount_octas = VEIL_AMOUNT_OCTAS.toString();
  });
  console.log(`\n[state] deploys.${DEPLOY_ID}.user_ca written`);
}

main().catch((e) => {
  console.error('FAILED:', e.message || e);
  if (e.stack) console.error(e.stack);
  process.exit(1);
});

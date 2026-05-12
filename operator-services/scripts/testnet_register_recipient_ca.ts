/**
 * Phase 2.X / W.1 — register bridge-spare's ConfidentialAsset store on testnet
 *                  APT (FA 0xa) so it can receive vault → recipient transfers.
 *
 * Mirror of testnet_register_user_ca.ts, swap profile = bridge-spare. NO veil
 * deposit step — recipient just needs an empty CA store ready to receive.
 *
 * Persists to:
 *   .recipient-ek.json    — bridge-spare TwistedEd25519 keypair (gitignored)
 *   testnet_state.json    — state.recipient_ca block
 *
 * Run: cd operator-services && npx tsx scripts/testnet_register_recipient_ca.ts
 */

import {
  Account,
  Aptos,
  AptosConfig,
  Network,
  Ed25519PrivateKey,
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

function getBridgeSpareAccount(): Account {
  const configPath = path.join(__dirname, '..', '..', '.aptos', 'config.yaml');
  const yaml = fs.readFileSync(configPath, 'utf-8');
  const m = yaml.match(
    /bridge-spare:[\s\S]*?private_key:\s*(?:"|')?([^\s"']+)(?:"|')?/,
  );
  if (!m) throw new Error('cannot find bridge-spare private_key in config');
  const raw = m[1].trim().replace(/^ed25519-priv-/, '');
  return Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(raw) });
}

async function main() {
  const recipientAccount = getBridgeSpareAccount();
  console.log(`bridge-spare addr = ${recipientAccount.accountAddress.toString()}`);

  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const ca = new ConfidentialAsset({ config: aptos.config });

  // ---- 1. Load recipient TwistedEd25519 keypair from env (generate via generate_twisted_ed25519_keypair.ts) ----
  const recipientDk = new TwistedEd25519PrivateKey(loadSecretHex('RECIPIENT_ENCRYPTION_KEY_HEX', 32));
  console.log(`recipient_ek (twisted-ed25519 pub) = ${recipientDk.publicKey().toString()}`);

  // ---- 2. Check current state ----
  const alreadyRegistered = await ca.hasUserRegistered({
    accountAddress: recipientAccount.accountAddress,
    tokenAddress: APT_METADATA,
  });
  console.log(`hasUserRegistered = ${alreadyRegistered}`);

  let registerTxHash: string | null = null;
  let registerGas: number | null = null;
  if (!alreadyRegistered) {
    // ---- 3. Register CA balance ----
    console.log('\n[register] aptos.confidentialAsset.registerBalance ...');
    const regResp = await ca.registerBalance({
      signer: recipientAccount,
      tokenAddress: APT_METADATA,
      decryptionKey: recipientDk,
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
    console.log('skipping register; recipient already has CA store');
  }

  // ---- 4. Persist to staged deploy slot ----
  updateTargetDeploy((d) => {
    d.recipient_ca ??= {};
    d.recipient_ca.recipient_address = recipientAccount.accountAddress.toString();
    d.recipient_ca.asset_type = APT_METADATA;
    d.recipient_ca.recipient_decryption_key_secret_hex = recipientDk.toString();
    d.recipient_ca.recipient_encryption_key_pub_hex = recipientDk.publicKey().toString();
    if (registerTxHash) {
      d.recipient_ca.register_tx = registerTxHash;
      d.recipient_ca.register_gas = registerGas;
    }
  });
  console.log(`\n[state] deploys.${DEPLOY_ID}.recipient_ca written`);
}

main().catch((e) => {
  console.error('FAILED:', e.message || e);
  if (e.stack) console.error(e.stack);
  process.exit(1);
});

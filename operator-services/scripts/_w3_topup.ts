/**
 * W.3 helper: top up bridge-user CA balance (veil + rollover) so
 * testnet_deposit_e2e.ts can spend `available` for B.5 deposit.
 *
 * Veils TOPUP_OCTAS (default 10_000_000 = 0.1 APT) plain APT into user.pending,
 * then rolls user.pending → user.available.
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

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const APT_METADATA = '0xa';
const TOPUP_OCTAS = process.env.TOPUP_OCTAS ? BigInt(process.env.TOPUP_OCTAS) : 10_000_000n;
const BRIDGE_USER_PROFILE = process.env.BRIDGE_USER_PROFILE ?? 'bridge-user';

function loadAccount(profile: string): Account {
  const cfgPath = path.join(__dirname, '..', '..', '.aptos', 'config.yaml');
  const yaml = fs.readFileSync(cfgPath, 'utf-8');
  const m = yaml.match(new RegExp(`${profile}:[\\s\\S]*?private_key:\\s*(?:"|')?([^\\s"']+)(?:"|')?`));
  if (!m) throw new Error(`cannot find ${profile}`);
  const raw = m[1].trim().replace(/^ed25519-priv-/, '');
  return Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(raw) });
}

async function main() {
  const user = loadAccount(BRIDGE_USER_PROFILE);
  console.log(`bridge-user profile = ${BRIDGE_USER_PROFILE}`);
  console.log(`bridge-user = ${user.accountAddress.toString()}`);
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const ca = new ConfidentialAsset({ config: aptos.config });
  const userDk = new TwistedEd25519PrivateKey(loadSecretHex('USER_ENCRYPTION_KEY_HEX', 32));

  const balBefore = await ca.getBalance({
    accountAddress: user.accountAddress,
    tokenAddress: APT_METADATA,
    decryptionKey: userDk,
  });
  console.log(`pre  veil: pending=${balBefore.pending.getAmount()} available=${balBefore.available.getAmount()}`);

  console.log(`\n[step 1] veil ${TOPUP_OCTAS} octas plain APT → user.pending ...`);
  const veilResp = await ca.deposit({
    signer: user,
    tokenAddress: APT_METADATA,
    amount: TOPUP_OCTAS,
  });
  console.log(`  tx = ${veilResp.hash}, success=${veilResp.success}, gas=${veilResp.gas_used}`);
  if (!veilResp.success) throw new Error(`veil failed: ${veilResp.vm_status}`);

  console.log(`\n[step 2] rollover user.pending → user.available ...`);
  const rollResp = await ca.rolloverPendingBalance({
    signer: user,
    tokenAddress: APT_METADATA,
    checkNormalized: false,
  });
  const last = rollResp[rollResp.length - 1];
  console.log(`  tx = ${last.hash}, success=${last.success}, gas=${last.gas_used}`);
  if (!last.success) throw new Error(`rollover failed: ${last.vm_status}`);

  const balAfter = await ca.getBalance({
    accountAddress: user.accountAddress,
    tokenAddress: APT_METADATA,
    decryptionKey: userDk,
  });
  console.log(`\npost veil+roll: pending=${balAfter.pending.getAmount()} available=${balAfter.available.getAmount()}`);
  console.log(`✓ user CA topped up; testnet_deposit_e2e.ts can now spend ${balAfter.available.getAmount()} octas`);
}
main().catch((e) => { console.error('FAIL:', e.message || e); process.exit(1); });

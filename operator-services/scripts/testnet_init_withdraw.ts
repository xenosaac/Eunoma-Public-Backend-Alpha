/**
 * Phase 2 / Gate 6 — admin entries to enable withdraw on testnet.
 * Run AFTER bridge package upgrade (compatible upgrade adding W.1 changes).
 *   1. publish_withdraw_proof_vk (with bytes from withdrawal_proof_vk.json)
 *   2. publish_prepared_withdraw_proof_vk (on-chain pairing + 2 negs)
 *   3. init_used_nullifiers_table
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';
import {
  Account,
  Aptos,
  AptosConfig,
  Network,
  Ed25519PrivateKey,
} from '@aptos-labs/ts-sdk';
import { loadSecretHex } from '../shared/src/secrets.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BRIDGE_ADDR = '0x8268f56bdd9814d1cc925b861eaa1203d41c7f5425b3d2df887f618ffeb24820';

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

async function main() {
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const admin = Account.fromPrivateKey({
    privateKey: new Ed25519PrivateKey(hexToBytes(loadSecretHex('ADMIN_PRIVATE_KEY_HEX', 32))),
  });
  console.log(`admin = ${admin.accountAddress.toString()}`);

  // Extract VK
  const vkScript = path.resolve(__dirname, '..', '..', 'circuits', 'scripts', 'extract_withdraw_vk.js');
  const vkJson = JSON.parse(execSync(`node "${vkScript}"`, { encoding: 'utf-8' }));
  console.log('extracted VK: alpha_g1', vkJson.alpha_g1.length / 2, 'B; ic count', vkJson.ic.length);

  // === Tx 1: publish_withdraw_proof_vk ===
  console.log('\n[tx1] publish_withdraw_proof_vk ...');
  const args1 = [
    Array.from(hexToBytes(vkJson.alpha_g1)),
    Array.from(hexToBytes(vkJson.beta_g2)),
    Array.from(hexToBytes(vkJson.gamma_g2)),
    Array.from(hexToBytes(vkJson.delta_g2)),
    ...vkJson.ic.map((h: string) => Array.from(hexToBytes(h))),
  ];
  const tx1 = await aptos.transaction.build.simple({
    sender: admin.accountAddress,
    data: {
      function: `${BRIDGE_ADDR}::eunoma_bridge::publish_withdraw_proof_vk`,
      functionArguments: args1,
    },
    options: { maxGasAmount: 200_000, gasUnitPrice: 100 },
  });
  const sub1 = await aptos.signAndSubmitTransaction({ signer: admin, transaction: tx1 });
  const r1: any = await aptos.waitForTransaction({ transactionHash: sub1.hash });
  console.log(`  tx=${r1.hash} gas=${r1.gas_used} success=${r1.success}`);
  if (!r1.success) throw new Error(`tx1 failed: ${r1.vm_status}`);

  // === Tx 2: publish_prepared_withdraw_proof_vk ===
  console.log('\n[tx2] publish_prepared_withdraw_proof_vk ...');
  const tx2 = await aptos.transaction.build.simple({
    sender: admin.accountAddress,
    data: {
      function: `${BRIDGE_ADDR}::eunoma_bridge::publish_prepared_withdraw_proof_vk`,
      functionArguments: [],
    },
    options: { maxGasAmount: 300_000, gasUnitPrice: 100 },
  });
  const sub2 = await aptos.signAndSubmitTransaction({ signer: admin, transaction: tx2 });
  const r2: any = await aptos.waitForTransaction({ transactionHash: sub2.hash });
  console.log(`  tx=${r2.hash} gas=${r2.gas_used} success=${r2.success}`);
  if (!r2.success) throw new Error(`tx2 failed: ${r2.vm_status}`);

  // === Tx 3: init_used_nullifiers_table ===
  console.log('\n[tx3] init_used_nullifiers_table ...');
  const tx3 = await aptos.transaction.build.simple({
    sender: admin.accountAddress,
    data: {
      function: `${BRIDGE_ADDR}::eunoma_bridge::init_used_nullifiers_table`,
      functionArguments: [],
    },
    options: { maxGasAmount: 100_000, gasUnitPrice: 100 },
  });
  const sub3 = await aptos.signAndSubmitTransaction({ signer: admin, transaction: tx3 });
  const r3: any = await aptos.waitForTransaction({ transactionHash: sub3.hash });
  console.log(`  tx=${r3.hash} gas=${r3.gas_used} success=${r3.success}`);
  if (!r3.success) throw new Error(`tx3 failed: ${r3.vm_status}`);

  console.log('\n✓ all 3 admin txs success — withdraw infrastructure live on testnet');
}

main().catch((e) => { console.error('FATAL:', e); process.exit(1); });

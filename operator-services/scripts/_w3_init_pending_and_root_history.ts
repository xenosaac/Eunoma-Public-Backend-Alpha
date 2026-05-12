// W3 fresh-address init: pool_pending_queue::initialize +
//                         pool_pending_queue::initialize_commitment_index +
//                         pool_batch_root_update::initialize(empty_tree_root=ZERO32, chain_id=2, pool_id=ZERO32)
import { Account, Aptos, AptosConfig, Network, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import { loadSecretHex } from '../shared/src/secrets.js';
import { targetBridge, targetDeployId, updateTargetDeploy } from './_lib/state.js';

const BRIDGE_ADDR = targetBridge();
const DEPLOY_ID = targetDeployId();
const ZERO32 = Array.from(new Uint8Array(32));

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

async function callEntry(aptos: Aptos, admin: Account, fn: string, args: any[], maxGas = 100_000) {
  const tx = await aptos.transaction.build.simple({
    sender: admin.accountAddress,
    data: { function: `${BRIDGE_ADDR}::${fn}`, functionArguments: args },
    options: { maxGasAmount: maxGas, gasUnitPrice: 100 },
  });
  const sub = await aptos.signAndSubmitTransaction({ signer: admin, transaction: tx });
  const r: any = await aptos.waitForTransaction({ transactionHash: sub.hash, options: { checkSuccess: false } });
  console.log(`  ${fn}: tx=${r.hash} gas=${r.gas_used} success=${r.success} vm=${r.vm_status}`);
  if (!r.success) throw new Error(`${fn} failed: ${r.vm_status}`);
  return r;
}

async function main() {
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const admin = Account.fromPrivateKey({
    privateKey: new Ed25519PrivateKey(hexToBytes(loadSecretHex('ADMIN_PRIVATE_KEY_HEX', 32))),
  });
  console.log(`admin = ${admin.accountAddress.toString()}  target_deploy=${DEPLOY_ID}  bridge=${BRIDGE_ADDR}`);

  console.log('\n[1/3] pool_pending_queue::initialize');
  const r1 = await callEntry(aptos, admin, 'pool_pending_queue::initialize', []);

  console.log('\n[2/3] pool_pending_queue::initialize_commitment_index');
  const r2 = await callEntry(aptos, admin, 'pool_pending_queue::initialize_commitment_index', []);

  console.log('\n[3/3] pool_batch_root_update::initialize(empty_tree_root=ZERO32, chain_id=2, pool_id=ZERO32)');
  const r3 = await callEntry(aptos, admin, 'pool_batch_root_update::initialize', [ZERO32, 2, ZERO32], 150_000);

  updateTargetDeploy((d) => {
    d.publishes ??= {};
    d.publishes.pool_pending_queue_initialize = {
      tx: r1.hash, gas_used: Number(r1.gas_used), gas_unit_price: Number(r1.gas_unit_price ?? 100),
    };
    d.publishes.pool_pending_queue_init_commitment_index = {
      tx: r2.hash, gas_used: Number(r2.gas_used), gas_unit_price: Number(r2.gas_unit_price ?? 100),
    };
    d.publishes.pool_batch_root_update_initialize = {
      tx: r3.hash, gas_used: Number(r3.gas_used), gas_unit_price: Number(r3.gas_unit_price ?? 100),
    };
  });
  console.log(`\n[state] deploys.${DEPLOY_ID}.publishes.{pool_pending_queue_*,pool_batch_root_update_initialize} written`);
}
main().catch((e) => { console.error('FATAL:', e); process.exit(1); });

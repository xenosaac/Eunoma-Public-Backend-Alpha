// W3: roll the vault's CA pending balance into available so withdraw can spend it.
import { Account, Aptos, AptosConfig, Network, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import { loadSecretHex } from '../shared/src/secrets.js';
import { targetBridge, targetDeployId, updateTargetDeploy } from './_lib/state.js';

const BRIDGE_ADDR = targetBridge();
const DEPLOY_ID = targetDeployId();

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

async function main() {
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const op = Account.fromPrivateKey({
    privateKey: new Ed25519PrivateKey(hexToBytes(loadSecretHex('ADMIN_PRIVATE_KEY_HEX', 32))),
  });
  console.log(`main_operator = ${op.accountAddress.toString()}  target_deploy=${DEPLOY_ID}  bridge=${BRIDGE_ADDR}`);

  const tx = await aptos.transaction.build.simple({
    sender: op.accountAddress,
    data: { function: `${BRIDGE_ADDR}::eunoma_bridge::operator_rollover_vault_pending`, functionArguments: [] },
    options: { maxGasAmount: 200_000, gasUnitPrice: 100 },
  });
  const sub = await aptos.signAndSubmitTransaction({ signer: op, transaction: tx });
  const r: any = await aptos.waitForTransaction({ transactionHash: sub.hash, options: { checkSuccess: false } });
  console.log(`tx=${r.hash} gas=${r.gas_used} success=${r.success} vm=${r.vm_status}`);
  if (!r.success) throw new Error(`operator_rollover_vault_pending failed: ${r.vm_status}`);

  updateTargetDeploy((d) => {
    d.vault ??= {};
    d.vault.last_rollover_tx = r.hash;
    d.vault.last_rollover_gas = Number(r.gas_used);
  });
  console.log(`[state] deploys.${DEPLOY_ID}.vault.last_rollover_{tx,gas} written`);
}
main().catch((e) => { console.error('FATAL:', e); process.exit(1); });

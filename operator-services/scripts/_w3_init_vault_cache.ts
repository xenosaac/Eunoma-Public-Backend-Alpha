import { Account, Aptos, AptosConfig, Network, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import { loadSecretHex } from '../shared/src/secrets.js';

const BRIDGE_ADDR = '0x9c51607926e57b50c1963508863769821078ca46f42cd4f922659325e7546a5a';

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

  const tx = await aptos.transaction.build.simple({
    sender: admin.accountAddress,
    data: {
      function: `${BRIDGE_ADDR}::eunoma_bridge::init_vault_config_cache`,
      functionArguments: [],
    },
    options: { maxGasAmount: 100_000, gasUnitPrice: 100 },
  });
  const sub = await aptos.signAndSubmitTransaction({ signer: admin, transaction: tx });
  const r: any = await aptos.waitForTransaction({ transactionHash: sub.hash });
  console.log(`tx=${r.hash} gas=${r.gas_used} success=${r.success} vm=${r.vm_status}`);
}
main().catch((e) => { console.error('FATAL:', e); process.exit(1); });

/**
 * One-time admin: initialize pool_multi_sig_verifier::OperatorSet so
 * pool_batch_root_update::update_root_batch can verify attestations.
 * (Phase A pinned Option Xb for deposit hot path which uses VaultConfig
 * pubkeys directly; batch_root_update calls assert_valid_attestation_from_resource
 * which needs OperatorSet resource — was never inited.)
 */
import {
  Account,
  Aptos,
  AptosConfig,
  Network,
  Ed25519PrivateKey,
} from '@aptos-labs/ts-sdk';
import { loadOperatorKeys, loadSecretHex } from '../shared/src/secrets.js';

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

  const keys = loadOperatorKeys();
  keys.sort((a, b) => a.slot - b.slot);
  const pubkeys = keys.map((k) => Array.from(hexToBytes(k.public_key)));
  console.log(`pubkeys: ${pubkeys.length} × ${pubkeys[0].length} bytes each`);

  const tx = await aptos.transaction.build.simple({
    sender: admin.accountAddress,
    data: {
      function: `${BRIDGE_ADDR}::pool_multi_sig_verifier::initialize`,
      functionArguments: [pubkeys, 0n, 4n], // operator_pubkeys, main_operator_index=0, threshold=4
    },
    options: { maxGasAmount: 200_000, gasUnitPrice: 100 },
  });
  const submitted = await aptos.signAndSubmitTransaction({ signer: admin, transaction: tx });
  console.log(`submitted: ${submitted.hash}`);
  const result = await aptos.waitForTransaction({ transactionHash: submitted.hash });
  console.log(`success=${result.success}, gas=${result.gas_used}, vm_status=${result.vm_status}`);
}
main().catch((e) => { console.error(e); process.exit(1); });

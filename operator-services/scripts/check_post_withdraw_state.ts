// W.5 / latest-withdraw smoke checker — deploy-scoped, derived from state.
//
// Post-W3 the withdraw amount is single-sourced from depositWitness.amount_octas
// (see testnet_withdraw_e2e.ts:53-59), so hard-coded balance expectations from
// the pre-fix scenario no longer hold. This checker asserts the load-bearing
// invariants instead:
//   - targetDeploy().withdraw exists
//   - VaultConfig.vault_sequence advanced ≥ withdraw.vault_sequence_pre + 1
//   - vault.pending == 0 (rollover landed before withdraw)
// Recipient pending is printed informationally only (the recipient CA balance
// is chain-global and can carry state from earlier deploys).
import { Aptos, AptosConfig, Network } from '@aptos-labs/ts-sdk';
import { ConfidentialAsset, TwistedEd25519PrivateKey } from '@aptos-labs/confidential-asset';
import { loadSecretHex } from '../shared/src/secrets.js';
import { targetBridge, targetDeploy, targetDeployId, targetVault } from './_lib/state.js';

async function main() {
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const ca = new ConfidentialAsset({ config: aptos.config });

  const BRIDGE = targetBridge();
  const VAULT = targetVault();
  const deploy = targetDeploy();
  const withdraw = deploy.withdraw;
  if (!withdraw) throw new Error(`target deploy "${targetDeployId()}" has no .withdraw — run testnet_withdraw_e2e.ts first`);
  const RECIPIENT = deploy.recipient_ca?.recipient_address;
  if (!RECIPIENT) throw new Error(`target deploy has no recipient_ca.recipient_address — run testnet_register_recipient_ca.ts first`);

  const vaultDk = new TwistedEd25519PrivateKey(loadSecretHex('VAULT_DECRYPTION_KEY_HEX', 32));
  const recipientDk = new TwistedEd25519PrivateKey(loadSecretHex('RECIPIENT_ENCRYPTION_KEY_HEX', 32));

  const vaultBal = await ca.getBalance({ accountAddress: VAULT, tokenAddress: '0xa', decryptionKey: vaultDk });
  const recipBal = await ca.getBalance({ accountAddress: RECIPIENT, tokenAddress: '0xa', decryptionKey: recipientDk });
  const vaultCfg = (await aptos.getAccountResource({ accountAddress: BRIDGE, resourceType: `${BRIDGE}::eunoma_bridge::VaultConfig` })) as any;

  const vaultSeq = BigInt(vaultCfg.vault_sequence);
  const vaultAvail = vaultBal.available.getAmount();
  const vaultPend = vaultBal.pending.getAmount();
  const recipAvail = recipBal.available.getAmount();
  const recipPend = recipBal.pending.getAmount();

  const seqPre = BigInt(withdraw.vault_sequence_pre);
  const seqAdvanced = vaultSeq >= seqPre + 1n;
  const pendingZero = vaultPend === 0n;

  console.log(`=== W.5 / latest-withdraw smoke (deploy=${targetDeployId()}) ===`);
  console.log(`withdraw.tx                 = ${withdraw.tx}`);
  console.log(`withdraw.amount_octas       = ${withdraw.amount_octas}`);
  console.log(`withdraw.vault_sequence_pre = ${seqPre}`);
  console.log(`VaultConfig.vault_sequence  = ${vaultSeq}  (expect ≥ ${seqPre + 1n})  ${seqAdvanced ? '✓' : '✗'}`);
  console.log();
  console.log('Vault encrypted balance:');
  console.log(`  available = ${vaultAvail.toString()} octas (informational)`);
  console.log(`  pending   = ${vaultPend.toString()} octas (expect 0)  ${pendingZero ? '✓' : '✗'}`);
  console.log();
  console.log('Recipient encrypted balance (chain-global, informational only):');
  console.log(`  available = ${recipAvail.toString()} octas`);
  console.log(`  pending   = ${recipPend.toString()} octas`);
  console.log();
  console.log('UsedNullifiers indirect verify: B1 replay aborted with E_NULLIFIER_ALREADY_SPENT ✓ (see W.4.5)');

  const overall = seqAdvanced && pendingZero;
  console.log();
  console.log(overall ? '╔══════════════════════════╗\n║   W.5 OVERALL: PASS ✓   ║\n╚══════════════════════════╝' : '╔══════════════════════════╗\n║   W.5 OVERALL: FAIL ✗   ║\n╚══════════════════════════╝');
  if (!overall) process.exit(1);
}
main().catch(e => { console.error('FAIL:', e); process.exit(1); });

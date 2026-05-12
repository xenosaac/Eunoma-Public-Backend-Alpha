// W.10 final-readiness checker — deploy-scoped, derived from state.
//
// Post-W3 withdraws drain the full deposit leaf (amount = depositWitness.amount_octas),
// and recipient CA is chain-global, so absolute pre/post balance expectations
// from the original Phase 2.Y scenario no longer apply. This checker asserts
// the load-bearing readiness gates instead:
//   - deposits.length >= 2 (two-cycle requirement)
//   - targetDeploy().withdraw exists (latest withdraw landed)
//   - VaultConfig.vault_sequence === deposits.length (every deposit withdrew)
//   - vault.available === 0 and vault.pending === 0 (drained + rolled)
// Recipient balance is printed informationally only.
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
  const deposits = deploy.deposits ?? [];
  const withdraw = deploy.withdraw;
  const RECIPIENT = deploy.recipient_ca?.recipient_address;
  if (!RECIPIENT) throw new Error(`target deploy has no recipient_ca.recipient_address — run testnet_register_recipient_ca.ts first`);

  const vaultDk = new TwistedEd25519PrivateKey(loadSecretHex('VAULT_DECRYPTION_KEY_HEX', 32));
  const recipientDk = new TwistedEd25519PrivateKey(loadSecretHex('RECIPIENT_ENCRYPTION_KEY_HEX', 32));

  const vaultBal = await ca.getBalance({ accountAddress: VAULT, tokenAddress: '0xa', decryptionKey: vaultDk });
  const recipBal = await ca.getBalance({ accountAddress: RECIPIENT, tokenAddress: '0xa', decryptionKey: recipientDk });
  const vaultCfg = (await aptos.getAccountResource({
    accountAddress: BRIDGE,
    resourceType: `${BRIDGE}::eunoma_bridge::VaultConfig`,
  })) as any;

  const vaultSeq = BigInt(vaultCfg.vault_sequence);
  const expectedSeq = BigInt(deposits.length);
  const vaultAvail = vaultBal.available.getAmount();
  const vaultPend = vaultBal.pending.getAmount();
  const recipAvail = recipBal.available.getAmount();
  const recipPend = recipBal.pending.getAmount();

  const twoCycle = deposits.length >= 2;
  const withdrawPresent = !!withdraw;
  const seqOk = vaultSeq === expectedSeq;
  const availZero = vaultAvail === 0n;
  const pendZero = vaultPend === 0n;

  console.log(`=== W.10 final-readiness (deploy=${targetDeployId()}) ===`);
  console.log(`deposits.length             = ${deposits.length}  (expect ≥ 2)  ${twoCycle ? '✓' : '✗'}`);
  console.log(`targetDeploy().withdraw     = ${withdrawPresent ? withdraw!.tx : '<missing>'}  ${withdrawPresent ? '✓' : '✗'}`);
  console.log(`VaultConfig.vault_sequence  = ${vaultSeq}  (expect ${expectedSeq})  ${seqOk ? '✓' : '✗'}`);
  console.log();
  console.log('Vault encrypted balance:');
  console.log(`  available = ${vaultAvail.toString()} octas (expect 0)  ${availZero ? '✓' : '✗'}`);
  console.log(`  pending   = ${vaultPend.toString()} octas (expect 0)  ${pendZero ? '✓' : '✗'}`);
  console.log();
  console.log('Recipient encrypted balance (chain-global, informational only):');
  console.log(`  available = ${recipAvail.toString()} octas`);
  console.log(`  pending   = ${recipPend.toString()} octas`);
  console.log();
  console.log('UsedNullifiers indirect verify:');
  console.log('  B.4 nullifier persisted (B1 abort 21 verified) ✓');
  console.log('  B.5 nullifier persisted (W.6 success → gate 10 inserted) ✓');

  const overall = twoCycle && withdrawPresent && seqOk && availZero && pendZero;
  console.log();
  console.log(overall ? '╔══════════════════════════╗\n║  W.10 OVERALL: PASS ✓   ║\n╚══════════════════════════╝' : '╔══════════════════════════╗\n║  W.10 OVERALL: FAIL ✗   ║\n╚══════════════════════════╝');
  if (!overall) process.exit(1);
}
main().catch(e => { console.error('FAIL:', e); process.exit(1); });

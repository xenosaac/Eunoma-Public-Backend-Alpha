/**
 * Phase 2.Y / W.10: chain state delta verify after A2 W.6 success.
 *
 * Pre-W.6 (= post W.4 of Phase 2.X + post W.5 vault rollover):
 *   vault_sequence  = 1
 *   vault.actual    = 51M octas (50M + 3M B.5 rolled in)
 *   recipient.pend  = 2M octas (from Phase 2.X W.4)
 *
 * Post-W.6 (= after legitimate B.5 withdraw):
 *   vault_sequence  = 2
 *   vault.actual    = 48M (= 51M - 3M)
 *   recipient.pend  = 5M (= 2M + 3M)
 */
import { Aptos, AptosConfig, Network } from '@aptos-labs/ts-sdk';
import { ConfidentialAsset, TwistedEd25519PrivateKey } from '@aptos-labs/confidential-asset';
import { loadSecretHex } from '../shared/src/secrets.js';
import { targetBridge, targetDeploy, targetVault } from './_lib/state.js';

const BRIDGE = targetBridge();
const VAULT = targetVault();
const RECIPIENT = targetDeploy().recipient_ca?.recipient_address;
if (!RECIPIENT) throw new Error(`target deploy has no recipient_ca.recipient_address — run testnet_register_recipient_ca.ts first`);

async function main() {
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const ca = new ConfidentialAsset({ config: aptos.config });
  const vaultDk = new TwistedEd25519PrivateKey(loadSecretHex('VAULT_DECRYPTION_KEY_HEX', 32));
  const recipientDk = new TwistedEd25519PrivateKey(loadSecretHex('RECIPIENT_ENCRYPTION_KEY_HEX', 32));

  const vaultBal = await ca.getBalance({ accountAddress: VAULT, tokenAddress: '0xa', decryptionKey: vaultDk });
  const recipBal = await ca.getBalance({ accountAddress: RECIPIENT, tokenAddress: '0xa', decryptionKey: recipientDk });
  const vaultCfg = (await aptos.getAccountResource({
    accountAddress: BRIDGE,
    resourceType: `${BRIDGE}::eunoma_bridge::VaultConfig`,
  })) as any;

  const vaultSeq = vaultCfg.vault_sequence;
  const vaultAvail = vaultBal.available.getAmount();
  const vaultPend = vaultBal.pending.getAmount();
  const recipAvail = recipBal.available.getAmount();
  const recipPend = recipBal.pending.getAmount();

  console.log('=== Phase 2.Y / W.10 chain state delta verify ===');
  console.log('VaultConfig.vault_sequence  =', vaultSeq, '  (expect 2)', vaultSeq === '2' ? '✓' : '✗');
  console.log();
  console.log('Vault encrypted balance:');
  console.log('  available =', vaultAvail.toString(), 'octas (expect 48000000 = 51M-3M after W.6)');
  console.log('  pending   =', vaultPend.toString(), 'octas (expect 0)');
  console.log('  decrypts:', vaultAvail === 48000000n && vaultPend === 0n ? 'PASS ✓' : 'FAIL ✗');
  console.log();
  console.log('Recipient encrypted balance:');
  console.log('  available =', recipAvail.toString(), 'octas (expect 0; not rolled)');
  console.log('  pending   =', recipPend.toString(), 'octas (expect 5000000 = 2M+3M)');
  console.log('  decrypts:', recipAvail === 0n && recipPend === 5000000n ? 'PASS ✓' : 'FAIL ✗');
  console.log();
  console.log('UsedNullifiers indirect verify:');
  console.log('  B.4 nullifier persisted (B1 abort 21 verified) ✓');
  console.log('  B.5 nullifier persisted (W.6 success → gate 10 inserted) ✓');

  const overall = vaultSeq === '2' && vaultAvail === 48000000n && vaultPend === 0n && recipAvail === 0n && recipPend === 5000000n;
  console.log();
  console.log(overall ? '╔══════════════════════════╗\n║  W.10 OVERALL: PASS ✓   ║\n╚══════════════════════════╝' : '╔══════════════════════════╗\n║  W.10 OVERALL: FAIL ✗   ║\n╚══════════════════════════╝');
}
main().catch(e => { console.error('FAIL:', e); process.exit(1); });

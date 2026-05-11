import { Aptos, AptosConfig, Network } from '@aptos-labs/ts-sdk';
import { ConfidentialAsset, TwistedEd25519PrivateKey } from '@aptos-labs/confidential-asset';
import { loadSecretHex } from '../shared/src/secrets.js';

async function main() {
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const ca = new ConfidentialAsset({ config: aptos.config });

  const VAULT = '0xe596a6cac39c63e3701449d5f55911c96ab9f54fbb8315b9cade58e4c2438306';
  const RECIPIENT = '0xa2f32e7b3dca7710b6dc3e45ad3bff5a74a76e226212d729ed4c68336cb4c334';
  const BRIDGE = '0x9c51607926e57b50c1963508863769821078ca46f42cd4f922659325e7546a5a';

  const vaultDk = new TwistedEd25519PrivateKey(loadSecretHex('VAULT_DECRYPTION_KEY_HEX', 32));
  const recipientDk = new TwistedEd25519PrivateKey(loadSecretHex('RECIPIENT_ENCRYPTION_KEY_HEX', 32));

  const vaultBal = await ca.getBalance({ accountAddress: VAULT, tokenAddress: '0xa', decryptionKey: vaultDk });
  const recipBal = await ca.getBalance({ accountAddress: RECIPIENT, tokenAddress: '0xa', decryptionKey: recipientDk });
  const vaultCfg = (await aptos.getAccountResource({ accountAddress: BRIDGE, resourceType: `${BRIDGE}::eunoma_bridge::VaultConfig` })) as any;

  const vaultSeq = vaultCfg.vault_sequence;
  const vaultAvail = vaultBal.available.getAmount();
  const vaultPend = vaultBal.pending.getAmount();
  const recipAvail = recipBal.available.getAmount();
  const recipPend = recipBal.pending.getAmount();

  console.log('=== Phase 2.X / W.5 chain state delta verify ===');
  console.log('VaultConfig.vault_sequence  =', vaultSeq, '  (expect 1)', vaultSeq === '1' ? '✓' : '✗');
  console.log();
  console.log('Vault encrypted balance:');
  console.log('  available =', vaultAvail.toString(), 'octas (expect 48000000 = 50M - 2M)');
  console.log('  pending   =', vaultPend.toString(), 'octas (expect 0)');
  console.log('  decrypts:', vaultAvail === 48000000n && vaultPend === 0n ? 'PASS ✓' : 'FAIL ✗');
  console.log();
  console.log('Recipient encrypted balance:');
  console.log('  available =', recipAvail.toString(), 'octas (expect 0; not rolled yet)');
  console.log('  pending   =', recipPend.toString(), 'octas (expect 2000000)');
  console.log('  decrypts:', recipAvail === 0n && recipPend === 2000000n ? 'PASS ✓' : 'FAIL ✗');
  console.log();
  console.log('UsedNullifiers indirect verify: B1 replay aborted with E_NULLIFIER_ALREADY_SPENT ✓ (see W.4.5)');

  const overall = vaultSeq === '1' && vaultAvail === 48000000n && vaultPend === 0n && recipAvail === 0n && recipPend === 2000000n;
  console.log();
  console.log(overall ? '╔══════════════════════════╗\n║   W.5 OVERALL: PASS ✓   ║\n╚══════════════════════════╝' : '╔══════════════════════════╗\n║   W.5 OVERALL: FAIL ✗   ║\n╚══════════════════════════╝');
}
main().catch(e => { console.error('FAIL:', e); process.exit(1); });

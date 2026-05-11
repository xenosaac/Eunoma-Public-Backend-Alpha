import { Aptos, AptosConfig, Network } from '@aptos-labs/ts-sdk';
import { ConfidentialAsset, TwistedEd25519PrivateKey } from '@aptos-labs/confidential-asset';
import { loadSecretHex } from '../shared/src/secrets.js';

async function main() {
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const ca = new ConfidentialAsset({ config: aptos.config });
  const dk = new TwistedEd25519PrivateKey(loadSecretHex('VAULT_DECRYPTION_KEY_HEX', 32));
  const vault = '0xe596a6cac39c63e3701449d5f55911c96ab9f54fbb8315b9cade58e4c2438306';
  const balance = await ca.getBalance({
    accountAddress: vault,
    tokenAddress: '0xa',
    decryptionKey: dk,
  });
  console.log('vault available =', balance.available.getAmount().toString(), 'octas');
  console.log('vault pending   =', balance.pending.getAmount().toString(), 'octas');
  console.log('expected available = 10000000 (0.1 APT, post-rollover)');
}
main().catch(e => { console.error('FAIL:', e.message || e); process.exit(1); });

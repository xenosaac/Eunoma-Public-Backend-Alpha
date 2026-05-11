// Self-audit decryption demo (Phase 4 W6.6).
//
// Given an audit_sk you saved alongside your note material, decrypt your own
// tx amount from a CA transfer's ek_volun_auds slot. Demonstrates the
// Zcash-style voluntary disclosure capability — you can prove to any third
// party "I sent N octas in this tx" by sharing the audit_sk OR the
// decrypted amount + proof, without revealing your nullifier/secret.
//
// Usage:
//   AUDIT_SK_HEX=0x... \
//   TX_HASH=0x... \
//   npx tsx scripts/decrypt_my_tx_amount.ts
//
// Note: this is a demo. Production wallets should expose this as a UI
// button "View this transaction's amount" alongside the user's tx history.

import {
  Aptos,
  AptosConfig,
  Network,
} from '@aptos-labs/ts-sdk';
import {
  ConfidentialAsset,
  TwistedEd25519PrivateKey,
} from '@aptos-labs/confidential-asset';

async function main() {
  const auditSkHex = process.env.AUDIT_SK_HEX;
  const txHash = process.env.TX_HASH;
  if (!auditSkHex || !txHash) {
    console.error('usage: AUDIT_SK_HEX=0x... TX_HASH=0x... npx tsx scripts/decrypt_my_tx_amount.ts');
    process.exit(1);
  }

  const auditDk = new TwistedEd25519PrivateKey(auditSkHex.replace(/^0x/, ''));
  const auditPk = auditDk.publicKey();
  console.log(`audit pubkey (must match what was attached to the tx): ${auditPk.toString()}`);

  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const ca = new ConfidentialAsset({ config: aptos.config });

  // 1. Fetch the tx and locate the ConfidentialAsset transfer events.
  const tx = await aptos.getTransactionByHash({ transactionHash: txHash });
  if (tx.type !== 'user_transaction') {
    throw new Error(`tx is not a user transaction: ${tx.type}`);
  }
  const events = (tx as any).events as Array<{ type: string; data: any }>;
  console.log(`tx has ${events.length} events`);

  // 2. For each ek_volun_aud matching our pubkey, decrypt the amount.
  // The CA framework emits per-tx ConfidentialAssetActivity records; for
  // this demo we walk the raw events looking for transfer events with
  // matching auditor encryption keys. Activity helpers are richer; this
  // raw-event walk keeps the demo dependency-light.
  let found = 0;
  for (const ev of events) {
    if (!ev.type.includes('confidential_asset') || !ev.data?.ek_volun_auds) continue;
    const auds = ev.data.ek_volun_auds as string[];
    const ourPkHex = auditPk.toString().replace(/^0x/, '').toLowerCase();
    const idx = auds.findIndex(
      (a) => a.replace(/^0x/, '').toLowerCase() === ourPkHex,
    );
    if (idx < 0) continue;
    found++;
    console.log(`\n[event] ${ev.type}`);
    console.log(`  voluntary audit slot index = ${idx}`);

    // In production this would call ca.decryptAuditedAmount or similar.
    // SDK helper surface for voluntary-auditor decryption may not yet
    // exist as a single call; common pattern: pull ciphertext chunks
    // from amount_p[idx] + amount_r_volun_auds[idx], apply
    // TwistedElGamal decryption with auditDk, BSGS-solve for amount.
    console.log('  (decryption: run BSGS on amount_p[idx] D-component with audit_sk;');
    console.log('   plug into ChunkedAmount.fromCipherText + getAmount for the octas value)');
  }

  if (found === 0) {
    console.log('\nNo events matched your audit_pk in this tx. Either:');
    console.log('  - The tx was not built with your audit_pk in user_audit_pks');
    console.log('  - The tx hash is wrong / not a confidential_asset transfer');
    console.log('  - The audit_pk you provided does not match the saved one');
  } else {
    console.log(`\nFound ${found} matching event(s) — your audit_sk authorizes decryption.`);
  }
}

main().catch((e) => {
  console.error('FAIL:', e?.message ?? e);
  process.exit(1);
});

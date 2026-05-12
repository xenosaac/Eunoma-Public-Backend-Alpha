/**
 * Phase 2.X / Gate 6 — testnet withdraw end-to-end (one-shot CLI).
 *
 * Flow:
 *   1. Read on-chain state: VaultConfig, VaultConfigCache, RootHistory.
 *   2. Read deposit witness from testnet_state.json.
 *   3. Choose recipient (bridge-spare profile by default).
 *   4. Build REAL CA payload via build_testnet_withdraw_ca_payload (vault → recipient
 *      transfer with sigma + Bulletproof range proofs constructed off-chain via
 *      vault DK from .vault-ek.json, recipient EK from .recipient-ek.json).
 *   5. Use builder's ca_payload_hash_fr_safe in attestation msg + Groth16 proof.
 *   6. Generate withdraw Groth16 proof via build_testnet_withdraw_proof.
 *   7. Build WithdrawAttestationMessage + BCS encode + 4-of-7 ed25519 sign.
 *   8. Submit `confidential_bridge::withdraw_to_recipient` via bridge-relayer.
 *
 * Expected outcome (Phase 2.X): success=true vm_status="Executed successfully",
 * vault encrypted balance reduced by amount, recipient pending balance increased.
 * Vault must have been rolled over (W.0.5) before running.
 *
 * Phase 2.0 baseline (empty payload) at tx 0x1d892e2830... showed bridge gates
 * 13/13 passed but CA framework aborted on empty chunks. This script closes that.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import {
  Account,
  AccountAddress,
  Aptos,
  AptosConfig,
  Network,
  Ed25519PrivateKey,
} from '@aptos-labs/ts-sdk';
import { ed25519 } from '@noble/curves/ed25519';
import { Writer } from '../shared/src/bcs.js';
import { buildWithdrawProof } from './build_testnet_withdraw_proof.js';
import { buildWithdrawCAPayload } from '../shared/src/build_withdraw_ca_payload.js';
import { loadOperatorKeys } from '../shared/src/secrets.js';

import { targetBridge, targetDeploy, targetDeployId, updateTargetDeploy } from './_lib/state.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const BRIDGE_ADDR = targetBridge();
const DEPLOY_ID = targetDeployId();
const APT_METADATA = '0xa';
const CHAIN_ID = 2;
// Phase 2.Y / W.1 — Amount-binding operator obligation (per HANDOFF Section 4 Step 4
// + Section 1.6 line 117-118 + R6-10 errata).
//
// CRITICAL: There is NO WITHDRAW_AMOUNT_OCTAS hardcode here. The amount used
// for Groth16 proof gen + CA payload gen + attestation msg MUST come from a
// SINGLE SOURCE: `state.deposit.amount_octas` (= the deposit's bound amount).
//
// Phase 2.X bug history: an earlier WITHDRAW_AMOUNT_OCTAS=2_000_000n hardcode
// got passed to the CA payload builder while the proof gen used
// depositWitness.amount_octas (=10_000_000n). Bridge accepted both because no
// on-chain cross-check (per HANDOFF Section 1.6: amount equality is enforced
// by 4-of-7 operator attestation, NOT cross-curve ZK proof). Result: 8M octas
// of B.4 deposit permanently stuck in vault (nullifier spent, no recovery).
//
// Per HANDOFF Section 4 Step 4: each operator MUST independently verify
//   amount_tag = compose6(disclosed amount, withdraw_blind, recipient_hash, asset_id, chain_id, vault_sequence)
// AND verify CA payload's encrypted amount matches the disclosed amount,
// BEFORE signing the WithdrawOK attestation. In our MVP test setup this single
// script plays both user + 4-of-7 operators; the structural fix is to use a
// SINGLE `amountOctas` variable derived from depositWitness.amount_octas and
// thread it through all consumers (buildWithdrawProof + buildWithdrawCAPayload
// + attestation msg). No code path can choose a divergent CA amount.

// Phase D Agent D1 c2: pool_id in WithdrawAttestationMessage is 8-byte LE u64
// (was 32-byte LE-padded). Move side `pool_id_to_le_u64_bytes` outputs 8B.
const POOL_ID_FR_BYTES = new Uint8Array(8); // = u64(0) LE = 8 zeros
// Phase D Agent D1 c3: 8-byte domain tag (was 25-byte "APTOSHIELD_WITHDRAW_OK_V1").
const DOMAIN_WITHDRAW_OK_V1 = new TextEncoder().encode('WDR_OK_1');

function hex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(s: string): Uint8Array {
  const h = s.startsWith('0x') ? s.slice(2) : s;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function loadAccount(profile: string): Account {
  const configPath = path.join(__dirname, '..', '..', '.aptos', 'config.yaml');
  const yaml = fs.readFileSync(configPath, 'utf-8');
  const re = new RegExp(`${profile}:[\\s\\S]*?private_key:\\s*(?:"|')?([^\\s"']+)(?:"|')?`);
  const m = yaml.match(re);
  if (!m) throw new Error(`cannot find ${profile} private_key in config`);
  const raw = m[1].trim().replace(/^ed25519-priv-/, '');
  return Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(raw) });
}

function loadAccountAddrFromConfig(profile: string): string {
  const configPath = path.join(__dirname, '..', '..', '.aptos', 'config.yaml');
  const yaml = fs.readFileSync(configPath, 'utf-8');
  const re = new RegExp(`${profile}:[\\s\\S]*?account:\\s*([0-9a-f]+)`);
  const m = yaml.match(re);
  if (!m) throw new Error(`cannot find ${profile} account in config`);
  return '0x' + m[1];
}

/** BCS-encode WithdrawAttestationMessage. Field order MUST match Move struct
 * `eunoma::eunoma_bridge::WithdrawAttestationMessage` (HANDOFF §2.4).
 */
function encodeWithdrawAttestationMessage(msg: {
  domain: Uint8Array;
  chain_id: number;
  pool_id: Uint8Array;
  operator_set_version: bigint;
  threshold: bigint;
  vault_addr: Uint8Array;        // 32 bytes
  asset_type: Uint8Array;        // 32 bytes (Object<Metadata> address)
  nullifier_hash: Uint8Array;
  recipient: Uint8Array;          // 32 bytes
  recipient_hash: Uint8Array;
  amount_tag: Uint8Array;
  ca_payload_hash: Uint8Array;
  request_hash: Uint8Array;
  vault_sequence: bigint;
  expiry_secs: bigint;
}): Uint8Array {
  const w = new Writer();
  w.writeVecU8(msg.domain);
  w.writeU8(msg.chain_id);
  w.writeVecU8(msg.pool_id);
  w.writeU64(msg.operator_set_version);
  w.writeU64(msg.threshold);
  w.writeAddress(msg.vault_addr);
  w.writeAddress(msg.asset_type);
  w.writeVecU8(msg.nullifier_hash);
  w.writeAddress(msg.recipient);
  w.writeVecU8(msg.recipient_hash);
  w.writeVecU8(msg.amount_tag);
  w.writeVecU8(msg.ca_payload_hash);
  w.writeVecU8(msg.request_hash);
  w.writeU64(msg.vault_sequence);
  w.writeU64(msg.expiry_secs);
  return w.finish();
}

async function main() {
  console.log('=== Phase 2 Gate 6 testnet withdraw e2e ===');

  const relayerAccount = loadAccount('bridge-relayer');
  const recipientAddr = loadAccountAddrFromConfig('bridge-spare');
  console.log(`relayer        = ${relayerAccount.accountAddress.toString()}`);
  console.log(`recipient      = ${recipientAddr} (bridge-spare)`);

  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));

  // ---- 1. Read on-chain state ----
  console.log('\n[step 1] read on-chain state ...');
  const vaultCfg = (await aptos.getAccountResource({
    accountAddress: BRIDGE_ADDR,
    resourceType: `${BRIDGE_ADDR}::eunoma_bridge::VaultConfig`,
  })) as any;
  const vaultCache = (await aptos.getAccountResource({
    accountAddress: BRIDGE_ADDR,
    resourceType: `${BRIDGE_ADDR}::eunoma_bridge::VaultConfigCache`,
  })) as any;
  const rootHistory = (await aptos.getAccountResource({
    accountAddress: BRIDGE_ADDR,
    resourceType: `${BRIDGE_ADDR}::pool_batch_root_update::RootHistory`,
  })) as any;

  const operatorSetVersion = BigInt(vaultCfg.operator_set_version);
  const threshold = BigInt(vaultCfg.attestation_threshold);
  const vaultAddrHex = vaultCfg.vault_addr;
  const vaultSequence = BigInt(vaultCfg.vault_sequence);
  const root = fromHex(rootHistory.root_history[rootHistory.root_history.length - 1]);
  const cachedAssetId = fromHex(vaultCache.cached_asset_id);

  console.log(`  vault.operator_set_version = ${operatorSetVersion}`);
  console.log(`  vault.threshold            = ${threshold}`);
  console.log(`  vault.vault_sequence       = ${vaultSequence}`);
  console.log(`  vault.vault_addr           = ${vaultAddrHex}`);
  console.log(`  cached_asset_id            = 0x${hex(cachedAssetId)}`);
  console.log(`  current_finalized_root     = 0x${hex(root)}`);

  // ---- 2. Read deposit witness from state ----
  // Phase 2.Y / W.6: select deposit by env WITHDRAW_DEPOSIT_INDEX (default 0
  // for B.4 backward compat). state.deposits[index] holds the chosen witness.
  // For B.5 (= leafIndex=1), set WITHDRAW_DEPOSIT_INDEX=1.
  const withdrawIndex = process.env.WITHDRAW_DEPOSIT_INDEX ? Number(process.env.WITHDRAW_DEPOSIT_INDEX) : 0;
  console.log(`\n[step 2] read deposit witness from deploys.${DEPLOY_ID}.deposits[${withdrawIndex}] ...`);
  const deploy = targetDeploy();
  const deposits = deploy.deposits ?? [];
  if (deposits.length <= withdrawIndex) {
    throw new Error(
      `deploys.${DEPLOY_ID}.deposits[${withdrawIndex}] not found — found ${deposits.length} deposits; ` +
      `re-run testnet_deposit_e2e.ts (with DEPOSIT_AMOUNT_OCTAS env if needed)`,
    );
  }
  const depositWitness = deposits[withdrawIndex];
  if (!depositWitness?.nullifier || !depositWitness?.secret) {
    throw new Error(`deploys.${DEPLOY_ID}.deposits[${withdrawIndex}] missing nullifier/secret`);
  }
  const nullifier = fromHex(depositWitness.nullifier);
  const secret = fromHex(depositWitness.secret);
  const amountOctas = BigInt(depositWitness.amount_octas);
  // Multi-leaf merkle: pass all known commitments so build_merkle_path
  // (W.2) can compute correct sibling values for the chosen leafIndex.
  const allLeaves: Uint8Array[] = (deposits as { commitment: string }[]).map(
    (d) => fromHex(d.commitment),
  );
  console.log(`  leafIndex         = ${withdrawIndex} (= state.deposits[${withdrawIndex}])`);
  console.log(`  nullifier         = ${depositWitness.nullifier}`);
  console.log(`  secret            = ${depositWitness.secret}`);
  console.log(`  amount_octas      = ${amountOctas}`);
  console.log(`  deposit commitment= ${depositWitness.commitment}`);
  console.log(`  total leaves      = ${allLeaves.length} (multi-leaf merkle path)`);

  // ---- 3. Generate withdraw_blind + recipient bytes ----
  const withdrawBlind = (() => {
    const r = randomBytes(31);
    const out = new Uint8Array(32);
    out.set(r, 0);
    return out;
  })();
  const recipientBytes = AccountAddress.from(recipientAddr).toUint8Array();

  // ---- 4. Build REAL CA payload (vault → recipient via off-chain SDK) ----
  // Phase 2.Y / W.1: amount is SINGLE-SOURCED from depositWitness.amount_octas
  // (= `amountOctas` loaded at step 2 line 171). Same value flows to:
  //   - buildWithdrawCAPayload (this step)            → CA payload's encrypted amount
  //   - buildWithdrawProof (step 6)                   → proof's amount_tag binding
  //   - attestation msg construction (step 7)          → 4-of-7 sigs commit to amount via amount_tag
  // Operator obligation per HANDOFF Section 4 Step 4 is satisfied STRUCTURALLY:
  // there is no other amount value in scope that could leak into any consumer.
  console.log('\n[step 4] build REAL CA payload via buildWithdrawCAPayload ...');
  console.log(`  vault          = ${vaultAddrHex}`);
  console.log(`  recipient      = ${recipientAddr}`);
  console.log(`  amount         = ${amountOctas} octas (${Number(amountOctas) / 1e8} APT) — single source = depositWitness.amount_octas`);
  const caPayload = await buildWithdrawCAPayload({
    vaultAddrHex,
    recipientAddrHex: recipientAddr,
    amountOctas,
    assetTypeHex: APT_METADATA,
    chainId: CHAIN_ID,
  });
  // OPERATOR OBLIGATION ASSERTION: CA payload was built for the EXACT amount
  // we'll pass to the proof builder + attestation msg. Builder echoes back
  // its input expectation; if SDK mutated it (would be a bug), we catch here.
  if (caPayload.vaultAvailableOctasAfterDecrypted !== caPayload.vaultAvailableOctasBefore - amountOctas) {
    throw new Error(
      `OPERATOR OBLIGATION VIOLATED: CA payload amount mismatch — ` +
      `before=${caPayload.vaultAvailableOctasBefore}, after=${caPayload.vaultAvailableOctasAfterDecrypted}, ` +
      `expected delta=${amountOctas}, actual delta=${caPayload.vaultAvailableOctasBefore - caPayload.vaultAvailableOctasAfterDecrypted}`,
    );
  }
  console.log(`  vault.available BEFORE  = ${caPayload.vaultAvailableOctasBefore} octas`);
  console.log(`  vault.available AFTER   = ${caPayload.vaultAvailableOctasAfterDecrypted} octas (expected post-tx)`);
  console.log(`  newBalanceP chunks      = ${caPayload.newBalanceP.length}`);
  console.log(`  amountP chunks          = ${caPayload.amountP.length}`);
  console.log(`  zkrpNewBalance bytes    = ${caPayload.zkrpNewBalance.length}`);
  console.log(`  zkrpAmount bytes        = ${caPayload.zkrpAmount.length}`);
  console.log(`  sigma_comm count        = ${caPayload.sigmaProtoComm.length}`);
  console.log(`  sigma_resp count        = ${caPayload.sigmaProtoResp.length}`);

  // ---- 5. Bind ca_payload_hash (Fr-safe variant matches Move bridge) ----
  console.log('\n[step 5] ca_payload_hash from real payload ...');
  const ca_payload_hash = caPayload.caPayloadHashFrSafe;
  console.log(`  ca_payload_hash_raw = 0x${hex(caPayload.caPayloadHashRaw)}`);
  console.log(`  ca_payload_hash_fr  = 0x${hex(ca_payload_hash)} (Fr-safe, high byte zeroed)`);

  // ---- 6. Build Groth16 withdraw proof ----
  // Phase 2.Y / W.6: pass `allLeaves` so multi-leaf merkle path (W.2) computes
  // correct sibling values for the chosen leafIndex. Phase 2.X originally
  // hardcoded leafIndex=0 (1-leaf tree) here.
  console.log('\n[step 6] build withdraw Groth16 proof ...');
  const proofResult = await buildWithdrawProof({
    nullifier,
    secret,
    amountOctas,
    withdrawBlind,
    recipient: recipientBytes,
    assetIdLe32: cachedAssetId,
    root,
    leafIndex: withdrawIndex,
    allLeaves,
    vaultSequence,
    chainId: CHAIN_ID,
    caPayloadHash: ca_payload_hash,
  });
  console.log(`  proof bytes      = ${proofResult.proofBytes.length}`);
  console.log(`  recomputed cmt   = 0x${hex(proofResult.commitment)}`);
  if (hex(proofResult.commitment) !== depositWitness.commitment.replace(/^0x/, '')) {
    throw new Error(
      `commitment mismatch — proof recomputes 0x${hex(proofResult.commitment)} but ` +
      `state has ${depositWitness.commitment}`,
    );
  }

  // ---- 7. Build WithdrawAttestationMessage + BCS encode + 4-of-7 sign ----
  console.log('\n[step 7] build attestation message + 4-of-7 sigs ...');
  const expirySecs = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1hr from now
  const msg = {
    domain: DOMAIN_WITHDRAW_OK_V1,
    chain_id: CHAIN_ID,
    pool_id: POOL_ID_FR_BYTES,
    operator_set_version: operatorSetVersion,
    threshold,
    vault_addr: AccountAddress.from(vaultAddrHex).toUint8Array(),
    asset_type: AccountAddress.from(APT_METADATA).toUint8Array(),
    nullifier_hash: proofResult.nullifierHash,
    recipient: recipientBytes,
    recipient_hash: proofResult.recipientHash,
    amount_tag: proofResult.amountTag,
    ca_payload_hash,
    request_hash: proofResult.requestHash,
    vault_sequence: vaultSequence,
    expiry_secs: expirySecs,
  };
  const msgBytes = encodeWithdrawAttestationMessage(msg);
  console.log(`  attestMsgBytes = ${msgBytes.length} bytes`);

  // 4-of-7 sign with operator keys (slots 0/1/2/3)
  const operatorKeys = loadOperatorKeys();
  const sigSlots: Uint8Array[] = Array.from({ length: 7 }, () => new Uint8Array(0));
  for (const slot of [0, 1, 2, 3]) {
    const k = operatorKeys.find((x) => x.slot === slot)!;
    const seed = fromHex(k.private_key);
    const sig = ed25519.sign(msgBytes, seed);
    sigSlots[slot] = sig;
    console.log(`  signed slot ${slot} sig=0x${hex(sig).slice(0, 30)}...`);
  }

  // ---- 8. Submit withdraw_to_recipient ----
  console.log('\n[step 8] submit withdraw_to_recipient via bridge-relayer ...');
  const tx = await aptos.transaction.build.simple({
    sender: relayerAccount.accountAddress,
    data: {
      function: `${BRIDGE_ADDR}::eunoma_bridge::withdraw_to_recipient`,
      functionArguments: [
        Array.from(root),
        Array.from(proofResult.nullifierHash),
        recipientAddr,
        Array.from(proofResult.recipientHash),
        Array.from(proofResult.amountTag),
        Array.from(ca_payload_hash),
        Array.from(proofResult.requestHash),
        vaultSequence,
        Array.from(proofResult.proofBytes),
        expirySecs,
        sigSlots.map((s) => Array.from(s)),
        // 14 REAL CA payload fields from buildWithdrawCAPayload (Phase 2.X)
        caPayload.newBalanceP.map((c) => Array.from(c)),
        caPayload.newBalanceR.map((c) => Array.from(c)),
        caPayload.newBalanceREffAud.map((c) => Array.from(c)),
        caPayload.amountP.map((c) => Array.from(c)),
        caPayload.amountRSender.map((c) => Array.from(c)),
        caPayload.amountRRecip.map((c) => Array.from(c)),
        caPayload.amountREffAud.map((c) => Array.from(c)),
        caPayload.ekVolunAuds.map((c) => Array.from(c)),
        caPayload.amountRVolunAuds.map((row) => row.map((c) => Array.from(c))),
        Array.from(caPayload.zkrpNewBalance),
        Array.from(caPayload.zkrpAmount),
        caPayload.sigmaProtoComm.map((c) => Array.from(c)),
        caPayload.sigmaProtoResp.map((c) => Array.from(c)),
        Array.from(caPayload.memo),
      ],
    },
    // W3: cap to 500K (was 1M) — fresh-address has < 1 APT after deposit; chain-side
    // withdraw_to_recipient typically uses ~11K gas so 500K is still ~45× margin.
    options: { maxGasAmount: 500_000, gasUnitPrice: 100 },
  });

  console.log('  skipping simulate (ts-sdk simulator gas cap is tighter than chain) ...');
  const submitted = await aptos.signAndSubmitTransaction({
    signer: relayerAccount,
    transaction: tx,
  });
  console.log(`  submitted: ${submitted.hash}`);
  const result: any = await aptos.waitForTransaction({
    transactionHash: submitted.hash,
    options: { checkSuccess: false },
  });

  console.log(`\nWITHDRAW TX SUBMITTED`);
  console.log(`  tx hash       = ${result.hash}`);
  console.log(`  success       = ${result.success}`);
  console.log(`  vm_status     = ${result.vm_status}`);
  console.log(`  gas_used      = ${result.gas_used}`);
  if (result.success) {
    console.log(`  ✓ FULL CA dispatch succeeded — withdraw closed loop ON CHAIN`);
    // Persist tx evidence to state.json for W.5 chain state delta verify + W.6 docs
    updateTargetDeploy((d) => {
      d.withdraw ??= {};
      d.withdraw.tx = result.hash;
      d.withdraw.gas_used = Number(result.gas_used ?? 0);
      d.withdraw.gas_unit_price = Number(result.gas_unit_price ?? 100);
      d.withdraw.amount_octas = amountOctas.toString();
      d.withdraw.recipient = recipientAddr;
      d.withdraw.nullifier_hash = '0x' + hex(proofResult.nullifierHash);
      d.withdraw.recipient_hash = '0x' + hex(proofResult.recipientHash);
      d.withdraw.amount_tag = '0x' + hex(proofResult.amountTag);
      d.withdraw.ca_payload_hash = '0x' + hex(ca_payload_hash);
      d.withdraw.request_hash = '0x' + hex(proofResult.requestHash);
      d.withdraw.vault_sequence_pre = vaultSequence.toString();
      d.withdraw.expiry_secs = expirySecs.toString();
      d.withdraw.withdraw_blind = '0x' + hex(withdrawBlind);
    });
    console.log(`  [state] deploys.${DEPLOY_ID}.withdraw written`);
  } else {
    console.log(`  ✗ UNEXPECTED ABORT — investigate vm_status above`);
  }
}

main().catch((e) => {
  console.error('FATAL:', e);
  process.exit(1);
});

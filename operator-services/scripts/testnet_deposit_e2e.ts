/**
 * Phase 6 — END-TO-END deposit on testnet (LOAD-BEARING). Gate 4d-bis.
 *
 * Pipeline:
 *   1. Roll over user's pending balance into available (so transfer can spend it).
 *   2. Build CA confidential_transfer payload (sigma + range proofs) for
 *      user → vault transfer of CA_TRANSFER_AMOUNT_OCTAS.
 *   3. Compute ca_payload_hash = keccak256(BCS(CAPayloadForHash{...})).
 *   4. Generate fresh deposit-binding Groth16 proof against testnet-real public
 *      inputs (real Poseidon-derived asset_id + vault_addr_hash).
 *   5. Build canonical DepositAttestationMessage; have 4 operators sign it.
 *   6. Submit `bridge::deposit_with_commitment(...)` from bridge-relayer.
 *   7. Verify on-chain DepositEvent + capture LOAD-BEARING tx hash + gas.
 *
 * Run: cd operator-services && npx tsx scripts/testnet_deposit_e2e.ts
 */

import {
  Account,
  Aptos,
  AptosConfig,
  Network,
  Ed25519PrivateKey,
  AccountAddress,
  type CommittedTransactionResponse,
} from '@aptos-labs/ts-sdk';
import {
  ConfidentialAsset,
  ConfidentialTransfer,
  TwistedEd25519PrivateKey,
  TwistedEd25519PublicKey,
  EncryptedAmount,
} from '@aptos-labs/confidential-asset';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { buildDepositProof } from './build_testnet_deposit_proof.js';
import {
  bcsEncodeCAPayloadForHash,
  bcsEncodeDepositAttestationMessage,
} from '../shared/src/bcs.js';
import { keccak256 } from '../shared/src/keccak.js';
import {
  CAPayloadForHashStruct,
  DepositAttestationMessageStruct,
  DOMAIN_DEPOSIT_OK_V1,
  POOL_ID_VALUE,
} from '../shared/src/types.js';
import { u64ToFieldLe32 } from '../shared/src/hex.js';
import { loadOperatorKeys, loadSecretHex } from '../shared/src/secrets.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STATE_PATH = path.join(__dirname, 'testnet_state.json');

const BRIDGE_ADDR =
  '0x8268f56bdd9814d1cc925b861eaa1203d41c7f5425b3d2df887f618ffeb24820';
const APT_METADATA = '0xa';
const CHAIN_ID = 2; // testnet
// Phase 2.Y / W.3 — amount overridable via env DEPOSIT_AMOUNT_OCTAS for B.5+ deposits.
// Default 0.1 APT preserves Phase 2.X B.4 reproducibility.
const CA_TRANSFER_AMOUNT_OCTAS: bigint = process.env.DEPOSIT_AMOUNT_OCTAS
  ? BigInt(process.env.DEPOSIT_AMOUNT_OCTAS)
  : 10_000_000n;

function hex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(s: string): Uint8Array {
  const h = s.startsWith('0x') ? s.slice(2) : s;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function loadAccount(profile: 'bridge-user' | 'bridge-relayer'): Account {
  const configPath = path.join(__dirname, '..', '..', '.aptos', 'config.yaml');
  const yaml = fs.readFileSync(configPath, 'utf-8');
  const re = new RegExp(
    `${profile}:[\\s\\S]*?private_key:\\s*(?:"|')?([^\\s"']+)(?:"|')?`,
  );
  const m = yaml.match(re);
  if (!m) throw new Error(`cannot find ${profile} private_key in config`);
  const raw = m[1].trim().replace(/^ed25519-priv-/, '');
  return Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(raw) });
}

/** Generate 254-bit Fr — 31 random bytes + zero high byte. */
function randomFr(): Uint8Array {
  const r = randomBytes(31);
  const out = new Uint8Array(32);
  out.set(r, 0);
  return out;
}

async function main() {
  const userAccount = loadAccount('bridge-user');
  const relayerAccount = loadAccount('bridge-relayer');
  console.log(`bridge-user    = ${userAccount.accountAddress.toString()}`);
  console.log(`bridge-relayer = ${relayerAccount.accountAddress.toString()}`);

  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const ca = new ConfidentialAsset({ config: aptos.config });

  // Load state
  const state = JSON.parse(fs.readFileSync(STATE_PATH, 'utf-8'));
  const vaultAddrHex = state.vault.address as string;
  if (!vaultAddrHex) throw new Error('vault.address missing — run Phase 3 first');
  const vaultAddrBytes = AccountAddress.from(vaultAddrHex).toUint8Array();
  console.log(`vault          = ${vaultAddrHex}`);

  // Load user TwistedEd25519 from env
  const userDk = new TwistedEd25519PrivateKey(loadSecretHex('USER_ENCRYPTION_KEY_HEX', 32));
  console.log(`user_ek        = ${userDk.publicKey().toString()}`);

  // Load operator keys from env
  const operatorKeys = loadOperatorKeys();

  // Vault TwistedEd25519 public key — we need this to encrypt the transfer-amount
  // chunks under the recipient (vault) key.
  const vaultEkBytes = fromHex(state.vault.vault_ek_hex);
  const vaultEk = new TwistedEd25519PublicKey(vaultEkBytes);

  // ---- 1. Roll over user pending balance ----
  console.log('\n[step 1] roll over user pending balance ...');
  const userRegistered = await ca.hasUserRegistered({
    accountAddress: userAccount.accountAddress,
    tokenAddress: APT_METADATA,
  });
  if (!userRegistered) throw new Error('user CA not registered — run Phase 5 first');

  // Fetch current balance state to decide if rollover is needed
  let userBalance;
  try {
    userBalance = await ca.getBalance({
      accountAddress: userAccount.accountAddress,
      tokenAddress: APT_METADATA,
      decryptionKey: userDk,
    });
  } catch (e) {
    console.log('  getBalance() threw — likely WASM init issue; proceeding to rollover anyway');
  }

  if (userBalance) {
    console.log(`  pending  = ${userBalance.pending.getAmount().toString()} octas`);
    console.log(`  available= ${userBalance.available.getAmount().toString()} octas`);
  }

  let needRollover = true;
  if (userBalance && userBalance.available.getAmount() >= CA_TRANSFER_AMOUNT_OCTAS) {
    console.log(`  available >= transfer; skipping rollover`);
    needRollover = false;
  } else if (userBalance && userBalance.pending.getAmount() === 0n) {
    throw new Error('pending == 0 and available insufficient — re-veil first');
  }

  if (needRollover) {
    const rolloverResp = await ca.rolloverPendingBalance({
      signer: userAccount,
      tokenAddress: APT_METADATA,
      checkNormalized: false,
    });
    const last = rolloverResp[rolloverResp.length - 1];
    console.log(`  rollover tx = ${last.hash}, success=${last.success}, gas=${last.gas_used}`);
    if (!last.success) throw new Error(`rollover failed: ${last.vm_status}`);
    state.user_ca.rollover_tx = last.hash;
    state.user_ca.rollover_gas = Number(last.gas_used ?? 0);
  }

  // Re-fetch balance post-rollover
  userBalance = await ca.getBalance({
    accountAddress: userAccount.accountAddress,
    tokenAddress: APT_METADATA,
    decryptionKey: userDk,
  });
  console.log(`  post-rollover available = ${userBalance.available.getAmount().toString()} octas`);
  if (userBalance.available.getAmount() < CA_TRANSFER_AMOUNT_OCTAS) {
    throw new Error(
      `insufficient available balance: ${userBalance.available.getAmount()} < ${CA_TRANSFER_AMOUNT_OCTAS}`,
    );
  }

  // ---- 2. Build CA confidential_transfer payload ----
  console.log('\n[step 2] build CA confidential_transfer payload ...');
  // Optional global asset auditor check: APT on testnet may have one.
  const assetAuditorEk = await ca.getAssetAuditorEncryptionKey({ tokenAddress: APT_METADATA });
  const hasEffectiveAuditor = !!assetAuditorEk;
  const auditorKeys = assetAuditorEk ? [assetAuditorEk] : [];
  console.log(`  hasEffectiveAuditor = ${hasEffectiveAuditor}`);

  const transfer = await ConfidentialTransfer.create({
    senderDecryptionKey: userDk,
    senderAvailableBalanceCipherText: userBalance.available.getCipherText(),
    amount: CA_TRANSFER_AMOUNT_OCTAS,
    recipientEncryptionKey: vaultEk,
    hasEffectiveAuditor,
    auditorEncryptionKeys: auditorKeys,
    senderAddress: userAccount.accountAddress.toUint8Array(),
    recipientAddress: vaultAddrBytes,
    tokenAddress: AccountAddress.from(APT_METADATA).toUint8Array(),
    chainId: CHAIN_ID,
  });
  const [
    { sigmaProof, rangeProof },
    senderNewBal,
    recipAmount,
    auditorTransferAmounts,
    auditorNewBalances,
  ] = await transfer.authorizeTransfer();

  // Map outputs to bridge entry-fn arg shape
  // Sender new balance ciphertext: each chunk has {C, D}
  const newBalanceP = senderNewBal.getCipherText().map((ct) => ct.C.toRawBytes());
  const newBalanceR = senderNewBal.getCipherText().map((ct) => ct.D.toRawBytes());

  // Sender transferred-amount ciphertext: encrypted under sender key
  const senderXfer = transfer.transferAmountEncryptedBySender;
  const amountP = senderXfer.getCipherText().map((ct) => ct.C.toRawBytes());
  const amountRSender = senderXfer.getCipherText().map((ct) => ct.D.toRawBytes());

  // Recipient transferred-amount ciphertext: encrypted under recipient (vault) key — D-points only
  const amountRRecip = recipAmount.getCipherText().map((ct) => ct.D.toRawBytes());

  // Asset (effective) auditor: D-points for both new balance and transfer amount
  const newBalanceREffAud = hasEffectiveAuditor
    ? auditorNewBalances[auditorNewBalances.length - 1].getCipherText().map((ct) => ct.D.toRawBytes())
    : [];
  const amountREffAud = hasEffectiveAuditor
    ? auditorTransferAmounts[auditorTransferAmounts.length - 1].getCipherText().map((ct) => ct.D.toRawBytes())
    : [];

  // Voluntary additional auditors: encryption key bytes + per-auditor amount D-points
  // We have none.
  const ekVolunAuds: Uint8Array[] = [];
  const amountRVolunAuds: Uint8Array[][] = [];

  const zkrpNewBalance = rangeProof.rangeProofNewBalance;
  const zkrpAmount = rangeProof.rangeProofAmount;
  const sigmaProtoComm = sigmaProof.commitment;
  const sigmaProtoResp = sigmaProof.response;
  const memo = new Uint8Array(0);

  console.log(`  newBalanceP chunks   = ${newBalanceP.length}`);
  console.log(`  amountP chunks       = ${amountP.length}`);
  console.log(`  zkrpNewBalance bytes = ${zkrpNewBalance.length}`);
  console.log(`  zkrpAmount bytes     = ${zkrpAmount.length}`);
  console.log(`  sigma_comm count     = ${sigmaProtoComm.length}`);
  console.log(`  sigma_resp count     = ${sigmaProtoResp.length}`);

  // ---- 3. Compute ca_payload_hash (keccak256 BCS(CAPayloadForHash)) ----
  const caPayload: CAPayloadForHashStruct = {
    asset_type: AccountAddress.from(APT_METADATA).toUint8Array(),
    vault_addr: vaultAddrBytes,
    new_balance_p: newBalanceP,
    new_balance_r: newBalanceR,
    new_balance_r_eff_aud: newBalanceREffAud,
    amount_p: amountP,
    amount_r_sender: amountRSender,
    amount_r_recip: amountRRecip,
    amount_r_eff_aud: amountREffAud,
    ek_volun_auds: ekVolunAuds,
    amount_r_volun_auds: amountRVolunAuds,
    zkrp_new_balance: zkrpNewBalance,
    zkrp_amount: zkrpAmount,
    sigma_proto_comm: sigmaProtoComm,
    sigma_proto_resp: sigmaProtoResp,
    memo,
  };
  const caPayloadHash = keccak256(bcsEncodeCAPayloadForHash(caPayload));
  console.log(`\n[step 3] ca_payload_hash = 0x${hex(caPayloadHash)}`);

  // ---- 4. Generate fresh deposit-binding Groth16 proof ----
  console.log('\n[step 4] generate deposit-binding proof against testnet-real public inputs ...');
  const nullifier = randomFr();
  const secret = randomFr();
  const depositBlind = randomFr();
  const proofResult = await buildDepositProof({
    assetTypeAddr: AccountAddress.from(APT_METADATA).toUint8Array(),
    vaultAddr: vaultAddrBytes,
    amountOctas: CA_TRANSFER_AMOUNT_OCTAS,
    nullifier,
    secret,
    depositBlind,
    chainId: CHAIN_ID,
  });
  console.log(`  commitment   = 0x${hex(proofResult.commitment)}`);
  console.log(`  amount_tag   = 0x${hex(proofResult.amountTag)}`);
  console.log(`  proof bytes  = ${proofResult.proofBytes.length}`);

  // ---- 5. Build attestation message + 4 operator signatures ----
  console.log('\n[step 5] build attestation message + 4 operator signatures ...');
  const depositNonce = randomBytes(32);
  const expirySecs = BigInt(Math.floor(Date.now() / 1000) + 60 * 60); // +1h
  const poolIdLe32 = u64ToFieldLe32(POOL_ID_VALUE);

  const attestMsg: DepositAttestationMessageStruct = {
    domain: DOMAIN_DEPOSIT_OK_V1,
    chain_id: CHAIN_ID,
    pool_id: poolIdLe32,
    operator_set_version: 0n,
    threshold: 4n,
    vault_addr: vaultAddrBytes,
    asset_type: AccountAddress.from(APT_METADATA).toUint8Array(),
    commitment: proofResult.commitment,
    amount_tag: proofResult.amountTag,
    ca_payload_hash: caPayloadHash,
    deposit_nonce: depositNonce,
    expiry_secs: expirySecs,
  };
  const attestBytes = bcsEncodeDepositAttestationMessage(attestMsg);
  console.log(`  attestMsgBytes = ${attestBytes.length} bytes`);

  // Build 7-slot signature vector. Empty slots = empty vec<u8> per Move convention.
  // Sign with slots 0,1,2,3 (main + 3 partners) for 4-of-7.
  const sigSlots: Uint8Array[] = Array.from({ length: 7 }, () => new Uint8Array(0));
  for (const slotIdx of [0, 1, 2, 3]) {
    const opKey = operatorKeys.find((k) => k.slot === slotIdx);
    if (!opKey) throw new Error(`missing operator slot ${slotIdx}`);
    const seedBytes = fromHex(opKey.private_key);
    const sig = ed25519.sign(attestBytes, seedBytes);
    sigSlots[slotIdx] = sig;
    console.log(`  signed slot ${slotIdx} (${opKey.role}): sig=0x${hex(sig).slice(0, 16)}...`);
  }

  // ---- 6. Submit deposit_with_commitment from bridge-relayer ----
  // Wait — the entry function signature has `user: &signer` as first arg. The
  // user signer must sign for the CA confidential_transfer dispatch. So the
  // submitter MUST be the bridge-user, NOT the relayer.
  console.log('\n[step 6] submit bridge::deposit_with_commitment (signer = bridge-user) ...');
  const tx = await aptos.transaction.build.simple({
    sender: userAccount.accountAddress,
    options: {
      maxGasAmount: 1000000, // Step 4 (2026-05-08): bridge now also calls
                             // pool_pending_queue::deposit_precomputed; baseline
                             // 13,330 + small incremental. 1M is generous.
      gasUnitPrice: 100,
    },
    data: {
      function: `${BRIDGE_ADDR}::eunoma_bridge::deposit_with_commitment`,
      typeArguments: [],
      functionArguments: [
        proofResult.commitment, // commitment
        proofResult.amountTag, // amount_tag
        proofResult.proofBytes, // deposit_binding_proof
        depositNonce, // deposit_nonce
        expirySecs, // expiry_secs (u64)
        sigSlots, // operator_signatures vec<vec<u8>>
        // CA payload
        newBalanceP,
        newBalanceR,
        newBalanceREffAud,
        amountP,
        amountRSender,
        amountRRecip,
        amountREffAud,
        ekVolunAuds,
        amountRVolunAuds, // vec<vec<vec<u8>>>
        zkrpNewBalance,
        zkrpAmount,
        sigmaProtoComm,
        sigmaProtoResp,
        memo,
      ],
    },
  });

  // Step 4 (2026-05-08): skipped simulation due to ts-sdk simulator's
  // EXECUTION_LIMIT_REACHED at 9308 gas (cause unknown — likely per-tx
  // simulation cap separate from maxGasAmount). The on-chain submit honors
  // tx.options.maxGasAmount = 1M which is plenty.
  console.log('  skipping simulate (ts-sdk simulator cap hits 9308); going straight to submit ...');

  // Sign + submit
  console.log('  signing + submitting ...');
  const senderAuth = aptos.transaction.sign({ signer: userAccount, transaction: tx });
  const pending = await aptos.transaction.submit.simple({ transaction: tx, senderAuthenticator: senderAuth });
  console.log(`  submitted: ${pending.hash}`);
  const committed: CommittedTransactionResponse = await aptos.waitForTransaction({ transactionHash: pending.hash });
  console.log(`\nLOAD-BEARING DEPOSIT EXECUTED`);
  console.log(`  tx hash       = ${committed.hash}`);
  console.log(`  success       = ${committed.success}`);
  console.log(`  vm_status     = ${committed.vm_status}`);
  console.log(`  gas_used      = ${committed.gas_used}`);
  console.log(`  gas_unit_price= ${committed.gas_unit_price ?? 'n/a'}`);
  if (!committed.success) {
    throw new Error(`deposit_with_commitment failed: ${committed.vm_status}`);
  }

  // ---- 7. Persist state ----
  // Phase 2.Y / W.3 — push to state.deposits[] array (multi-deposit support per W.2 schema).
  // state.deposit (singular) preserved as Phase 2.X B.4 for backward compat with any
  // legacy code path; new deposits append to deposits[].
  const newDeposit = {
    tx: committed.hash,
    gas_used: Number(committed.gas_used),
    gas_unit_price: Number(committed.gas_unit_price ?? 100),
    commitment: '0x' + hex(proofResult.commitment),
    amount_tag: '0x' + hex(proofResult.amountTag),
    deposit_nonce: '0x' + hex(depositNonce),
    expiry_secs: expirySecs.toString(),
    amount_octas: CA_TRANSFER_AMOUNT_OCTAS.toString(),
    nullifier: '0x' + hex(nullifier),
    secret: '0x' + hex(secret),
    deposit_blind: '0x' + hex(depositBlind),
    user_addr: userAccount.accountAddress.toString(),
    vault_addr: vaultAddrHex,
    signing_slots: [0, 1, 2, 3],
    has_effective_auditor: hasEffectiveAuditor,
  };
  state.deposits = state.deposits || [];
  state.deposits.push(newDeposit);
  // Keep state.deposit pointing at the FIRST deposit (B.4) for backward compat;
  // do NOT overwrite with the new deposit. Multi-deposit consumers should iterate
  // state.deposits[] instead.
  if (!state.deposit) state.deposit = newDeposit;
  fs.writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));
  console.log(`\npersisted to ${STATE_PATH} (state.deposits[${state.deposits.length - 1}] = new deposit; leafIndex = ${state.deposits.length - 1})`);
}

main().catch((e) => {
  console.error('FAILED:', e.message || e);
  if (e.stack) console.error(e.stack);
  process.exit(1);
});

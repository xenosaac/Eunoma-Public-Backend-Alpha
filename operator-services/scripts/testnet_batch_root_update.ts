/**
 * Phase B post-closure: testnet batch finalization (Phase 1 闭环最后一步)
 *
 * Reads on-chain bridge state, computes off-chain queue_range_hash + new_root +
 * frontier_meta_hash via spike's Poseidon helpers, builds BCS canonical
 * BatchUpdateAttestationMessage, signs 4-of-7 with REAL operator keys from
 * .operator-keys.json (NOT spike deterministic seeds), and submits
 * pool_batch_root_update::update_root_batch via bridge-relayer.
 *
 * Convention notes:
 *   - empty_tree_root on chain = ZERO32 literal (per init at Phase A)
 *   - Operators trusted to compute new_root consistently (Move side does not
 *     re-derive merkle root algorithmically; new_root is consent-validated by
 *     the 4-of-7 signature check over the BCS-encoded message).
 *   - batch_id = last_batch_id + 1 (INV6); first batch = 1.
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'node:url';
import {
  Account,
  Aptos,
  AptosConfig,
  Network,
  Ed25519PrivateKey,
  Serializer,
} from '@aptos-labs/ts-sdk';
import { loadOperatorKeys, loadSecretHex } from '../shared/src/secrets.js';
import { initPoseidon, poseidon2 } from '../shared/src/batch_updater_poseidon.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Phase 4 / W4 — Poseidon batch helpers now live in @eunoma/shared (was
// Poseidon_Research/AptosShield_Spike/operator/batch_updater.ts via
// createRequire ESM→CJS bridge). mvp-backend is now self-contained.

// ----- helpers (inlined from spike, only what's not exported) -----

const ZERO32 = new Uint8Array(32);

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  if (s.length % 2 !== 0) throw new Error('odd hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.substr(i * 2, 2), 16);
  }
  return out;
}

function toHex(b: Uint8Array): string {
  return '0x' + Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

function u64ToFrLE(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = n;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

const TREE_DEPTH = 20;

function emptyFrontier(): { nodes: Uint8Array[]; nextLeafIndex: bigint } {
  return {
    nodes: Array.from({ length: TREE_DEPTH }, () => ZERO32),
    nextLeafIndex: 0n,
  };
}

function frontierInsert(
  f: { nodes: Uint8Array[]; nextLeafIndex: bigint },
  leaf: Uint8Array,
): { nodes: Uint8Array[]; nextLeafIndex: bigint } {
  let cur = leaf;
  let idx = f.nextLeafIndex;
  const nodes = [...f.nodes];
  for (let level = 0; level < TREE_DEPTH; level++) {
    if ((idx & 1n) === 0n) {
      nodes[level] = cur;
      cur = poseidon2(cur, ZERO32);
    } else {
      cur = poseidon2(nodes[level], cur);
    }
    idx >>= 1n;
  }
  return { nodes, nextLeafIndex: f.nextLeafIndex + 1n };
}

function frontierRoot(f: { nodes: Uint8Array[]; nextLeafIndex: bigint }): Uint8Array {
  let cur: Uint8Array = ZERO32;
  let idx = f.nextLeafIndex;
  for (let level = 0; level < TREE_DEPTH; level++) {
    if ((idx & 1n) === 0n) {
      cur = poseidon2(cur, ZERO32);
    } else {
      cur = poseidon2(f.nodes[level], cur);
    }
    idx >>= 1n;
  }
  return cur;
}

function frontierMetaHash(f: { nodes: Uint8Array[]; nextLeafIndex: bigint }): Uint8Array {
  let acc: Uint8Array = u64ToFrLE(f.nextLeafIndex);
  for (const n of f.nodes) {
    acc = poseidon2(acc, n);
  }
  return acc;
}

// BCS encoding — must match Move BatchUpdateAttestationMessage field order EXACTLY
function encodeAttestationMessage(msg: {
  domain: Uint8Array;
  chain_id: number;
  pool_id: Uint8Array;
  operator_set_version: bigint;
  old_root: Uint8Array;
  new_root: Uint8Array;
  start_index: bigint;
  end_index: bigint;
  batch_size: bigint;
  queue_range_hash: Uint8Array;
  frontier_or_meta_hash: Uint8Array;
  batch_id: bigint;
}): Uint8Array {
  const ser = new Serializer();
  ser.serializeBytes(msg.domain);
  ser.serializeU8(msg.chain_id);
  ser.serializeBytes(msg.pool_id);
  ser.serializeU64(msg.operator_set_version);
  ser.serializeBytes(msg.old_root);
  ser.serializeBytes(msg.new_root);
  ser.serializeU64(msg.start_index);
  ser.serializeU64(msg.end_index);
  ser.serializeU64(msg.batch_size);
  ser.serializeBytes(msg.queue_range_hash);
  ser.serializeBytes(msg.frontier_or_meta_hash);
  ser.serializeU64(msg.batch_id);
  return ser.toUint8Array();
}

import { targetBridge, targetDeploy, targetDeployId } from './_lib/state.js';

const BRIDGE_ADDR = targetBridge();
const DEPLOY_ID = targetDeployId();

async function main() {
  console.log('Phase 1 closed-loop test: testnet batch_root_update');
  console.log('===================================================');

  await initPoseidon();
  console.log('[init] poseidon initialized');

  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));

  // Step 1: read on-chain state
  console.log('\n[step 1] reading on-chain state...');
  const vaultConfig = (await aptos.getAccountResource({
    accountAddress: BRIDGE_ADDR,
    resourceType: `${BRIDGE_ADDR}::eunoma_bridge::VaultConfig`,
  })) as any;
  const pendingQueue = (await aptos.getAccountResource({
    accountAddress: BRIDGE_ADDR,
    resourceType: `${BRIDGE_ADDR}::pool_pending_queue::PendingQueue`,
  })) as any;
  const rootHistory = (await aptos.getAccountResource({
    accountAddress: BRIDGE_ADDR,
    resourceType: `${BRIDGE_ADDR}::pool_batch_root_update::RootHistory`,
  })) as any;

  const operator_set_version = BigInt(rootHistory.operator_set_version);
  const last_batch_id = BigInt(rootHistory.last_batch_id);
  const next_unfinalized_index = BigInt(rootHistory.next_unfinalized_index);
  const chain_id = Number(rootHistory.chain_id);
  const pool_id_bytes = hexToBytes(rootHistory.pool_id);
  const old_root = hexToBytes(rootHistory.root_history[rootHistory.root_history.length - 1]);

  const next_index = BigInt(pendingQueue.next_index);
  const acc_history: Uint8Array[] = pendingQueue.acc_history.map((h: string) => hexToBytes(h));

  console.log(`  vault.attestation_threshold = ${vaultConfig.attestation_threshold}`);
  console.log(`  vault.main_operator_index   = ${vaultConfig.main_operator_index}`);
  console.log(`  vault.operator_set_version  = ${vaultConfig.operator_set_version}`);
  console.log(`  pool.next_index             = ${next_index} (queued deposits)`);
  console.log(`  pool.acc_history.length     = ${acc_history.length}`);
  console.log(`  root_history.last_batch_id  = ${last_batch_id}`);
  console.log(`  root_history.length         = ${rootHistory.root_history.length}`);
  console.log(`  current_finalized_root      = ${toHex(old_root)}`);
  console.log(`  pool_id (hex)               = ${rootHistory.pool_id}`);
  console.log(`  pool_id (utf8)              = ${Buffer.from(pool_id_bytes).toString('utf-8')}`);

  // Step 2: choose batch range
  const start_index = next_unfinalized_index;
  const end_index = next_index; // finalize all currently-queued
  const batch_size = end_index - start_index;
  if (batch_size <= 0n) {
    throw new Error(`no deposits to finalize (next_unfinalized=${start_index}, next_index=${end_index})`);
  }
  console.log(`\n[step 2] batch range: [${start_index}, ${end_index}), batch_size = ${batch_size}`);

  // Step 3: compute queue_range_hash (matches pending_queue::compute_range_hash)
  const queue_range_hash = poseidon2(
    acc_history[Number(start_index)],
    acc_history[Number(end_index)],
  );
  console.log(`[step 3] queue_range_hash = ${toHex(queue_range_hash)}`);

  // Step 4: harvest leaves from the deposit tx that queued them.
  // W.4: dynamic — pick the deposit tx by start_index from the deploy's
  // deposits[] array. Sanity check below verifies leaf vs on-chain acc_history.
  const depositList = (targetDeploy().deposits ?? []) as { tx: string; commitment: string }[];
  if (depositList.length <= Number(start_index)) {
    throw new Error(
      `deploys.${DEPLOY_ID}.deposits[${start_index}] not found — expected at least ${Number(start_index) + 1} deposit entries; ` +
      `re-run testnet_deposit_e2e.ts to populate`,
    );
  }
  const depositTxHash = depositList[Number(start_index)].tx;
  console.log(`[step 4] using deposit tx ${depositTxHash} (= deploys.${DEPLOY_ID}.deposits[${start_index}])`);
  const depTxResp = await fetch(
    `https://fullnode.testnet.aptoslabs.com/v1/transactions/by_hash/${depositTxHash}`,
  );
  const depTx: any = await depTxResp.json();
  const queueEvents = (depTx.events || []).filter(
    (e: any) => e.type === `${BRIDGE_ADDR}::pool_pending_queue::DepositQueued`,
  );
  const targetEvents = queueEvents
    .filter((e: any) => {
      const idx = BigInt(e.data.deposit_index);
      return idx >= start_index && idx < end_index;
    })
    .sort((a: any, b: any) => Number(BigInt(a.data.deposit_index) - BigInt(b.data.deposit_index)));
  if (targetEvents.length !== Number(batch_size)) {
    throw new Error(
      `expected ${batch_size} deposit events in range, got ${targetEvents.length}; ` +
      `from tx ${depositTxHash}`,
    );
  }
  const leaves = targetEvents.map((e: any) => hexToBytes(e.data.leaf_commitment));
  console.log(`  leaves (${leaves.length}) from tx ${depositTxHash}:`);
  for (let i = 0; i < leaves.length; i++) {
    console.log(`    [${i}] = ${toHex(leaves[i])}`);
  }
  const leaf = leaves[0]; // for batch_size=1

  // Verify our leaf assumption: rebuild acc_history[1] and compare on-chain
  const idxFr = u64ToFrLE(start_index);
  const leafAccInput = poseidon2(idxFr, leaf);
  const accCheck = poseidon2(acc_history[Number(start_index)], leafAccInput);
  if (toHex(accCheck) !== toHex(acc_history[Number(end_index)])) {
    throw new Error(
      `acc_history mismatch — operator-side leaf does not match on-chain accumulator!\n` +
      `  computed: ${toHex(accCheck)}\n` +
      `  on-chain: ${toHex(acc_history[Number(end_index)])}`,
    );
  }
  console.log(`  ✓ leaf verified against on-chain acc_history[${end_index}]`);

  // Phase 2.Y / W.4: seed frontier with all previously-finalized leaves
  // (= state.deposits[0..start_index-1]) so this batch's insert lands at the
  // correct position. For batch 1 (B.4), start_index=0 and the loop body is
  // skipped (= emptyFrontier as before).
  let frontier = emptyFrontier();
  for (let i = 0; i < Number(start_index); i++) {
    const prevLeaf = hexToBytes(depositList[i].commitment);
    frontier = frontierInsert(frontier, prevLeaf);
  }
  console.log(`  seeded frontier with ${Number(start_index)} prior leaf(s)`);
  frontier = frontierInsert(frontier, leaf);
  const new_root = frontierRoot(frontier);
  const meta_hash = frontierMetaHash(frontier);
  console.log(`[step 4] new_root           = ${toHex(new_root)}`);
  console.log(`         frontier_meta_hash = ${toHex(meta_hash)}`);

  // Step 5: build BCS message
  const DOMAIN = new TextEncoder().encode('APTOSHIELD_BATCH_ROOT_UPDATE_V1');
  const batch_id = last_batch_id + 1n;
  const message = {
    domain: DOMAIN,
    chain_id,
    pool_id: pool_id_bytes,
    operator_set_version,
    old_root,
    new_root,
    start_index,
    end_index,
    batch_size,
    queue_range_hash,
    frontier_or_meta_hash: meta_hash,
    batch_id,
  };
  const msgBytes = encodeAttestationMessage(message);
  console.log(`\n[step 5] BCS message ${msgBytes.length} bytes; batch_id = ${batch_id}`);
  console.log(`         msg hex = ${toHex(msgBytes).slice(0, 100)}...`);

  // Step 6: sign with 4-of-7 (slots 0,1,2,3; main = 0)
  const operatorKeys = loadOperatorKeys();

  // Sanity: verify on-chain pubkeys match env-loaded keys
  const onchainPubkeys: string[] = vaultConfig.operator_pubkeys.map((p: string) => p.toLowerCase());
  for (const k of operatorKeys) {
    const onchain = onchainPubkeys[k.slot];
    const local = k.public_key.replace('0x', '').toLowerCase();
    if (onchain.replace('0x', '') !== local) {
      throw new Error(`slot ${k.slot} pubkey mismatch: chain=${onchain} local=${local}`);
    }
  }
  console.log(`[step 6] all 7 operator pubkeys match between OPERATOR_KEYS_JSON_B64 and on-chain VaultConfig`);

  const sigs: Uint8Array[] = Array.from({ length: 7 }, () => new Uint8Array(0));
  for (const slot of [0, 1, 2, 3]) {
    const k = operatorKeys.find((x) => x.slot === slot)!;
    const sk = new Ed25519PrivateKey(hexToBytes(k.private_key));
    const sig = sk.sign(msgBytes);
    sigs[slot] = sig.toUint8Array();
    console.log(`  slot ${slot} (${k.private_key.slice(0, 20)}...): sig ${toHex(sigs[slot]).slice(0, 30)}...`);
  }

  // Step 7: build + submit transaction
  console.log(`\n[step 7] submitting update_root_batch via bridge-relayer...`);
  const relayer = Account.fromPrivateKey({
    privateKey: new Ed25519PrivateKey(hexToBytes(loadSecretHex('RELAYER_PRIVATE_KEY_HEX', 32))),
  });
  console.log(`  relayer address = ${relayer.accountAddress.toString()}`);

  const tx = await aptos.transaction.build.simple({
    sender: relayer.accountAddress,
    data: {
      function: `${BRIDGE_ADDR}::pool_batch_root_update::update_root_batch`,
      functionArguments: [
        Array.from(old_root),
        Array.from(new_root),
        start_index,
        end_index,
        batch_size,
        Array.from(queue_range_hash),
        Array.from(meta_hash),
        batch_id,
        sigs.map((s) => Array.from(s)),
      ],
    },
    options: { maxGasAmount: 500_000, gasUnitPrice: 100 },
  });

  const submitted = await aptos.signAndSubmitTransaction({ signer: relayer, transaction: tx });
  console.log(`  submitted: ${submitted.hash}`);
  const result = await aptos.waitForTransaction({ transactionHash: submitted.hash });
  console.log(`\nLOAD-BEARING BATCH ROOT UPDATE EXECUTED`);
  console.log(`  tx hash      = ${result.hash}`);
  console.log(`  success      = ${result.success}`);
  console.log(`  vm_status    = ${result.vm_status}`);
  console.log(`  gas_used     = ${result.gas_used}`);
  if (!result.success) throw new Error('tx FAILED');
}

main().catch((e) => {
  console.error('FATAL:', e);
  process.exit(1);
});

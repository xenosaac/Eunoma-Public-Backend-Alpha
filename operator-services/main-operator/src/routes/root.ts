import type { FastifyInstance } from "fastify";
import {
  Account,
  Aptos,
  AptosConfig,
  Ed25519PrivateKey,
  Network,
  Serializer,
} from "@aptos-labs/ts-sdk";
import { loadOperatorKeys, loadSecretHex, initPoseidon, poseidon2 } from "@eunoma/shared";
import type { MainOperatorConfig } from "../config.js";

const ZERO32 = new Uint8Array(32);
const TREE_DEPTH = 20;
const DOMAIN = new TextEncoder().encode("APTOSHIELD_BATCH_ROOT_UPDATE_V1");

export interface RootCurrent {
  current_finalized_root: string;
  root_history_length: string;
  last_batch_id: string;
  next_unfinalized_index: string;
  pending_next_index: string;
  pending_count: string;
}

export interface RootUpdateResult {
  status: "updated";
  tx: string;
  success: boolean;
  vm_status: string;
  gas_used: string;
  start_index: string;
  end_index: string;
  new_root: string;
  rollover_tx: null | string;
}

export interface RootRouteHooks {
  readRootCurrent?: () => Promise<RootCurrent>;
  updateRootBatch?: (input: { max_batch_size: number }) => Promise<RootUpdateResult | { status: "noop"; reason: "no_pending_deposits" }>;
}

function networkFromConfig(cfg: MainOperatorConfig): Network {
  if (cfg.network === "mainnet") return Network.MAINNET;
  if (cfg.network === "devnet") return Network.DEVNET;
  return Network.TESTNET;
}

function bridgeAddr(cfg: MainOperatorConfig): string {
  return cfg.bridge_package_address ?? process.env.BRIDGE_PACKAGE_ADDRESS ?? ("0x" + "11".repeat(32));
}

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  if (s.length % 2 !== 0) throw new Error("odd_hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(b: Uint8Array): string {
  return "0x" + Buffer.from(b).toString("hex");
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

function emptyFrontier(): { nodes: Uint8Array[]; nextLeafIndex: bigint } {
  return { nodes: Array.from({ length: TREE_DEPTH }, () => ZERO32), nextLeafIndex: 0n };
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
  let cur = ZERO32;
  let idx = f.nextLeafIndex;
  for (let level = 0; level < TREE_DEPTH; level++) {
    if ((idx & 1n) === 0n) cur = new Uint8Array(poseidon2(cur, ZERO32));
    else cur = new Uint8Array(poseidon2(f.nodes[level], cur));
    idx >>= 1n;
  }
  return cur;
}

function frontierMetaHash(f: { nodes: Uint8Array[]; nextLeafIndex: bigint }): Uint8Array {
  let acc = u64ToFrLE(f.nextLeafIndex);
  for (const n of f.nodes) acc = poseidon2(acc, n);
  return acc;
}

function encodeAttestationMessage(msg: {
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
  ser.serializeBytes(DOMAIN);
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

async function readCurrentFromChain(aptos: Aptos, bridge: string): Promise<RootCurrent> {
  const rootHistory = (await aptos.getAccountResource({
    accountAddress: bridge,
    resourceType: `${bridge}::pool_batch_root_update::RootHistory`,
  })) as any;
  const pendingQueue = (await aptos.getAccountResource({
    accountAddress: bridge,
    resourceType: `${bridge}::pool_pending_queue::PendingQueue`,
  })) as any;
  const nextUnfinalized = BigInt(rootHistory.next_unfinalized_index);
  const pendingNext = BigInt(pendingQueue.next_index);
  const roots = rootHistory.root_history ?? [];
  const current = rootHistory.current_finalized_root ?? roots[roots.length - 1] ?? toHex(ZERO32);
  return {
    current_finalized_root: current,
    root_history_length: String(roots.length),
    last_batch_id: BigInt(rootHistory.last_batch_id).toString(),
    next_unfinalized_index: nextUnfinalized.toString(),
    pending_next_index: pendingNext.toString(),
    pending_count: (pendingNext - nextUnfinalized).toString(),
  };
}

async function viewBytes(aptos: Aptos, functionId: string, args: unknown[]): Promise<Uint8Array> {
  const result = await (aptos as any).view({
    payload: {
      function: functionId,
      functionArguments: args,
    },
  });
  const first = Array.isArray(result) ? result[0] : result;
  if (typeof first === "string") return hexToBytes(first);
  if (Array.isArray(first)) return new Uint8Array(first.map(Number));
  throw new Error("unexpected_view_result");
}

async function defaultUpdateRootBatch(
  cfg: MainOperatorConfig,
  input: { max_batch_size: number },
): Promise<RootUpdateResult | { status: "noop"; reason: "no_pending_deposits" }> {
  await initPoseidon();
  const aptos = new Aptos(new AptosConfig({ network: networkFromConfig(cfg) }));
  const bridge = bridgeAddr(cfg);
  const rootHistory = (await aptos.getAccountResource({
    accountAddress: bridge,
    resourceType: `${bridge}::pool_batch_root_update::RootHistory`,
  })) as any;
  const pendingQueue = (await aptos.getAccountResource({
    accountAddress: bridge,
    resourceType: `${bridge}::pool_pending_queue::PendingQueue`,
  })) as any;
  const vaultConfig = (await aptos.getAccountResource({
    accountAddress: bridge,
    resourceType: `${bridge}::eunoma_bridge::VaultConfig`,
  })) as any;

  const startIndex = BigInt(rootHistory.next_unfinalized_index);
  const pendingNext = BigInt(pendingQueue.next_index);
  if (pendingNext <= startIndex) return { status: "noop", reason: "no_pending_deposits" };

  const maxBatch = BigInt(input.max_batch_size);
  const endIndex = pendingNext - startIndex > maxBatch ? startIndex + maxBatch : pendingNext;
  const batchSize = endIndex - startIndex;
  const roots = rootHistory.root_history ?? [];
  const oldRoot = hexToBytes(rootHistory.current_finalized_root ?? roots[roots.length - 1]);
  const accHistory = pendingQueue.acc_history as string[];
  const queueRangeHash = poseidon2(hexToBytes(accHistory[Number(startIndex)]), hexToBytes(accHistory[Number(endIndex)]));

  let frontier = emptyFrontier();
  for (let i = 0n; i < endIndex; i++) {
    const leaf = await viewBytes(aptos, `${bridge}::pool_pending_queue::commitment_at_index`, [i.toString()]);
    frontier = frontierInsert(frontier, leaf);
  }
  const newRoot = frontierRoot(frontier);
  const metaHash = frontierMetaHash(frontier);
  const batchId = BigInt(rootHistory.last_batch_id) + 1n;
  const operatorSetVersion = BigInt(rootHistory.operator_set_version);
  const chainId = Number(rootHistory.chain_id);
  const poolId = hexToBytes(rootHistory.pool_id);
  const msgBytes = encodeAttestationMessage({
    chain_id: chainId,
    pool_id: poolId,
    operator_set_version: operatorSetVersion,
    old_root: oldRoot,
    new_root: newRoot,
    start_index: startIndex,
    end_index: endIndex,
    batch_size: batchSize,
    queue_range_hash: queueRangeHash,
    frontier_or_meta_hash: metaHash,
    batch_id: batchId,
  });

  const onchainPubkeys: string[] = (vaultConfig.operator_pubkeys ?? []).map((p: string) => p.replace(/^0x/, "").toLowerCase());
  const operatorKeys = loadOperatorKeys();
  const sigs: Uint8Array[] = Array.from({ length: 7 }, () => new Uint8Array(0));
  for (const slot of [0, 1, 2, 3]) {
    const key = operatorKeys.find((k) => k.slot === slot);
    if (!key) throw new Error("operator_key_missing");
    const localPub = key.public_key.replace(/^0x/, "").toLowerCase();
    if (onchainPubkeys[slot] && onchainPubkeys[slot] !== localPub) {
      throw new Error("operator_pubkey_mismatch");
    }
    const sk = new Ed25519PrivateKey(hexToBytes(key.private_key));
    sigs[slot] = sk.sign(msgBytes).toUint8Array();
  }

  const relayer = Account.fromPrivateKey({
    privateKey: new Ed25519PrivateKey(hexToBytes(loadSecretHex("RELAYER_PRIVATE_KEY_HEX", 32))),
  });
  const tx = await aptos.transaction.build.simple({
    sender: relayer.accountAddress,
    data: {
      function: `${bridge}::pool_batch_root_update::update_root_batch`,
      functionArguments: [
        Array.from(oldRoot),
        Array.from(newRoot),
        startIndex,
        endIndex,
        batchSize,
        Array.from(queueRangeHash),
        Array.from(metaHash),
        batchId,
        sigs.map((s) => Array.from(s)),
      ],
    },
    options: { maxGasAmount: 500_000, gasUnitPrice: 100 },
  });
  const submitted = await aptos.signAndSubmitTransaction({ signer: relayer, transaction: tx });
  const result: any = await aptos.waitForTransaction({
    transactionHash: submitted.hash,
    options: { checkSuccess: false },
  });
  return {
    status: "updated",
    tx: result.hash ?? submitted.hash,
    success: Boolean(result.success),
    vm_status: String(result.vm_status ?? ""),
    gas_used: String(result.gas_used ?? "0"),
    start_index: startIndex.toString(),
    end_index: endIndex.toString(),
    new_root: toHex(newRoot),
    rollover_tx: null,
  };
}

export function registerRootRoutes(
  fastify: FastifyInstance,
  cfg: MainOperatorConfig,
  hooks: RootRouteHooks = {},
): void {
  fastify.get("/v1/root/current", async (_req, reply) => {
    try {
      const read = hooks.readRootCurrent ?? (() => readCurrentFromChain(new Aptos(new AptosConfig({ network: networkFromConfig(cfg) })), bridgeAddr(cfg)));
      return reply.code(200).send(await read());
    } catch {
      return reply.code(502).send({ error: "chain_state_unavailable" });
    }
  });

  fastify.post("/v1/root/update", async (req, reply) => {
    const body = (req.body ?? {}) as { max_batch_size?: unknown };
    const raw = body.max_batch_size ?? 32;
    if (!Number.isInteger(raw) || Number(raw) < 1 || Number(raw) > 256) {
      return reply.code(400).send({ error: "invalid_max_batch_size" });
    }
    try {
      const update = hooks.updateRootBatch ?? ((input) => defaultUpdateRootBatch(cfg, input));
      return reply.code(200).send(await update({ max_batch_size: Number(raw) }));
    } catch {
      return reply.code(502).send({ error: "root_update_failed" });
    }
  });
}

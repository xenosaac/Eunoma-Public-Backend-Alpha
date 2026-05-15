import { randomBytes } from "node:crypto";
import { bytesToHex, hexToBytes } from "@eunoma/shared";
import { CA_DKG_SCHEME_LOCAL, CA_DKG_SCHEME_V2, DEOPERATOR_COUNT, DEOPERATOR_THRESHOLD } from "./constants.js";
import { caDkgV2RosterHash, rosterHash, validateCaDkgV2Roster, validateRoster } from "./roster.js";
import type { CaDkgScheme, CaDkgV2Roster, DeoperatorRoster } from "./types.js";

export interface LocalFrostMaterial {
  groupPublicKey: string;
  verifyingShares: Array<{
    slot: number;
    frostVerifyingShare: string;
  }>;
}

export interface LocalCaDkgV2Material {
  hpkePublicKeys: Array<{
    slot: number;
    hpkePublicKey: string;
  }>;
}

export interface LocalClusterPlanOptions {
  frost: LocalFrostMaterial;
  caDkgV2?: LocalCaDkgV2Material;
  vaultEk: string;
  stateRoot?: string;
  coordinatorPort?: number;
  nodePortBase?: number;
  workerPortBase?: number;
  relayerPort?: number;
  host?: string;
  operatorSetVersion?: string;
  dkgEpoch?: string;
  caDkgScheme?: CaDkgScheme;
  aptosNodeUrl?: string;
  randomHex?: (bytes: number, label: string) => string;
}

export interface LocalServiceEnv {
  name: string;
  env: Record<string, string>;
}

export interface LocalClusterPlan {
  stateRoot: string;
  roster: DeoperatorRoster;
  rosterHash: string;
  caDkgV2Roster?: CaDkgV2Roster;
  caDkgV2RosterHash?: string;
  nodeBearerTokens: Record<string, string>;
  coordinator: LocalServiceEnv & { port: number };
  relayer: LocalServiceEnv & { port: number };
  nodes: Array<LocalServiceEnv & { slot: number; port: number }>;
  workers: Array<LocalServiceEnv & { slot: number; port: number; stateDir: string }>;
}

export function buildLocalClusterPlan(opts: LocalClusterPlanOptions): LocalClusterPlan {
  const host = opts.host ?? "127.0.0.1";
  if (host !== "127.0.0.1" && host !== "localhost" && host !== "::1") {
    throw new Error("local cluster services must bind localhost only");
  }
  const stateRoot = opts.stateRoot ?? ".agent-local/eunoma-v2";
  const coordinatorPort = opts.coordinatorPort ?? 4200;
  const nodePortBase = opts.nodePortBase ?? 4100;
  const workerPortBase = opts.workerPortBase ?? 4400;
  const relayerPort = opts.relayerPort ?? 4300;
  const randomHex = opts.randomHex ?? ((bytes: number) => bytesToHex(randomBytes(bytes)));

  assertHexBytes("vaultEk", opts.vaultEk, 32);
  assertHexBytes("frost.groupPublicKey", opts.frost.groupPublicKey, 32);
  if (opts.frost.verifyingShares.length !== DEOPERATOR_COUNT) {
    throw new Error(`FROST material must contain ${DEOPERATOR_COUNT} verifying shares`);
  }

  const sharesBySlot = new Map<number, string>();
  for (const share of opts.frost.verifyingShares) {
    if (!Number.isInteger(share.slot) || share.slot < 0 || share.slot >= DEOPERATOR_COUNT) {
      throw new Error(`invalid FROST verifying share slot ${share.slot}`);
    }
    if (sharesBySlot.has(share.slot)) {
      throw new Error(`duplicate FROST verifying share slot ${share.slot}`);
    }
    assertHexBytes(`frost.verifyingShares[${share.slot}]`, share.frostVerifyingShare, 32);
    sharesBySlot.set(share.slot, bytesToHex(hexToBytes(share.frostVerifyingShare)));
  }

  const nodes = Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
    slot,
    nodeId: `local-deop-${slot}`,
    endpoint: `http://${host}:${nodePortBase + slot}`,
    hpkePublicKey: randomHex(32, `slot-${slot}-hpke-public`),
    transcriptPublicKey: randomHex(32, `slot-${slot}-transcript-public`),
    frostVerifyingShare: sharesBySlot.get(slot) ?? unreachable(`missing slot ${slot}`),
  }));

  const caDkgV2Roster = opts.caDkgV2
    ? buildCaDkgV2Roster(opts, sharesBySlot, host, nodePortBase)
    : undefined;
  if (caDkgV2Roster) validateCaDkgV2Roster(caDkgV2Roster);
  const currentCaDkgV2RosterHash = caDkgV2Roster ? caDkgV2RosterHash(caDkgV2Roster) : undefined;

  const roster: DeoperatorRoster = {
    operatorSetVersion: opts.operatorSetVersion ?? "1",
    dkgEpoch: opts.dkgEpoch ?? "1",
    caDkgScheme: opts.caDkgScheme ?? CA_DKG_SCHEME_LOCAL,
    threshold: DEOPERATOR_THRESHOLD,
    nodes,
    frostGroupPubkey: bytesToHex(hexToBytes(opts.frost.groupPublicKey)),
    vaultEk: bytesToHex(hexToBytes(opts.vaultEk)),
    circuitVersions: {
      depositBinding: "deposit-v2.0.0",
      withdraw: "withdraw-v2.0.0",
      caPayload: "aptos-ca-v1",
    },
  };
  validateRoster(roster);
  const currentRosterHash = rosterHash(roster);
  const nodeBearerTokens = Object.fromEntries(
    Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => [
      String(slot),
      randomHex(32, `slot-${slot}-node-bearer`),
    ]),
  );
  const coordinatorBearer = randomHex(32, "coordinator-bearer");
  const relayerBearer = randomHex(32, "relayer-bearer");
  const rosterJson = JSON.stringify(roster);

  return {
    stateRoot,
    roster,
    rosterHash: currentRosterHash,
    caDkgV2Roster,
    caDkgV2RosterHash: currentCaDkgV2RosterHash,
    nodeBearerTokens,
    coordinator: {
      name: "coordinator",
      port: coordinatorPort,
      env: {
        COORDINATOR_HOST: host,
        COORDINATOR_PORT: String(coordinatorPort),
        COORDINATOR_BEARER_TOKEN: coordinatorBearer,
        DEOPERATOR_ROSTER_JSON: rosterJson,
        ...(caDkgV2Roster ? { CA_DKG_V2_ROSTER_JSON: JSON.stringify(caDkgV2Roster) } : {}),
        DEOPERATOR_NODE_BEARER_TOKENS_JSON: JSON.stringify(nodeBearerTokens),
      },
    },
    relayer: {
      name: "relayer",
      port: relayerPort,
      env: {
        RELAYER_HOST: host,
        RELAYER_PORT: String(relayerPort),
        RELAYER_BEARER_TOKEN: relayerBearer,
        APTOS_NODE_URL: opts.aptosNodeUrl ?? "https://fullnode.testnet.aptoslabs.com/v1",
      },
    },
    nodes: Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
      name: `deoperator-node-${slot}`,
      slot,
      port: nodePortBase + slot,
      env: {
        DEOPERATOR_SLOT: String(slot),
        DEOPERATOR_NODE_ID: `local-deop-${slot}`,
        DEOPERATOR_HOST: host,
        DEOPERATOR_PORT: String(nodePortBase + slot),
        DEOPERATOR_BEARER_TOKEN: nodeBearerTokens[String(slot)],
        DEOPERATOR_ROSTER_JSON: rosterJson,
        ...(caDkgV2Roster ? { CA_DKG_V2_ROSTER_JSON: JSON.stringify(caDkgV2Roster) } : {}),
        CRYPTO_WORKER_URL: `http://${host}:${workerPortBase + slot}`,
      },
    })),
    workers: Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
      name: `crypto-worker-${slot}`,
      slot,
      port: workerPortBase + slot,
      stateDir: `${stateRoot}/slot-${slot}`,
      env: {
        CRYPTO_WORKER_SLOT: String(slot),
        CRYPTO_WORKER_HOST: host,
        CRYPTO_WORKER_PORT: String(workerPortBase + slot),
        CRYPTO_WORKER_STATE_DIR: `${stateRoot}/slot-${slot}`,
        CRYPTO_WORKER_STATE_ROOT: stateRoot,
      },
    })),
  };
}

function buildCaDkgV2Roster(
  opts: LocalClusterPlanOptions,
  _sharesBySlot: Map<number, string>,
  host: string,
  nodePortBase: number,
): CaDkgV2Roster {
  if (!opts.caDkgV2 || opts.caDkgV2.hpkePublicKeys.length !== DEOPERATOR_COUNT) {
    throw new Error(`CA DKG V2 material must contain ${DEOPERATOR_COUNT} HPKE public keys`);
  }
  const hpkeBySlot = new Map<number, string>();
  for (const key of opts.caDkgV2.hpkePublicKeys) {
    if (!Number.isInteger(key.slot) || key.slot < 0 || key.slot >= DEOPERATOR_COUNT) {
      throw new Error(`invalid CA DKG V2 HPKE slot ${key.slot}`);
    }
    if (hpkeBySlot.has(key.slot)) {
      throw new Error(`duplicate CA DKG V2 HPKE slot ${key.slot}`);
    }
    assertHexBytes(`caDkgV2.hpkePublicKeys[${key.slot}]`, key.hpkePublicKey, 32);
    hpkeBySlot.set(key.slot, bytesToHex(hexToBytes(key.hpkePublicKey)));
  }
  const randomHex = opts.randomHex ?? ((bytes: number) => bytesToHex(randomBytes(bytes)));
  return {
    operatorSetVersion: opts.operatorSetVersion ?? "1",
    dkgEpoch: opts.dkgEpoch ?? "1",
    caDkgScheme: CA_DKG_SCHEME_V2,
    threshold: DEOPERATOR_THRESHOLD,
    nodes: Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
      slot,
      nodeId: `local-deop-${slot}`,
      endpoint: `http://${host}:${nodePortBase + slot}`,
      hpkePublicKey: hpkeBySlot.get(slot) ?? unreachable(`missing HPKE slot ${slot}`),
      transcriptPublicKey: randomHex(32, `slot-${slot}-ca-dkg-v2-transcript-public`),
    })),
  };
}

function assertHexBytes(name: string, hex: string, bytes: number): void {
  const parsed = hexToBytes(hex);
  if (parsed.length !== bytes) {
    throw new Error(`${name}: expected ${bytes} bytes, got ${parsed.length}`);
  }
}

function unreachable(message: string): never {
  throw new Error(message);
}

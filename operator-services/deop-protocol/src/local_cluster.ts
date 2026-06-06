import { randomBytes } from "node:crypto";
import { chmodSync, writeFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { bytesToHex, hexToBytes } from "@eunoma/shared";
import {
  CA_DKG_SCHEME_LOCAL,
  CA_DKG_SCHEME_V2,
  DEOPERATOR_COUNT,
  DEOPERATOR_THRESHOLD,
  FROST_DKG_SCHEME_V2,
} from "./constants.js";
import {
  caDkgV2RosterHash,
  frostDkgV2RosterHash,
  rosterHash,
  validateCaDkgV2Roster,
  validateFrostDkgV2Roster,
  validateRoster,
} from "./roster.js";
import type {
  CaDkgScheme,
  CaDkgV2Roster,
  DeoperatorRoster,
  FrostDkgV2Roster,
} from "./types.js";

const DEFAULT_RELAYER_MAX_GAS_PRICE_OCTAS = "1000";
const DEFAULT_RELAYER_RESERVE_MIN_BALANCE_OCTAS = "200000000";

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
  /**
   * M10-l (codex iter-7 P1-16): bridge vault address. Propagated to both the
   * coordinator and every worker as `BRIDGE_VAULT_ADDRESS` so the
   * /v2/balance/decrypt + /v2/balance/decrypt_partial config-trust checks
   * have the value they need. Without this, the cluster will fail closed
   * with `coordinator missing BRIDGE_VAULT_ADDRESS` on the first balance-
   * decrypt call.
   */
  bridgeVaultAddress?: string;
  /**
   * M10-l (codex iter-7 P1-16): bridge asset type tag. Same rationale as
   * `bridgeVaultAddress` — propagated as `BRIDGE_ASSET_TYPE` to coordinator
   * + workers.
   */
  bridgeAssetType?: string;
  /**
   * M11: bridge package address (the `@eunoma` module-publish address, distinct
   * from the vault resource account). Propagated as `BRIDGE_PACKAGE_ADDRESS` to
   * every worker so the /v2/vault/resync handler can build the trusted
   * WithdrawEventV2 event type. Without it, resync fails closed with
   * `worker_missing_bridge_config` and the coordinator fan-out never reaches quorum.
   */
  bridgePackageAddress?: string;
  adminProfile?: string;
  relayerProfile?: string;
  relayerSubmitEnabled?: string;
  relayerReserveAccountAddress?: string;
  relayerMaxGasPriceOctas?: string;
  relayerReserveMinBalanceOctas?: string;
  aptosCliCwd?: string;
  refreshSignerMode?: "admin" | "delegate";
  refreshAdminProfile?: string;
  refreshDelegateProfile?: string;
  refreshAspRecorderProfile?: string;
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
  frostDkgV2Roster?: FrostDkgV2Roster;
  frostDkgV2RosterHash?: string;
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

  const frostDkgV2Roster = opts.caDkgV2
    ? buildFrostDkgV2Roster(opts, host, nodePortBase)
    : undefined;
  if (frostDkgV2Roster) validateFrostDkgV2Roster(frostDkgV2Roster);
  const currentFrostDkgV2RosterHash = frostDkgV2Roster
    ? frostDkgV2RosterHash(frostDkgV2Roster)
    : undefined;

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

  const caDkgV2RosterJson = caDkgV2Roster ? JSON.stringify(caDkgV2Roster) : undefined;
  const caDkgV2RosterPath = caDkgV2Roster ? `${stateRoot}/cluster/ca-dkg-v2-roster.json` : undefined;
  const frostDkgV2RosterJson = frostDkgV2Roster ? JSON.stringify(frostDkgV2Roster) : undefined;
  const relayerGasEnv = buildRelayerGasEnv(opts);
  return {
    stateRoot,
    roster,
    rosterHash: currentRosterHash,
    caDkgV2Roster,
    caDkgV2RosterHash: currentCaDkgV2RosterHash,
    frostDkgV2Roster,
    frostDkgV2RosterHash: currentFrostDkgV2RosterHash,
    nodeBearerTokens,
    coordinator: {
      name: "coordinator",
      port: coordinatorPort,
      env: {
        COORDINATOR_HOST: host,
        COORDINATOR_PORT: String(coordinatorPort),
        COORDINATOR_BEARER_TOKEN: coordinatorBearer,
        DEOPERATOR_ROSTER_JSON: rosterJson,
        ...(caDkgV2RosterJson ? { CA_DKG_V2_ROSTER_JSON: caDkgV2RosterJson } : {}),
        ...(caDkgV2RosterPath ? { CA_DKG_V2_ROSTER_JSON_PATH: caDkgV2RosterPath } : {}),
        ...(frostDkgV2RosterJson ? { FROST_DKG_V2_ROSTER_JSON: frostDkgV2RosterJson } : {}),
        DEOPERATOR_NODE_BEARER_TOKENS_JSON: JSON.stringify(nodeBearerTokens),
        // M10-l (codex iter-7 P1-16): the /v2/balance/decrypt route needs
        // these envs for the iter-1 (chain URL) + iter-6 (vault, asset) trust
        // checks. Without them, the route fails closed at first request.
        APTOS_NODE_URL: opts.aptosNodeUrl ?? "https://fullnode.testnet.aptoslabs.com/v1",
        ...(opts.bridgeVaultAddress ? { BRIDGE_VAULT_ADDRESS: opts.bridgeVaultAddress } : {}),
        ...(opts.bridgeAssetType ? { BRIDGE_ASSET_TYPE: opts.bridgeAssetType } : {}),
        ...(opts.adminProfile ? { ADMIN_PROFILE: opts.adminProfile } : {}),
        ...(opts.refreshSignerMode ? { EUNOMA_REFRESH_SIGNER_MODE: opts.refreshSignerMode } : {}),
        ...(opts.refreshAdminProfile ? { EUNOMA_REFRESH_ADMIN_PROFILE: opts.refreshAdminProfile } : {}),
        ...(opts.refreshDelegateProfile ? { EUNOMA_REFRESH_DELEGATE_PROFILE: opts.refreshDelegateProfile } : {}),
        ...(opts.refreshAspRecorderProfile
          ? { EUNOMA_REFRESH_ASP_RECORDER_PROFILE: opts.refreshAspRecorderProfile }
          : {}),
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
        ...(opts.bridgePackageAddress ? { BRIDGE_PACKAGE_ADDRESS: opts.bridgePackageAddress } : {}),
        ...(opts.bridgePackageAddress ? { RELAYER_USE_V3: "1" } : {}),
        ...(opts.bridgePackageAddress
          ? { RELAYER_SUBMIT_ENABLED: opts.relayerSubmitEnabled ?? "1" }
          : {}),
        ...(opts.relayerProfile ? { RELAYER_PROFILE: opts.relayerProfile } : {}),
        ...relayerGasEnv,
        EUNOMA_STATE_ROOT: stateRoot,
        ...(opts.bridgeAssetType ? { BRIDGE_ASSET_TYPE: opts.bridgeAssetType } : {}),
        ...(opts.aptosCliCwd ? { APTOS_CLI_CWD: opts.aptosCliCwd } : {}),
        ...(opts.bridgeVaultAddress ? { BRIDGE_VAULT_ADDRESS: opts.bridgeVaultAddress } : {}),
        ...(opts.adminProfile ? { ADMIN_PROFILE: opts.adminProfile } : {}),
        ...(opts.refreshAdminProfile ? { EUNOMA_REFRESH_ADMIN_PROFILE: opts.refreshAdminProfile } : {}),
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
        ...(caDkgV2RosterJson ? { CA_DKG_V2_ROSTER_JSON: caDkgV2RosterJson } : {}),
        ...(frostDkgV2RosterJson ? { FROST_DKG_V2_ROSTER_JSON: frostDkgV2RosterJson } : {}),
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
        // M10-l (codex iter-7 P1-16): workers do their own chain re-fetch
        // for the balance-decrypt path (iter-1 P1-1 closure) and enforce
        // their own (vault, asset) match against the request (iter-6 P1-13
        // closure). All three envs must be present here or the worker will
        // fail closed with `worker_missing_aptos_node_url_config` /
        // `worker_missing_bridge_vault_or_asset_config` at first decrypt.
        APTOS_NODE_URL: opts.aptosNodeUrl ?? "https://fullnode.testnet.aptoslabs.com/v1",
        ...(opts.bridgeVaultAddress ? { BRIDGE_VAULT_ADDRESS: opts.bridgeVaultAddress } : {}),
        ...(opts.bridgeAssetType ? { BRIDGE_ASSET_TYPE: opts.bridgeAssetType } : {}),
        // M11: the /v2/vault/resync handler builds the trusted WithdrawEventV2 event
        // type from this; without it resync fails closed `worker_missing_bridge_config`.
        ...(opts.bridgePackageAddress ? { BRIDGE_PACKAGE_ADDRESS: opts.bridgePackageAddress } : {}),
      },
    })),
  };
}

function buildRelayerGasEnv(opts: LocalClusterPlanOptions): Record<string, string> {
  if (!opts.relayerReserveAccountAddress) return {};
  return {
    RESERVE_ACCOUNT_ADDRESS: opts.relayerReserveAccountAddress,
    RELAYER_MAX_GAS_PRICE_OCTAS: decimalString(
      opts.relayerMaxGasPriceOctas ?? DEFAULT_RELAYER_MAX_GAS_PRICE_OCTAS,
      "relayerMaxGasPriceOctas",
    ),
    RELAYER_RESERVE_MIN_BALANCE_OCTAS: maxDecimalString(
      opts.relayerReserveMinBalanceOctas ?? DEFAULT_RELAYER_RESERVE_MIN_BALANCE_OCTAS,
      DEFAULT_RELAYER_RESERVE_MIN_BALANCE_OCTAS,
      "relayerReserveMinBalanceOctas",
    ),
  };
}

function decimalString(value: string, name: string): string {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error(`${name} must be a decimal string`);
  }
  return value;
}

function maxDecimalString(value: string, floor: string, name: string): string {
  const parsed = BigInt(decimalString(value, name));
  const floorParsed = BigInt(decimalString(floor, `${name} floor`));
  return String(parsed > floorParsed ? parsed : floorParsed);
}

export interface RenderEnvFilesResult {
  paths: {
    coordinatorEnv: string;
    relayerEnv: string;
    nodeEnv: Record<number, string>;
    workerEnv: Record<number, string>;
  };
}

export function renderEnvFiles(plan: LocalClusterPlan, clusterDir: string): RenderEnvFilesResult {
  const coordinatorPath = resolvePath(clusterDir, "coordinator.env");
  const relayerPath = resolvePath(clusterDir, "relayer.env");
  writeEnvFile(coordinatorPath, plan.coordinator.env);
  writeEnvFile(relayerPath, plan.relayer.env);
  const nodeEnv: Record<number, string> = {};
  for (const node of plan.nodes) {
    const path = resolvePath(clusterDir, `node-${node.slot}.env`);
    writeEnvFile(path, node.env);
    nodeEnv[node.slot] = path;
  }
  const workerEnv: Record<number, string> = {};
  for (const worker of plan.workers) {
    const path = resolvePath(clusterDir, `worker-${worker.slot}.env`);
    writeEnvFile(path, worker.env);
    workerEnv[worker.slot] = path;
  }
  return {
    paths: { coordinatorEnv: coordinatorPath, relayerEnv: relayerPath, nodeEnv, workerEnv },
  };
}

function writeEnvFile(path: string, env: Record<string, string>): void {
  const lines = Object.entries(env).map(([key, value]) => `${key}=${shellQuote(value)}`);
  writeFileSync(path, `${lines.join("\n")}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function shellQuote(value: string): string {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
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

function buildFrostDkgV2Roster(
  opts: LocalClusterPlanOptions,
  host: string,
  nodePortBase: number,
): FrostDkgV2Roster {
  if (!opts.caDkgV2 || opts.caDkgV2.hpkePublicKeys.length !== DEOPERATOR_COUNT) {
    throw new Error(`FROST DKG V2 material must contain ${DEOPERATOR_COUNT} HPKE public keys`);
  }
  const hpkeBySlot = new Map<number, string>();
  for (const key of opts.caDkgV2.hpkePublicKeys) {
    assertHexBytes(`frostDkgV2.hpkePublicKeys[${key.slot}]`, key.hpkePublicKey, 32);
    hpkeBySlot.set(key.slot, bytesToHex(hexToBytes(key.hpkePublicKey)));
  }
  const randomHex = opts.randomHex ?? ((bytes: number) => bytesToHex(randomBytes(bytes)));
  return {
    operatorSetVersion: opts.operatorSetVersion ?? "1",
    dkgEpoch: opts.dkgEpoch ?? "1",
    caDkgScheme: FROST_DKG_SCHEME_V2,
    threshold: DEOPERATOR_THRESHOLD,
    nodes: Array.from({ length: DEOPERATOR_COUNT }, (_, slot) => ({
      slot,
      nodeId: `local-deop-${slot}`,
      endpoint: `http://${host}:${nodePortBase + slot}`,
      hpkePublicKey: hpkeBySlot.get(slot) ?? unreachable(`missing HPKE slot ${slot}`),
      transcriptPublicKey: randomHex(32, `slot-${slot}-frost-dkg-v2-transcript-public`),
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

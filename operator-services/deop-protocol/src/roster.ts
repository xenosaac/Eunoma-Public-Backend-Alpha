import type { HexString } from "@eunoma/shared";
import { bytesToHex, hexToBytes, sha256, sha3_256, stableStringify } from "@eunoma/shared";
import {
  CA_DKG_SCHEME_LOCAL,
  CA_DKG_SCHEME_V2,
  DEOPERATOR_COUNT,
  DEOPERATOR_THRESHOLD,
  DOMAIN_CA_DKG_V2_ROSTER_HASH,
  DOMAIN_FROST_DKG_V2_ROSTER_HASH,
  DOMAIN_HPKE_AAD_V2,
  DOMAIN_ROSTER_HASH_V2,
  ED25519_PUBLIC_KEY_BYTES,
  FROST_DKG_SCHEME_V2,
} from "./constants.js";
import type {
  CaDkgV2Roster,
  DeoperatorRoster,
  FrostDkgV2Roster,
  FrostDkgV2WorkerArtifact,
  RequestPhase,
} from "./types.js";

export function validateRoster(roster: DeoperatorRoster): void {
  if (roster.threshold !== DEOPERATOR_THRESHOLD) {
    throw new Error(`V2 threshold must be ${DEOPERATOR_THRESHOLD}`);
  }
  if (roster.nodes.length !== DEOPERATOR_COUNT) {
    throw new Error(`V2 roster must contain ${DEOPERATOR_COUNT} nodes`);
  }
  if (roster.caDkgScheme !== CA_DKG_SCHEME_V2 && roster.caDkgScheme !== CA_DKG_SCHEME_LOCAL) {
    throw new Error("roster caDkgScheme must be ca_dkg_v2 or ca_local");
  }
  const slots = new Set<number>();
  for (const node of roster.nodes) {
    if (!Number.isInteger(node.slot) || node.slot < 0 || node.slot >= DEOPERATOR_COUNT) {
      throw new Error(`invalid roster slot: ${node.slot}`);
    }
    if (slots.has(node.slot)) {
      throw new Error(`duplicate roster slot: ${node.slot}`);
    }
    slots.add(node.slot);
    assertHexBytes("hpkePublicKey", node.hpkePublicKey, 32);
    assertHexBytes("transcriptPublicKey", node.transcriptPublicKey, ED25519_PUBLIC_KEY_BYTES);
    assertHexBytes("frostVerifyingShare", node.frostVerifyingShare, ED25519_PUBLIC_KEY_BYTES);
  }
  assertHexBytes("frostGroupPubkey", roster.frostGroupPubkey, ED25519_PUBLIC_KEY_BYTES);
  assertHexBytes("vaultEk", roster.vaultEk, 32);
}

export function rosterHash(roster: DeoperatorRoster): string {
  validateRoster(roster);
  const canonical = {
    domain: DOMAIN_ROSTER_HASH_V2,
    operatorSetVersion: roster.operatorSetVersion,
    dkgEpoch: roster.dkgEpoch,
    caDkgScheme: roster.caDkgScheme,
    threshold: roster.threshold,
    nodes: [...roster.nodes]
      .sort((a, b) => a.slot - b.slot)
      .map((node) => ({
        slot: node.slot,
        nodeId: node.nodeId,
        endpoint: node.endpoint,
        hpkePublicKey: normalizeHex(node.hpkePublicKey),
        transcriptPublicKey: normalizeHex(node.transcriptPublicKey),
        frostVerifyingShare: normalizeHex(node.frostVerifyingShare),
      })),
    frostGroupPubkey: normalizeHex(roster.frostGroupPubkey),
    vaultEk: normalizeHex(roster.vaultEk),
    circuitVersions: roster.circuitVersions,
  };
  return bytesToHex(sha3_256(new TextEncoder().encode(stableStringify(canonical))));
}

export function validateCaDkgV2Roster(roster: CaDkgV2Roster): void {
  if (roster.caDkgScheme !== CA_DKG_SCHEME_V2) {
    throw new Error("CA DKG V2 roster caDkgScheme must be ca_dkg_v2");
  }
  if (roster.threshold !== DEOPERATOR_THRESHOLD) {
    throw new Error(`CA DKG V2 threshold must be ${DEOPERATOR_THRESHOLD}`);
  }
  if (roster.nodes.length !== DEOPERATOR_COUNT) {
    throw new Error(`CA DKG V2 roster must contain ${DEOPERATOR_COUNT} nodes`);
  }
  const slots = new Set<number>();
  for (const node of roster.nodes) {
    if (!Number.isInteger(node.slot) || node.slot < 0 || node.slot >= DEOPERATOR_COUNT) {
      throw new Error(`invalid CA DKG V2 roster slot: ${node.slot}`);
    }
    if (slots.has(node.slot)) {
      throw new Error(`duplicate CA DKG V2 roster slot: ${node.slot}`);
    }
    slots.add(node.slot);
    assertHexBytes("hpkePublicKey", node.hpkePublicKey, 32);
    assertHexBytes("transcriptPublicKey", node.transcriptPublicKey, ED25519_PUBLIC_KEY_BYTES);
  }
}

export function caDkgV2RosterHash(roster: CaDkgV2Roster): string {
  validateCaDkgV2Roster(roster);
  const canonical = {
    domain: DOMAIN_CA_DKG_V2_ROSTER_HASH,
    operatorSetVersion: roster.operatorSetVersion,
    dkgEpoch: roster.dkgEpoch,
    caDkgScheme: roster.caDkgScheme,
    threshold: roster.threshold,
    nodes: [...roster.nodes]
      .sort((a, b) => a.slot - b.slot)
      .map((node) => ({
        slot: node.slot,
        nodeId: node.nodeId,
        endpoint: node.endpoint,
        hpkePublicKey: normalizeHex(node.hpkePublicKey),
        transcriptPublicKey: normalizeHex(node.transcriptPublicKey),
      })),
  };
  return bytesToHex(sha3_256(new TextEncoder().encode(stableStringify(canonical))));
}

export function validateFrostDkgV2Roster(roster: FrostDkgV2Roster): void {
  if (roster.caDkgScheme !== FROST_DKG_SCHEME_V2) {
    throw new Error("FROST DKG V2 roster caDkgScheme must be frost_dkg_v2");
  }
  if (roster.threshold !== DEOPERATOR_THRESHOLD) {
    throw new Error(`FROST DKG V2 threshold must be ${DEOPERATOR_THRESHOLD}`);
  }
  if (roster.nodes.length !== DEOPERATOR_COUNT) {
    throw new Error(`FROST DKG V2 roster must contain ${DEOPERATOR_COUNT} nodes`);
  }
  const slots = new Set<number>();
  for (const node of roster.nodes) {
    if (!Number.isInteger(node.slot) || node.slot < 0 || node.slot >= DEOPERATOR_COUNT) {
      throw new Error(`invalid FROST DKG V2 roster slot: ${node.slot}`);
    }
    if (slots.has(node.slot)) {
      throw new Error(`duplicate FROST DKG V2 roster slot: ${node.slot}`);
    }
    slots.add(node.slot);
    assertHexBytes("hpkePublicKey", node.hpkePublicKey, 32);
    assertHexBytes("transcriptPublicKey", node.transcriptPublicKey, ED25519_PUBLIC_KEY_BYTES);
  }
}

export function frostDkgV2RosterHash(roster: FrostDkgV2Roster): string {
  validateFrostDkgV2Roster(roster);
  const canonical = {
    domain: DOMAIN_FROST_DKG_V2_ROSTER_HASH,
    operatorSetVersion: roster.operatorSetVersion,
    dkgEpoch: roster.dkgEpoch,
    caDkgScheme: roster.caDkgScheme,
    threshold: roster.threshold,
    nodes: [...roster.nodes]
      .sort((a, b) => a.slot - b.slot)
      .map((node) => ({
        slot: node.slot,
        nodeId: node.nodeId,
        endpoint: node.endpoint,
        hpkePublicKey: normalizeHex(node.hpkePublicKey),
        transcriptPublicKey: normalizeHex(node.transcriptPublicKey),
      })),
  };
  return bytesToHex(sha256(new TextEncoder().encode(stableStringify(canonical))));
}

export interface FrostRotationInput {
  groupPublicKey: HexString;
  dkgEpoch: string;
  workerArtifacts: FrostDkgV2WorkerArtifact[];
}

export interface FrostRotationOutput {
  roster: DeoperatorRoster;
  rosterHash: HexString;
  previousRosterHash: HexString;
  previousDkgEpoch: string;
  previousGroupPublicKey: HexString;
}

export function applyFrostRotationToRoster(
  roster: DeoperatorRoster,
  input: FrostRotationInput,
): FrostRotationOutput {
  validateRoster(roster);
  const previousRosterHash = rosterHash(roster);
  const previousDkgEpoch = roster.dkgEpoch;
  const previousGroupPublicKey = normalizeHex(roster.frostGroupPubkey);

  assertHexBytes("groupPublicKey", input.groupPublicKey, ED25519_PUBLIC_KEY_BYTES);
  if (!/^[0-9]+$/.test(input.dkgEpoch)) {
    throw new Error(`dkgEpoch must be a decimal string: ${input.dkgEpoch}`);
  }
  if (!/^[0-9]+$/.test(roster.dkgEpoch)) {
    throw new Error(`existing roster.dkgEpoch must be a decimal string: ${roster.dkgEpoch}`);
  }
  if (Number(input.dkgEpoch) <= Number(roster.dkgEpoch)) {
    throw new Error(
      `new dkgEpoch ${input.dkgEpoch} must be strictly greater than current ${roster.dkgEpoch}`,
    );
  }
  if (input.workerArtifacts.length !== DEOPERATOR_COUNT) {
    throw new Error(
      `workerArtifacts must contain ${DEOPERATOR_COUNT} entries, got ${input.workerArtifacts.length}`,
    );
  }
  const sharesBySlot = new Map<number, string>();
  for (const artifact of input.workerArtifacts) {
    if (!Number.isInteger(artifact.slot) || artifact.slot < 0 || artifact.slot >= DEOPERATOR_COUNT) {
      throw new Error(`invalid workerArtifacts slot: ${artifact.slot}`);
    }
    if (sharesBySlot.has(artifact.slot)) {
      throw new Error(`duplicate workerArtifacts slot: ${artifact.slot}`);
    }
    assertHexBytes(
      `workerArtifacts[slot=${artifact.slot}].frostVerifyingShare`,
      artifact.frostVerifyingShare,
      ED25519_PUBLIC_KEY_BYTES,
    );
    sharesBySlot.set(artifact.slot, normalizeHex(artifact.frostVerifyingShare));
  }
  for (let slot = 0; slot < DEOPERATOR_COUNT; slot += 1) {
    if (!sharesBySlot.has(slot)) {
      throw new Error(`workerArtifacts missing slot ${slot}`);
    }
  }

  const rotated: DeoperatorRoster = {
    operatorSetVersion: roster.operatorSetVersion,
    dkgEpoch: input.dkgEpoch,
    caDkgScheme: roster.caDkgScheme,
    threshold: roster.threshold,
    nodes: roster.nodes.map((node) => ({
      slot: node.slot,
      nodeId: node.nodeId,
      endpoint: node.endpoint,
      hpkePublicKey: node.hpkePublicKey,
      transcriptPublicKey: node.transcriptPublicKey,
      frostVerifyingShare:
        sharesBySlot.get(node.slot) ??
        (() => {
          throw new Error(`missing rotated share for slot ${node.slot}`);
        })(),
    })),
    frostGroupPubkey: normalizeHex(input.groupPublicKey),
    vaultEk: roster.vaultEk,
    circuitVersions: { ...roster.circuitVersions },
  };
  validateRoster(rotated);
  return {
    roster: rotated,
    rosterHash: rosterHash(rotated),
    previousRosterHash,
    previousDkgEpoch,
    previousGroupPublicKey,
  };
}

export interface FrostChainView {
  operatorSetVersion: string;
  dkgEpoch: string;
  rosterHash: HexString;
  frostGroupPubkey: HexString;
  vaultEk: HexString;
}

export interface FrostRotationSnapshot {
  operatorSetVersion: string;
  dkgEpoch: string;
  vaultEk: HexString;
  depositCircuitVersion: HexString;
  withdrawCircuitVersion: HexString;
  caPayloadCircuitVersion: HexString;
  fallbackPubkeys: HexString[];
}

export interface FrostRotationTxInput {
  currentRoster: DeoperatorRoster;
  chainView: FrostChainView;
  snapshot: FrostRotationSnapshot;
  dkgArtifact: { groupPublicKey: HexString; workerArtifactHashes: FrostDkgV2WorkerArtifact[] };
  newDkgEpoch?: string;
}

export interface FrostRotationMoveCallArgs {
  operatorSetVersion: string;
  newDkgEpoch: string;
  rotatedRosterHash: HexString;
  rotatedFrostGroupPubkey: HexString;
  vaultEk: HexString;
  depositCircuitVersion: HexString;
  withdrawCircuitVersion: HexString;
  caPayloadCircuitVersion: HexString;
  fallbackPubkeys: HexString[];
}

export interface FrostRotationTxOutput {
  rotatedRoster: DeoperatorRoster;
  rotatedRosterHash: HexString;
  previousRosterHash: HexString;
  moveCallArgs: FrostRotationMoveCallArgs;
}

export type StaleRotationCode =
  | "STALE_ROSTER_HASH"
  | "STALE_CHAIN_OPERATOR_SET_VERSION"
  | "STALE_CHAIN_DKG_EPOCH"
  | "STALE_CHAIN_VAULT_EK"
  | "STALE_CHAIN_FROST_GROUP_PUBKEY"
  | "STALE_SNAPSHOT_OPERATOR_SET_VERSION"
  | "STALE_SNAPSHOT_DKG_EPOCH"
  | "STALE_SNAPSHOT_VAULT_EK"
  | "INVALID_FALLBACK_PUBKEYS"
  | "INVALID_DKG_ARTIFACT";

export class StaleRotationStateError extends Error {
  constructor(
    public readonly code: StaleRotationCode,
    message: string,
  ) {
    super(message);
    this.name = "StaleRotationStateError";
  }
}

export function prepareFrostRotationTx(input: FrostRotationTxInput): FrostRotationTxOutput {
  const { currentRoster, chainView, snapshot, dkgArtifact } = input;

  validateRoster(currentRoster);

  if (!Array.isArray(snapshot.fallbackPubkeys) || snapshot.fallbackPubkeys.length !== DEOPERATOR_COUNT) {
    throw new StaleRotationStateError(
      "INVALID_FALLBACK_PUBKEYS",
      `snapshot.fallbackPubkeys must have ${DEOPERATOR_COUNT} entries, got ${
        Array.isArray(snapshot.fallbackPubkeys) ? snapshot.fallbackPubkeys.length : "non-array"
      }`,
    );
  }
  for (let i = 0; i < snapshot.fallbackPubkeys.length; i += 1) {
    try {
      assertHexBytes(`fallbackPubkeys[${i}]`, snapshot.fallbackPubkeys[i], ED25519_PUBLIC_KEY_BYTES);
    } catch (err) {
      throw new StaleRotationStateError(
        "INVALID_FALLBACK_PUBKEYS",
        (err as Error).message ?? `invalid fallbackPubkeys[${i}]`,
      );
    }
  }

  if (
    !Array.isArray(dkgArtifact.workerArtifactHashes) ||
    dkgArtifact.workerArtifactHashes.length !== DEOPERATOR_COUNT
  ) {
    throw new StaleRotationStateError(
      "INVALID_DKG_ARTIFACT",
      `dkgArtifact.workerArtifactHashes must have ${DEOPERATOR_COUNT} entries, got ${
        Array.isArray(dkgArtifact.workerArtifactHashes)
          ? dkgArtifact.workerArtifactHashes.length
          : "non-array"
      }`,
    );
  }
  try {
    assertHexBytes("dkgArtifact.groupPublicKey", dkgArtifact.groupPublicKey, ED25519_PUBLIC_KEY_BYTES);
  } catch (err) {
    throw new StaleRotationStateError(
      "INVALID_DKG_ARTIFACT",
      (err as Error).message ?? "invalid dkgArtifact.groupPublicKey",
    );
  }

  if (String(snapshot.operatorSetVersion) !== String(chainView.operatorSetVersion)) {
    throw new StaleRotationStateError(
      "STALE_SNAPSHOT_OPERATOR_SET_VERSION",
      `snapshot.operatorSetVersion=${snapshot.operatorSetVersion} != chain=${chainView.operatorSetVersion}`,
    );
  }
  if (String(snapshot.dkgEpoch) !== String(chainView.dkgEpoch)) {
    throw new StaleRotationStateError(
      "STALE_SNAPSHOT_DKG_EPOCH",
      `snapshot.dkgEpoch=${snapshot.dkgEpoch} != chain=${chainView.dkgEpoch}`,
    );
  }
  if (normalizeHex(snapshot.vaultEk) !== normalizeHex(chainView.vaultEk)) {
    throw new StaleRotationStateError(
      "STALE_SNAPSHOT_VAULT_EK",
      `snapshot.vaultEk mismatch vs chain.vaultEk`,
    );
  }

  if (String(currentRoster.operatorSetVersion) !== String(chainView.operatorSetVersion)) {
    throw new StaleRotationStateError(
      "STALE_CHAIN_OPERATOR_SET_VERSION",
      `currentRoster.operatorSetVersion=${currentRoster.operatorSetVersion} != chain=${chainView.operatorSetVersion}`,
    );
  }
  if (String(currentRoster.dkgEpoch) !== String(chainView.dkgEpoch)) {
    throw new StaleRotationStateError(
      "STALE_CHAIN_DKG_EPOCH",
      `currentRoster.dkgEpoch=${currentRoster.dkgEpoch} != chain=${chainView.dkgEpoch}`,
    );
  }
  if (normalizeHex(currentRoster.vaultEk) !== normalizeHex(chainView.vaultEk)) {
    throw new StaleRotationStateError(
      "STALE_CHAIN_VAULT_EK",
      `currentRoster.vaultEk mismatch vs chain.vaultEk`,
    );
  }
  if (normalizeHex(currentRoster.frostGroupPubkey) !== normalizeHex(chainView.frostGroupPubkey)) {
    throw new StaleRotationStateError(
      "STALE_CHAIN_FROST_GROUP_PUBKEY",
      `currentRoster.frostGroupPubkey mismatch vs chain.frostGroupPubkey`,
    );
  }

  const previousRosterHash = rosterHash(currentRoster);
  if (normalizeHex(previousRosterHash) !== normalizeHex(chainView.rosterHash)) {
    throw new StaleRotationStateError(
      "STALE_ROSTER_HASH",
      `rosterHash(currentRoster)=${previousRosterHash} != chain.rosterHash=${normalizeHex(chainView.rosterHash)}`,
    );
  }

  const newDkgEpoch = input.newDkgEpoch ?? String(Number(currentRoster.dkgEpoch) + 1);
  const rotation = applyFrostRotationToRoster(currentRoster, {
    groupPublicKey: dkgArtifact.groupPublicKey,
    dkgEpoch: newDkgEpoch,
    workerArtifacts: dkgArtifact.workerArtifactHashes,
  });

  return {
    rotatedRoster: rotation.roster,
    rotatedRosterHash: rotation.rosterHash,
    previousRosterHash,
    moveCallArgs: {
      operatorSetVersion: currentRoster.operatorSetVersion,
      newDkgEpoch: rotation.roster.dkgEpoch,
      rotatedRosterHash: rotation.rosterHash,
      rotatedFrostGroupPubkey: rotation.roster.frostGroupPubkey,
      vaultEk: normalizeHex(snapshot.vaultEk),
      depositCircuitVersion: normalizeHex(snapshot.depositCircuitVersion),
      withdrawCircuitVersion: normalizeHex(snapshot.withdrawCircuitVersion),
      caPayloadCircuitVersion: normalizeHex(snapshot.caPayloadCircuitVersion),
      fallbackPubkeys: snapshot.fallbackPubkeys.map(normalizeHex),
    },
  };
}

export function assertProductionCaDkgScheme(roster: DeoperatorRoster): void {
  if (roster.caDkgScheme !== CA_DKG_SCHEME_V2) {
    throw new Error("testnet and production config require ca_dkg_v2; ca_local is local fixture only");
  }
  validateRoster(roster);
}

export function hpkeAadHash(input: {
  requestId: string;
  sessionId: string;
  phase: RequestPhase;
  rosterHash: string;
  slot: number;
}): string {
  const canonical = stableStringify({
    domain: DOMAIN_HPKE_AAD_V2,
    requestId: input.requestId,
    sessionId: input.sessionId,
    phase: input.phase,
    rosterHash: normalizeHex(input.rosterHash),
    slot: input.slot,
  });
  return bytesToHex(sha3_256(new TextEncoder().encode(canonical)));
}

export function circuitVersionsHash(roster: DeoperatorRoster): string {
  return bytesToHex(
    sha3_256(new TextEncoder().encode(stableStringify(roster.circuitVersions))),
  );
}

function assertHexBytes(name: string, hex: string, bytes: number): void {
  const parsed = hexToBytes(hex);
  if (parsed.length !== bytes) {
    throw new Error(`${name}: expected ${bytes} bytes, got ${parsed.length}`);
  }
}

function normalizeHex(hex: string): string {
  return bytesToHex(hexToBytes(hex));
}

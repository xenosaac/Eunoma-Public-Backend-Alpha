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

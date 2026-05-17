// Tests for scripts/_lib/testnet_e2e_checks.mjs.
//
// Scope: the pure helpers + the chain-dependent paths of runPreflight/buildFinalReport
// driven by stubbed globalThis.fetch + tmp-dir state roots. The tests must NOT shell out
// to `aptos` and must NOT touch real network endpoints.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  validateRequiredEnv,
  compareObservedDepositArtifact,
  selectObservedDepositArtifact,
  buildFinalReport,
  runPreflight,
  isHex64,
  isTxHash,
} from "../_lib/testnet_e2e_checks.mjs";

// ---------------------------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------------------------

const HEX_A = "a".repeat(64);
const HEX_B = "b".repeat(64);
const HEX_C = "c".repeat(64);
const HEX_D = "d".repeat(64);
const HEX_E = "e".repeat(64);
const HEX_F = "f".repeat(64);
const TX_HASH_OK = `0x${"1".repeat(64)}`;
const TX_HASH_BAD = "0xnot-a-hash";
const VAULT_ADDR = `0x${"2".repeat(64)}`;
const ASSET_ADDR = `0x${"3".repeat(64)}`;
const SENDER_ADDR = `0x${"4".repeat(64)}`;
const VAULT_EK = `0x${"5".repeat(64)}`;

function fullEnvFixture(overrides = {}) {
  return {
    APTOS_TESTNET_NODE_URL: "https://example.test",
    BRIDGE_PACKAGE_ADDRESS: `0x${"7".repeat(64)}`,
    RELAYER_SUBMIT_ENABLED: "1",
    ADMIN_PROFILE: "testnet-admin",
    RELAYER_BEARER_TOKEN: "dummy",
    EUNOMA_TESTNET_REQUEST_ID: "rid-001",
    EUNOMA_TESTNET_DKG_EPOCH: "7",
    EUNOMA_TESTNET_VAULT_ADDRESS: VAULT_ADDR,
    EUNOMA_TESTNET_ASSET_TYPE: ASSET_ADDR,
    EUNOMA_TESTNET_CHAIN_ID: "2",
    EUNOMA_TESTNET_SENDER_ADDRESS: SENDER_ADDR,
    EUNOMA_TESTNET_DEPOSIT_TX_HASH: TX_HASH_OK,
    EUNOMA_TESTNET_DEPOSIT_COUNT: "1",
    EUNOMA_TESTNET_VAULT_EK: VAULT_EK,
    EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH: HEX_A,
    ...overrides,
  };
}

function chainEventFixture(overrides = {}) {
  return {
    type: "0x7777::eunoma_bridge::DepositConfirmedV2",
    sequence_number: "1",
    version: "100",
    data: {
      vault_addr: VAULT_ADDR,
      asset_type: ASSET_ADDR,
      deposit_count: "1",
      commitment: HEX_B,
      amount_tag: HEX_C,
      ca_payload_hash: HEX_A,
      deposit_nonce: HEX_D,
      ...overrides.data,
    },
    ...overrides,
  };
}

function observedArtifactFixture(overrides = {}) {
  return {
    scheme: "vault_state_v2_observe_deposit",
    dkgEpoch: "7",
    requestId: "rid-001",
    vaultEkTranscriptHash: HEX_E,
    registrationTranscriptHash: HEX_F,
    rosterHash: HEX_A,
    selectedSlots: [0, 1, 2, 3, 4],
    vaultEk: VAULT_EK,
    senderAddress: SENDER_ADDR,
    assetType: ASSET_ADDR,
    chainId: 2,
    depositCount: 1,
    commitment: HEX_B,
    amountTag: HEX_C,
    caPayloadHash: HEX_A,
    depositNonce: HEX_D,
    sequenceNumber: "1",
    txVersion: "100",
    eventGuid: "0x1::0x2::3",
    previousDepositCountObserved: 0,
    newDepositCountObserved: 1,
    perSlotContributions: [
      { slot: 0, vaultStateHash: HEX_A, workerTranscriptHash: HEX_B, previousDepositCountObserved: 0, depositCountObserved: 1, vaultSequence: 0 },
      { slot: 1, vaultStateHash: HEX_A, workerTranscriptHash: HEX_B, previousDepositCountObserved: 0, depositCountObserved: 1, vaultSequence: 0 },
      { slot: 2, vaultStateHash: HEX_A, workerTranscriptHash: HEX_B, previousDepositCountObserved: 0, depositCountObserved: 1, vaultSequence: 0 },
      { slot: 3, vaultStateHash: HEX_A, workerTranscriptHash: HEX_B, previousDepositCountObserved: 0, depositCountObserved: 1, vaultSequence: 0 },
      { slot: 4, vaultStateHash: HEX_A, workerTranscriptHash: HEX_B, previousDepositCountObserved: 0, depositCountObserved: 1, vaultSequence: 0 },
    ],
    transcriptHash: HEX_F,
    observedAtUnixMs: 1700000000000,
    ...overrides,
  };
}

function submitArtifactFixture(overrides = {}) {
  return {
    scheme: "mpcca_withdraw_submit_v2",
    domain: "EUNOMA_MPCCA_WITHDRAW_SUBMIT_V1",
    dkgEpoch: "7",
    requestId: "rid-001",
    finalizeTranscriptPath: "/tmp/finalize.json",
    finalizeTranscriptHash: HEX_A,
    createdAtUnixMs: 1700000000000,
    completed: true,
    simulated: false,
    accepted: true,
    submitInputHash: HEX_B,
    txHash: TX_HASH_OK,
    chainSuccess: true,
    transcriptHash: HEX_C,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------------------------
// Tmp state-root helpers
// ---------------------------------------------------------------------------------------------

let tmpRoot;
function makeTmpStateRoot() {
  tmpRoot = mkdtempSync(join(tmpdir(), "m6-hardening-"));
  return tmpRoot;
}

function writeSubmitArtifact(stateRoot, dkgEpoch, requestId, artifact) {
  const dir = join(stateRoot, "coordinator", "mpcca_withdraw_submit");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${dkgEpoch}__${requestId}.json`);
  writeFileSync(path, JSON.stringify(artifact));
  return path;
}

afterEach(() => {
  if (tmpRoot) {
    rmSync(tmpRoot, { recursive: true, force: true });
    tmpRoot = undefined;
  }
  vi.restoreAllMocks();
});

// =============================================================================================
// validateRequiredEnv
// =============================================================================================

describe("validateRequiredEnv", () => {
  it("missing required vars — empty env reports all 15 required keys", () => {
    const result = validateRequiredEnv({});
    expect(result.ok).toBe(false);
    const keys = result.missing.map((m) => m.key);
    for (const k of [
      "APTOS_TESTNET_NODE_URL",
      "BRIDGE_PACKAGE_ADDRESS",
      "RELAYER_SUBMIT_ENABLED",
      "ADMIN_PROFILE",
      "RELAYER_BEARER_TOKEN",
      "EUNOMA_TESTNET_REQUEST_ID",
      "EUNOMA_TESTNET_DKG_EPOCH",
      "EUNOMA_TESTNET_VAULT_ADDRESS",
      "EUNOMA_TESTNET_ASSET_TYPE",
      "EUNOMA_TESTNET_CHAIN_ID",
      "EUNOMA_TESTNET_SENDER_ADDRESS",
      "EUNOMA_TESTNET_DEPOSIT_TX_HASH",
      "EUNOMA_TESTNET_DEPOSIT_COUNT",
      "EUNOMA_TESTNET_VAULT_EK",
      "EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH",
    ]) {
      expect(keys).toContain(k);
    }
    for (const m of result.missing) expect(m.priority).toBe("m6c-env");
  });

  it("malformed ca_payload_hash — non-hex string is rejected as _malformed", () => {
    const env = fullEnvFixture({ EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH: "not-a-hex-string" });
    const result = validateRequiredEnv(env);
    expect(result.ok).toBe(false);
    const keys = result.missing.map((m) => m.key);
    expect(keys).toContain("EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH_malformed");
    // No other entries — every other var is set.
    expect(result.missing.length).toBe(1);
  });

  it("ca_payload_hash accepts 0x prefix and bare hex equally", () => {
    expect(validateRequiredEnv(fullEnvFixture({ EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH: HEX_A })).ok).toBe(true);
    expect(validateRequiredEnv(fullEnvFixture({ EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH: `0x${HEX_A}` })).ok).toBe(true);
  });

  it("full valid env passes", () => {
    expect(validateRequiredEnv(fullEnvFixture()).ok).toBe(true);
  });
});

// =============================================================================================
// compareObservedDepositArtifact
// =============================================================================================

describe("compareObservedDepositArtifact", () => {
  it("happy path — all fields agree", () => {
    const result = compareObservedDepositArtifact(observedArtifactFixture(), chainEventFixture(), fullEnvFixture());
    expect(result.ok).toBe(true);
  });

  it("scheme mismatch", () => {
    const result = compareObservedDepositArtifact(
      observedArtifactFixture({ scheme: "something_else" }),
      chainEventFixture(),
      fullEnvFixture(),
    );
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((m) => m.key)).toContain("vault_state_v2_observed_scheme_invalid");
  });

  it("epoch mismatch", () => {
    const result = compareObservedDepositArtifact(
      observedArtifactFixture({ dkgEpoch: "999" }),
      chainEventFixture(),
      fullEnvFixture(),
    );
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((m) => m.key)).toContain("vault_state_v2_observed_epoch_mismatch");
  });

  it("depositCount mismatch", () => {
    const result = compareObservedDepositArtifact(
      observedArtifactFixture({ depositCount: 999 }),
      chainEventFixture(),
      fullEnvFixture(),
    );
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((m) => m.key)).toContain("vault_state_v2_observed_count_mismatch");
  });

  it("sender mismatch", () => {
    const result = compareObservedDepositArtifact(
      observedArtifactFixture({ senderAddress: `0x${"9".repeat(64)}` }),
      chainEventFixture(),
      fullEnvFixture(),
    );
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((m) => m.key)).toContain("vault_state_v2_observed_sender_mismatch");
  });

  it("asset mismatch", () => {
    const result = compareObservedDepositArtifact(
      observedArtifactFixture({ assetType: `0x${"9".repeat(64)}` }),
      chainEventFixture(),
      fullEnvFixture(),
    );
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((m) => m.key)).toContain("vault_state_v2_observed_asset_mismatch");
  });

  it("chainId mismatch", () => {
    const result = compareObservedDepositArtifact(
      observedArtifactFixture({ chainId: 99 }),
      chainEventFixture(),
      fullEnvFixture(),
    );
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((m) => m.key)).toContain("vault_state_v2_observed_chain_mismatch");
  });

  it("vaultEk mismatch", () => {
    const result = compareObservedDepositArtifact(
      observedArtifactFixture({ vaultEk: `0x${"9".repeat(64)}` }),
      chainEventFixture(),
      fullEnvFixture(),
    );
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((m) => m.key)).toContain("vault_state_v2_observed_vaultek_mismatch");
  });

  it("caPayloadHash mismatch (chain disagrees with artifact)", () => {
    const result = compareObservedDepositArtifact(
      observedArtifactFixture({ caPayloadHash: HEX_E }),
      chainEventFixture(),
      fullEnvFixture(),
    );
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((m) => m.key)).toContain("vault_state_v2_observed_ca_payload_hash_mismatch");
  });

  it("sequenceNumber mismatch", () => {
    const result = compareObservedDepositArtifact(
      observedArtifactFixture({ sequenceNumber: "999" }),
      chainEventFixture(),
      fullEnvFixture(),
    );
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((m) => m.key)).toContain("vault_state_v2_observed_sequence_number_mismatch");
  });

  it("txVersion mismatch", () => {
    const result = compareObservedDepositArtifact(
      observedArtifactFixture({ txVersion: "9999" }),
      chainEventFixture(),
      fullEnvFixture(),
    );
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((m) => m.key)).toContain("vault_state_v2_observed_tx_version_mismatch");
  });

  it("eventGuid missing", () => {
    const result = compareObservedDepositArtifact(
      observedArtifactFixture({ eventGuid: "" }),
      chainEventFixture(),
      fullEnvFixture(),
    );
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((m) => m.key)).toContain("vault_state_v2_observed_event_guid_missing");
  });

  it("perSlotContributions count mismatch", () => {
    const artifact = observedArtifactFixture();
    artifact.perSlotContributions = artifact.perSlotContributions.slice(0, 3);
    const result = compareObservedDepositArtifact(artifact, chainEventFixture(), fullEnvFixture());
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((m) => m.key)).toContain("vault_state_v2_observed_per_slot_count_mismatch");
  });
});

// =============================================================================================
// selectObservedDepositArtifact
// =============================================================================================

describe("selectObservedDepositArtifact", () => {
  it("no candidates", () => {
    const result = selectObservedDepositArtifact([], chainEventFixture(), fullEnvFixture(), "rid");
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("no_candidates");
  });

  it("single match", () => {
    const candidates = [
      { path: "/a/rid-001.json", artifact: observedArtifactFixture() },
      { path: "/a/rid-bad.json", artifact: observedArtifactFixture({ caPayloadHash: HEX_E }) },
    ];
    const result = selectObservedDepositArtifact(candidates, chainEventFixture(), fullEnvFixture(), undefined);
    expect(result.ok).toBe(true);
    expect(result.selected.path).toBe("/a/rid-001.json");
  });

  it("ambiguous without requestId", () => {
    const candidates = [
      { path: "/a/rid-001.json", artifact: observedArtifactFixture() },
      { path: "/a/rid-002.json", artifact: observedArtifactFixture() },
    ];
    const result = selectObservedDepositArtifact(candidates, chainEventFixture(), fullEnvFixture(), undefined);
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("ambiguous");
    expect(result.matchedPaths).toEqual(["/a/rid-001.json", "/a/rid-002.json"]);
  });

  it("ambiguous resolved by requestId", () => {
    const candidates = [
      { path: "/a/rid-001.json", artifact: observedArtifactFixture() },
      { path: "/a/rid-002.json", artifact: observedArtifactFixture() },
    ];
    const result = selectObservedDepositArtifact(candidates, chainEventFixture(), fullEnvFixture(), "rid-001");
    expect(result.ok).toBe(true);
    expect(result.selected.path).toBe("/a/rid-001.json");
  });

  it("no match — all candidates disagree", () => {
    const candidates = [
      { path: "/a/x.json", artifact: observedArtifactFixture({ caPayloadHash: HEX_E }) },
      { path: "/a/y.json", artifact: observedArtifactFixture({ txVersion: "9999" }) },
    ];
    const result = selectObservedDepositArtifact(candidates, chainEventFixture(), fullEnvFixture(), undefined);
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("no_match");
    expect(result.allMismatches.length).toBe(2);
    expect(result.allMismatches[0].path).toBe("/a/x.json");
    expect(result.allMismatches[1].path).toBe("/a/y.json");
  });
});

// =============================================================================================
// buildFinalReport — submit artifact validation paths
// =============================================================================================

describe("buildFinalReport — submit artifact validation", () => {
  it("simulated submit rejected", async () => {
    const stateRoot = makeTmpStateRoot();
    writeSubmitArtifact(stateRoot, "7", "rid-001", submitArtifactFixture({ simulated: true }));
    const env = fullEnvFixture();
    const result = await buildFinalReport({}, env, "/", stateRoot);
    expect(result.ok).toBe(false);
    expect(result.missingArtifacts.some((m) => /simulated=true/.test(m.reason))).toBe(true);
  });

  it("chainSuccess=false rejected", async () => {
    const stateRoot = makeTmpStateRoot();
    writeSubmitArtifact(stateRoot, "7", "rid-001", submitArtifactFixture({ chainSuccess: false }));
    const env = fullEnvFixture();
    const result = await buildFinalReport({}, env, "/", stateRoot);
    expect(result.ok).toBe(false);
    expect(result.missingArtifacts.some((m) => /chainSuccess=false/.test(m.reason))).toBe(true);
  });

  it("malformed txHash in submit artifact rejected", async () => {
    const stateRoot = makeTmpStateRoot();
    writeSubmitArtifact(stateRoot, "7", "rid-001", submitArtifactFixture({ txHash: TX_HASH_BAD }));
    const env = fullEnvFixture();
    const result = await buildFinalReport({}, env, "/", stateRoot);
    expect(result.ok).toBe(false);
    expect(result.missingArtifacts.some((m) => /no valid txHash/.test(m.reason))).toBe(true);
  });

  it("submit artifact absent on disk rejected", async () => {
    const stateRoot = makeTmpStateRoot();
    const env = fullEnvFixture();
    const result = await buildFinalReport({}, env, "/", stateRoot);
    expect(result.ok).toBe(false);
    expect(result.missingArtifacts.some((m) => /submit-transcript artifact not found/.test(m.reason))).toBe(true);
  });

  it("submit artifact present + completed=false rejected", async () => {
    const stateRoot = makeTmpStateRoot();
    writeSubmitArtifact(stateRoot, "7", "rid-001", submitArtifactFixture({ completed: false }));
    const env = fullEnvFixture();
    const result = await buildFinalReport({}, env, "/", stateRoot);
    expect(result.ok).toBe(false);
    expect(result.missingArtifacts.some((m) => /completed=false/.test(m.reason))).toBe(true);
  });
});

// =============================================================================================
// buildFinalReport — independent chain re-query path
// =============================================================================================

describe("buildFinalReport — independent chain re-query", () => {
  it("chain re-query 404 rejected", async () => {
    const stateRoot = makeTmpStateRoot();
    writeSubmitArtifact(stateRoot, "7", "rid-001", submitArtifactFixture());
    const env = fullEnvFixture();

    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      status: 404,
      ok: false,
      text: async () => "",
    });

    const result = await buildFinalReport({}, env, "/", stateRoot);
    expect(result.ok).toBe(false);
    expect(result.missingArtifacts.some((m) => /Independent on-chain re-query/.test(m.reason))).toBe(true);
  });

  it("chain re-query body.success=false rejected", async () => {
    const stateRoot = makeTmpStateRoot();
    writeSubmitArtifact(stateRoot, "7", "rid-001", submitArtifactFixture());
    const env = fullEnvFixture();

    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      status: 200,
      ok: true,
      text: async () => JSON.stringify({ success: false, vm_status: "ABORTED", version: "1234" }),
    });

    const result = await buildFinalReport({}, env, "/", stateRoot);
    expect(result.ok).toBe(false);
    expect(result.missingArtifacts.some((m) => /Independent on-chain re-query/.test(m.reason))).toBe(true);
  });

  it("chain re-query non-Executed vm_status rejected", async () => {
    const stateRoot = makeTmpStateRoot();
    writeSubmitArtifact(stateRoot, "7", "rid-001", submitArtifactFixture());
    const env = fullEnvFixture();

    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      status: 200,
      ok: true,
      text: async () => JSON.stringify({ success: true, vm_status: "Out of gas", version: "1234" }),
    });

    const result = await buildFinalReport({}, env, "/", stateRoot);
    expect(result.ok).toBe(false);
    expect(result.missingArtifacts.some((m) => /vm_status is "Out of gas"/.test(m.reason))).toBe(true);
  });
});

// =============================================================================================
// runPreflight — BridgeVault / DeoperatorConfigV2 are queried at BRIDGE_PACKAGE_ADDRESS,
// NOT at EUNOMA_TESTNET_VAULT_ADDRESS. Vault is a value inside BridgeVault, not its location.
// =============================================================================================

function fetchUrlCapturingStub(routeMap) {
  const calls = [];
  return [
    calls,
    vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => {
      calls.push(String(url));
      const entry = Object.entries(routeMap).find(([pattern]) => String(url).includes(pattern));
      if (!entry) {
        return { status: 404, ok: false, text: async () => "" };
      }
      const [, value] = entry;
      const status = value.status ?? 200;
      const body = value.body ?? null;
      return {
        status,
        ok: status >= 200 && status < 300,
        text: async () => (body === null ? "" : JSON.stringify(body)),
      };
    }),
  ];
}

describe("runPreflight — BridgeVault/DeoperatorConfigV2 query target", () => {
  it("queries BridgeVault at BRIDGE_PACKAGE_ADDRESS, not at vault address", async () => {
    const env = fullEnvFixture();
    const bridge = env.BRIDGE_PACKAGE_ADDRESS;
    const [calls] = fetchUrlCapturingStub({
      // The /modules endpoint must return an eunoma_bridge entry so the bridge_modules check
      // passes (this is checked before BridgeVault).
      "/modules": { body: [{ abi: { name: "eunoma_bridge" } }] },
      // BridgeVault must be queryable at bridge address — return a healthy resource.
      "BridgeVault": {
        body: {
          data: {
            vault_addr: env.EUNOMA_TESTNET_VAULT_ADDRESS,
            asset_type: env.EUNOMA_TESTNET_ASSET_TYPE,
          },
        },
      },
      "DeoperatorConfigV2": {
        body: {
          data: { dkg_epoch: env.EUNOMA_TESTNET_DKG_EPOCH, threshold: 5 },
        },
      },
    });

    await runPreflight({ env, serviceRoot: "/", stateRoot: "/tmp" });

    // The BridgeVault query URL must include bridgeAddress, not vaultAddress.
    const bridgeVaultCalls = calls.filter((u) => u.includes("BridgeVault"));
    expect(bridgeVaultCalls.length).toBeGreaterThan(0);
    for (const u of bridgeVaultCalls) {
      // Find the /v1/accounts/<addr>/ segment.
      const m = u.match(/\/v1\/accounts\/([^/]+)\/resource\//);
      expect(m).not.toBeNull();
      const queriedAddr = m[1].toLowerCase();
      expect(queriedAddr).toBe(bridge.toLowerCase());
      expect(queriedAddr).not.toBe(env.EUNOMA_TESTNET_VAULT_ADDRESS.toLowerCase());
    }

    const cfgCalls = calls.filter((u) => u.includes("DeoperatorConfigV2"));
    expect(cfgCalls.length).toBeGreaterThan(0);
    for (const u of cfgCalls) {
      const m = u.match(/\/v1\/accounts\/([^/]+)\/resource\//);
      expect(m).not.toBeNull();
      const queriedAddr = m[1].toLowerCase();
      expect(queriedAddr).toBe(bridge.toLowerCase());
    }
  });

  it("flags bridge_vault_addr_mismatch when BridgeVault.vault_addr disagrees with env", async () => {
    const env = fullEnvFixture();
    const wrongVaultAddr = `0x${"9".repeat(64)}`; // intentionally different from env
    fetchUrlCapturingStub({
      "/modules": { body: [{ abi: { name: "eunoma_bridge" } }] },
      "BridgeVault": {
        body: {
          data: {
            vault_addr: wrongVaultAddr,
            asset_type: env.EUNOMA_TESTNET_ASSET_TYPE,
          },
        },
      },
      "DeoperatorConfigV2": {
        body: { data: { dkg_epoch: env.EUNOMA_TESTNET_DKG_EPOCH, threshold: 5 } },
      },
    });

    const result = await runPreflight({ env, serviceRoot: "/", stateRoot: "/tmp" });

    expect(result.missing.some((m) => m.key === "bridge_vault_addr_mismatch")).toBe(true);
  });

  it("passes BridgeVault binding when vault_addr matches env even with { inner } shape", async () => {
    const env = fullEnvFixture();
    fetchUrlCapturingStub({
      "/modules": { body: [{ abi: { name: "eunoma_bridge" } }] },
      "BridgeVault": {
        body: {
          data: {
            // Aptos sometimes wraps address values as { inner }.
            vault_addr: { inner: env.EUNOMA_TESTNET_VAULT_ADDRESS },
            asset_type: { inner: env.EUNOMA_TESTNET_ASSET_TYPE },
          },
        },
      },
      "DeoperatorConfigV2": {
        body: { data: { dkg_epoch: env.EUNOMA_TESTNET_DKG_EPOCH, threshold: 5 } },
      },
    });

    const result = await runPreflight({ env, serviceRoot: "/", stateRoot: "/tmp" });
    expect(result.missing.some((m) => m.key === "bridge_vault_addr_mismatch")).toBe(false);
    expect(result.missing.some((m) => m.key === "bridge_vault_resource")).toBe(false);
  });

  it("flags bridge_vault_resource when the resource is absent at bridge address", async () => {
    const env = fullEnvFixture();
    fetchUrlCapturingStub({
      "/modules": { body: [{ abi: { name: "eunoma_bridge" } }] },
      "BridgeVault": { status: 404 },
      "DeoperatorConfigV2": {
        body: { data: { dkg_epoch: env.EUNOMA_TESTNET_DKG_EPOCH, threshold: 5 } },
      },
    });

    const result = await runPreflight({ env, serviceRoot: "/", stateRoot: "/tmp" });
    expect(result.missing.some((m) => m.key === "bridge_vault_resource")).toBe(true);
  });
});

// =============================================================================================
// isHex64 / isTxHash regression tests (used by env validation + downstream)
// =============================================================================================

describe("isHex64 / isTxHash", () => {
  it("accepts 64-hex with and without 0x", () => {
    expect(isHex64("a".repeat(64))).toBe(true);
    expect(isHex64(`0x${"a".repeat(64)}`)).toBe(true);
  });
  it("rejects malformed", () => {
    expect(isHex64("not-a-hex")).toBe(false);
    expect(isHex64("a".repeat(63))).toBe(false);
    expect(isHex64("a".repeat(65))).toBe(false);
    expect(isHex64(undefined)).toBe(false);
  });
  it("isTxHash matches the 64-hex shape", () => {
    expect(isTxHash(`0x${"1".repeat(64)}`)).toBe(true);
    expect(isTxHash("0xnot-a-hash")).toBe(false);
  });
});

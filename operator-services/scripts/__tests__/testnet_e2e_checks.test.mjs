// Tests for scripts/_lib/testnet_e2e_checks.mjs.
//
// Scope: the pure helpers + the chain-dependent paths of runPreflight/buildFinalReport
// driven by stubbed globalThis.fetch + tmp-dir state roots. The tests must NOT shell out
// to `aptos` and must NOT touch real network endpoints.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  validateRequiredEnv,
  compareObservedDepositArtifact,
  selectObservedDepositArtifact,
  buildFinalReport,
  runPreflight,
  isHex64,
  isTxHash,
  vaultStateContentSignature,
  findSlotContentCollisions,
  evaluateReplayBypass,
  evaluateSkipTreeBuild,
} from "../_lib/testnet_e2e_checks.mjs";
import { CommitmentTreeV2 } from "../../../circuits/scripts/commitment_tree_v2.mjs";
import {
  bigToLE32,
  le32ToHex,
} from "../../../circuits/scripts/poseidon_merkle.mjs";

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

// =============================================================================================
// M9 helpers — slot truthfulness + privacy invariants
// =============================================================================================

describe("vaultStateContentSignature (M9-f)", () => {
  it("ignores slot + player_id fields when computing signature", () => {
    const slot0 = { slot: 0, player_id: 0, deposit_count_observed: 1, x: "y" };
    const slot5_clone = { slot: 5, player_id: 5, deposit_count_observed: 1, x: "y" };
    expect(vaultStateContentSignature(slot0)).toBe(vaultStateContentSignature(slot5_clone));
  });
  it("returns different signatures when content differs", () => {
    const a = { slot: 0, player_id: 0, content: "A" };
    const b = { slot: 0, player_id: 0, content: "B" };
    expect(vaultStateContentSignature(a)).not.toBe(vaultStateContentSignature(b));
  });
  it("null on bad input", () => {
    expect(vaultStateContentSignature(null)).toBe(null);
    expect(vaultStateContentSignature("not-an-object")).toBe(null);
  });
});

describe("findSlotContentCollisions (M9-f)", () => {
  it("returns [] when all 7 slots have distinct content", () => {
    const states = Array.from({ length: 7 }, (_, slot) => ({
      slot,
      json: { slot, player_id: slot, worker_transcript_hash: `0x${slot}`.padEnd(66, "f") },
    }));
    expect(findSlotContentCollisions(states)).toEqual([]);
  });
  it("flags slot-5 + slot-6 backfilled from slot-0", () => {
    const base = { worker_transcript_hash: "0x" + "a".repeat(64), deposit_count_observed: 1 };
    const states = [
      { slot: 0, json: { slot: 0, player_id: 0, ...base } },
      { slot: 1, json: { slot: 1, player_id: 1, worker_transcript_hash: "0x" + "1".repeat(64) } },
      { slot: 2, json: { slot: 2, player_id: 2, worker_transcript_hash: "0x" + "2".repeat(64) } },
      { slot: 3, json: { slot: 3, player_id: 3, worker_transcript_hash: "0x" + "3".repeat(64) } },
      { slot: 4, json: { slot: 4, player_id: 4, worker_transcript_hash: "0x" + "4".repeat(64) } },
      { slot: 5, json: { slot: 5, player_id: 5, ...base } }, // backfill of slot 0
      { slot: 6, json: { slot: 6, player_id: 6, ...base } }, // backfill of slot 0
    ];
    const dups = findSlotContentCollisions(states);
    // [0,5], [0,6], [5,6] all collide
    expect(dups.length).toBe(3);
    const flat = new Set(dups.flat());
    expect(flat.has(0)).toBe(true);
    expect(flat.has(5)).toBe(true);
    expect(flat.has(6)).toBe(true);
  });
});

// =============================================================================================
// M10-h — buildFinalReport truthfulness via CommitmentTreeV2.deserialize + drop leafIndex
//
// Codex P1 finding: buildFinalReport read commitment_tree_v2.json as raw JSON without re-running
// CommitmentTreeV2.deserialize() — a tampered tree could pass the privacy gate. M10-h forces
// deserialize() and drops leafIndex/commitmentHex from report.privacy to preserve multi-leaf
// unlinkability.
// =============================================================================================

const FR_MOD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function frFromSeed(seed) {
  let v = 0n;
  for (let i = 0; i < seed.length; i++) {
    v = (v * 1099511628211n + BigInt(seed.charCodeAt(i) + i)) & ((1n << 254n) - 1n);
  }
  return v % FR_MOD;
}

function senderHexN(n) {
  return ("0x" + n.toString(16).padStart(64, "f")).toLowerCase();
}

/**
 * Build a real CommitmentTreeV2 snapshot with `leafCount` distinct depositMeta entries,
 * each with a distinct sender (so distinctDepositSenders >= 2 for the privacy gate),
 * then serialize() to produce the canonical JSON contract that the report consumer expects.
 *
 * Returns { snapshot, rootHex } so callers can wire `usedRootHex` to the same value.
 */
async function buildRealTreeSnapshot(leafCount = 8) {
  const t = new CommitmentTreeV2(20);
  for (let i = 1; i <= leafCount; i++) {
    const big = frFromSeed(`m10h-leaf-${i}`);
    const commitmentHex = le32ToHex(bigToLE32(big));
    t.append(big, {
      depositCount: i,
      depositTxHash: "0x" + i.toString(16).padStart(64, "0"),
      txVersion: String(2000 + i),
      sequenceNumber: String(i),
      sender: senderHexN(i),
      commitmentHex,
    });
  }
  const snapshot = await t.serialize();
  return { snapshot, rootHex: snapshot.latestRootHex };
}

/**
 * Write every artifact buildFinalReport needs to reach the happy-path return, parameterized
 * over the commitment tree snapshot (so callers can tamper post-write) and the slot lineup.
 *
 * Mirrors the schema each production component emits on a successful run. NOT a fixture of the
 * real online flow — just enough fields to satisfy each null/exists check in buildFinalReport.
 */
async function writeHappyFixture(stateRoot, env, treeSnapshot, opts = {}) {
  const dkgEpoch = env.EUNOMA_TESTNET_DKG_EPOCH;
  const requestId = env.EUNOMA_TESTNET_REQUEST_ID;
  const usedRootHex = treeSnapshot.latestRootHex;
  const transcriptHash = treeSnapshot.transcriptHash;
  const selectedSlots = opts.selectedSlots ?? [0, 1, 2, 3, 4];
  const initTranscriptHash = opts.initTranscriptHash ?? ("0x" + "e".repeat(64));
  const chainSuccess = opts.chainSuccess ?? true;

  // 1. Submit artifact
  writeSubmitArtifact(stateRoot, dkgEpoch, requestId, submitArtifactFixture({
    chainSuccess,
    transcriptHash: "0x" + "c".repeat(64),
    finalizeTranscriptHash: "0x" + "a".repeat(64),
  }));

  // 2. Finalize transcript — provides selectedSlots + rosterHash + ca_payload_hash + root.
  const finalizeDir = join(stateRoot, "coordinator", "mpcca_withdraw");
  mkdirSync(finalizeDir, { recursive: true });
  writeFileSync(
    join(finalizeDir, `${dkgEpoch}__${requestId}__finalize.json`),
    JSON.stringify({
      schema: "mpcca_withdraw_finalize_v2",
      selectedSlots,
      quorumTranscriptHash: "0x" + "1".repeat(64),
      transcriptHash: "0x" + "1".repeat(64),
      mpccaWithdrawFinalTranscriptHash: "0x" + "1".repeat(64),
      rosterHash: "0x" + "2".repeat(64),
      withdrawV2CallArgsFields: {
        caPayloadHash: "0x" + "3".repeat(64),
        root: usedRootHex,
        selectedSlots,
      },
    }),
  );

  // 3. CA DKG V2 phase-2
  const caDir = join(stateRoot, "coordinator", "ca_dkg_v2");
  mkdirSync(caDir, { recursive: true });
  writeFileSync(
    join(caDir, `${dkgEpoch}__phase2.json`),
    JSON.stringify({
      schema: "ca_dkg_v2_phase2",
      rosterHash: "0x" + "4".repeat(64),
      caDkgV2RosterHash: "0x" + "4".repeat(64),
    }),
  );

  // 4. FROST DKG V2
  const frostDir = join(stateRoot, "coordinator", "frost_dkg_v2");
  mkdirSync(frostDir, { recursive: true });
  writeFileSync(
    join(frostDir, `${dkgEpoch}.json`),
    JSON.stringify({
      schema: "frost_dkg_v2",
      rosterHash: "0x" + "5".repeat(64),
      frostDkgV2RosterHash: "0x" + "5".repeat(64),
    }),
  );

  // 5. Per-slot vault_state_v2 — must agree on init_transcript_hash and have DISTINCT
  //    worker_transcript_hash (M9-f collision detector).
  for (const slot of selectedSlots) {
    const slotDir = join(stateRoot, `slot-${slot}`);
    mkdirSync(slotDir, { recursive: true });
    writeFileSync(
      join(slotDir, "vault_state_v2.json"),
      JSON.stringify({
        schema: "vault_state_v2",
        slot,
        player_id: slot,
        worker_transcript_hash: "0x" + (slot.toString(16).padStart(64, "a")),
        init_transcript_hash: initTranscriptHash,
        deposit_count_observed: 1,
      }),
    );
  }

  // 6. Commitment tree
  const coordDir = join(stateRoot, "coordinator");
  mkdirSync(coordDir, { recursive: true });
  writeFileSync(
    join(coordDir, "commitment_tree_v2.json"),
    JSON.stringify(treeSnapshot, null, 2),
  );

  // 7. Withdraw tree context (M10-f schema: no leafIndex, no commitmentHex)
  writeFileSync(
    join(coordDir, `withdraw_tree_context_${requestId.replace(/[^A-Za-z0-9_-]/g, "_")}.json`),
    JSON.stringify({
      schema: "withdraw_tree_context_v2",
      requestId,
      rootHex: usedRootHex,
      treeTranscriptHash: transcriptHash,
      anonymitySetSize: treeSnapshot.leafCount,
      distinctDepositSenders: new Set(treeSnapshot.depositMeta.map((m) => m.sender)).size,
      mode: "real-balance",
      depositorWitnessSchemaVersion: "v2_depositor_witness_v1",
      createdAtUnixMs: Date.now(),
    }),
  );

  return { usedRootHex, transcriptHash, selectedSlots };
}

/**
 * Snapshot fixture for the snapshot argument buildFinalReport(snapshot, ...) consumes — only
 * the fields it actually reads (`vaultInitTx`, `depositTx`, `depositEvent`,
 * `observedDepositTranscriptHash`, `deoperatorConfig`, etc).
 */
function happySnapshotArg(env) {
  return {
    vaultInitTx: { hash: env.EUNOMA_TESTNET_DEPOSIT_TX_HASH, version: "100" },
    depositTx: { hash: env.EUNOMA_TESTNET_DEPOSIT_TX_HASH, version: "100" },
    depositEvent: { commitment: "0x" + "b".repeat(64), version: "100" },
    observedDepositTranscriptHash: "0x" + "f".repeat(64),
    deoperatorConfig: { threshold: 5, operator_set_version: 1, dkg_epoch: env.EUNOMA_TESTNET_DKG_EPOCH },
    vaultInitArtifactPath: "/tmp/vault_init.json",
    observedDepositArtifactPath: "/tmp/observed_deposit.json",
  };
}

function mockChainReQueryOk() {
  vi.spyOn(globalThis, "fetch").mockResolvedValue({
    status: 200,
    ok: true,
    text: async () => JSON.stringify({ success: true, vm_status: "Executed successfully", version: "1234" }),
  });
}

describe("buildFinalReport — M10-h tree integrity + privacy field discipline", () => {
  it("tampered tree JSON (depositMeta sender swapped) → integrityFailure=tree_transcript_mismatch", async () => {
    const stateRoot = makeTmpStateRoot();
    const env = fullEnvFixture();
    const { snapshot } = await buildRealTreeSnapshot(8);
    // Tamper with one leaf's sender — this invalidates the transcriptHash binding but leaves
    // the leaf bytes themselves untouched, so the root still matches the tampered file's
    // claim. CommitmentTreeV2.deserialize() re-runs the transcript hash over the tampered
    // depositMeta and gets a different result vs. the file's claimed `transcriptHash`.
    const tamperedSnapshot = JSON.parse(JSON.stringify(snapshot));
    tamperedSnapshot.depositMeta[3].sender = "0x" + "9".repeat(64);
    await writeHappyFixture(stateRoot, env, tamperedSnapshot);
    mockChainReQueryOk();

    const result = await buildFinalReport(happySnapshotArg(env), env, "/", stateRoot);
    expect(result.ok).toBe(false);
    expect(result.integrityFailure).toBe("tree_transcript_mismatch");
  });

  it("tampered tree JSON (latestRootHex flipped) → integrityFailure=tree_root_mismatch", async () => {
    const stateRoot = makeTmpStateRoot();
    const env = fullEnvFixture();
    const { snapshot } = await buildRealTreeSnapshot(8);
    // Tamper with the claimed root hex; leaves+depositMeta unchanged. CommitmentTreeV2.deserialize()
    // re-derives the root from leaves and detects the mismatch BEFORE computing the transcript.
    const tamperedSnapshot = JSON.parse(JSON.stringify(snapshot));
    tamperedSnapshot.latestRootHex = "0x" + "0".repeat(64);
    await writeHappyFixture(stateRoot, env, tamperedSnapshot);
    mockChainReQueryOk();

    const result = await buildFinalReport(happySnapshotArg(env), env, "/", stateRoot);
    expect(result.ok).toBe(false);
    expect(result.integrityFailure).toBe("tree_root_mismatch");
  });

  it("leafIndex and commitmentHex are absent from report.privacy on the happy path", async () => {
    const stateRoot = makeTmpStateRoot();
    const env = fullEnvFixture();
    const { snapshot } = await buildRealTreeSnapshot(8);
    await writeHappyFixture(stateRoot, env, snapshot);
    mockChainReQueryOk();

    const result = await buildFinalReport(happySnapshotArg(env), env, "/", stateRoot);
    if (!result.ok) {
      // Surface the precise reason if the fixture is incomplete so future maintainers
      // don't chase phantom regressions.
      throw new Error(
        `expected ok=true for happy fixture, got: ${JSON.stringify(result, null, 2)}`,
      );
    }
    expect(result.report.privacy).toBeDefined();
    expect(result.report.privacy.leafIndexUsed).toBeUndefined();
    expect(result.report.privacy.commitmentHex).toBeUndefined();
    // The legitimate anonymity-set aggregates must still be present.
    expect(result.report.privacy.anonymitySetSize).toBe(8);
    expect(result.report.privacy.distinctDepositSenders).toBe(8);
    expect(typeof result.report.privacy.treeRootHex).toBe("string");
    expect(typeof result.report.privacy.treeTranscriptHash).toBe("string");
  });

  it("balanceWitnessIntegrity is true iff the submit tx chainSuccess is true", async () => {
    // Case A: chainSuccess=true → flag is true.
    {
      const stateRoot = makeTmpStateRoot();
      const env = fullEnvFixture();
      const { snapshot } = await buildRealTreeSnapshot(8);
      await writeHappyFixture(stateRoot, env, snapshot, { chainSuccess: true });
      mockChainReQueryOk();
      const result = await buildFinalReport(happySnapshotArg(env), env, "/", stateRoot);
      if (!result.ok) {
        throw new Error(
          `case A (chainSuccess=true) expected ok=true, got: ${JSON.stringify(result, null, 2)}`,
        );
      }
      expect(result.report.privacy.balanceWitnessIntegrity).toBe(true);
    }
    // Reset fetch mock between cases so each test gets its own isolation.
    vi.restoreAllMocks();
    // Case B: chainSuccess=false → submit-stage gate already rejects (ok=false). The whole
    // function never reaches the privacy block, so balanceWitnessIntegrity isn't emitted.
    // This is the desired semantics: a failed on-chain submit hard-fails the report; the
    // flag only becomes meaningful on the happy path.
    {
      const stateRoot = makeTmpStateRoot();
      const env = fullEnvFixture();
      const { snapshot } = await buildRealTreeSnapshot(8);
      await writeHappyFixture(stateRoot, env, snapshot, { chainSuccess: false });
      mockChainReQueryOk();
      const result = await buildFinalReport(happySnapshotArg(env), env, "/", stateRoot);
      expect(result.ok).toBe(false);
      expect(result.missingArtifacts.some((m) => /chainSuccess=false/.test(m.reason))).toBe(true);
    }
  });
});

// =============================================================================================
// M10-i — tx freshness check + two-gate env bypass
//
// Codex P1 finding: the chain re-query at the submit stage only verifies that the surfaced tx
// succeeded; it does not assert the tx is FRESH for the current run. A replay could present an
// old withdraw tx (e.g. M8's 0xeb55af02...) and pass every prior invariant. M10-i adds a
// historical-set check + two-gate env bypass for the replay/skip-tree-build flags.
// =============================================================================================

describe("buildFinalReport — M10-i tx freshness check", () => {
  it("chain tx hash in historical set → integrityFailure=tx_freshness_failed", async () => {
    const stateRoot = makeTmpStateRoot();
    const env = fullEnvFixture();
    const { snapshot } = await buildRealTreeSnapshot(8);
    await writeHappyFixture(stateRoot, env, snapshot);
    mockChainReQueryOk();

    // Seed the historical file with the submit tx hash. The submitArtifactFixture uses
    // TX_HASH_OK = 0x${"1".repeat(64)}; pre-populating it forces the freshness gate to fail.
    writeFileSync(
      join(stateRoot, "historical_withdraw_txs.json"),
      JSON.stringify(
        {
          txs: [TX_HASH_OK],
          note: "fixture: pretend M8's withdraw was already on chain",
          updatedAtUnixMs: 1716000000000,
        },
        null,
        2,
      ),
    );

    const result = await buildFinalReport(happySnapshotArg(env), env, "/", stateRoot);
    expect(result.ok).toBe(false);
    expect(result.integrityFailure).toBe("tx_freshness_failed");
    expect(result.txReplayed?.toLowerCase()).toBe(TX_HASH_OK.toLowerCase());
  });

  it("chain tx hash in historical set with different casing → still detected", async () => {
    const stateRoot = makeTmpStateRoot();
    const env = fullEnvFixture();
    const { snapshot } = await buildRealTreeSnapshot(8);
    await writeHappyFixture(stateRoot, env, snapshot);
    mockChainReQueryOk();

    // Uppercase the historical entry; case-insensitive match should still trip the gate.
    writeFileSync(
      join(stateRoot, "historical_withdraw_txs.json"),
      JSON.stringify({ txs: [TX_HASH_OK.toUpperCase()] }, null, 2),
    );

    const result = await buildFinalReport(happySnapshotArg(env), env, "/", stateRoot);
    expect(result.ok).toBe(false);
    expect(result.integrityFailure).toBe("tx_freshness_failed");
  });

  it("happy path with no prior history → tx is appended atomically (.tmp not left over)", async () => {
    const stateRoot = makeTmpStateRoot();
    const env = fullEnvFixture();
    const { snapshot } = await buildRealTreeSnapshot(8);
    await writeHappyFixture(stateRoot, env, snapshot);
    mockChainReQueryOk();

    const historicalPath = join(stateRoot, "historical_withdraw_txs.json");
    const tmpPath = `${historicalPath}.tmp`;
    expect(existsSync(historicalPath)).toBe(false);

    const result = await buildFinalReport(happySnapshotArg(env), env, "/", stateRoot);
    if (!result.ok) {
      throw new Error(
        `expected ok=true for happy fixture, got: ${JSON.stringify(result, null, 2)}`,
      );
    }

    expect(existsSync(historicalPath)).toBe(true);
    expect(existsSync(tmpPath)).toBe(false); // atomic rename removes the .tmp
    const written = JSON.parse(readFileSync(historicalPath, "utf8"));
    expect(written.txs).toEqual([TX_HASH_OK]);
    expect(typeof written.updatedAtUnixMs).toBe("number");
  });

  it("write happens only on full success — failed run does not pollute the historical set", async () => {
    const stateRoot = makeTmpStateRoot();
    const env = fullEnvFixture();
    const { snapshot } = await buildRealTreeSnapshot(8);
    // chainSuccess=false makes the submit-stage gate fail BEFORE the freshness write runs.
    await writeHappyFixture(stateRoot, env, snapshot, { chainSuccess: false });
    mockChainReQueryOk();

    const historicalPath = join(stateRoot, "historical_withdraw_txs.json");
    expect(existsSync(historicalPath)).toBe(false);

    const result = await buildFinalReport(happySnapshotArg(env), env, "/", stateRoot);
    expect(result.ok).toBe(false);
    // Critical: even though chainConfirmedWithdraw was a real-looking tx, the write must NOT
    // have happened because the broader report failed. Otherwise a botched run would seed the
    // history and block a later legitimate retry of the same tx hash.
    expect(existsSync(historicalPath)).toBe(false);
  });

  it("malformed historical file is treated as empty rather than crashing the gate", async () => {
    const stateRoot = makeTmpStateRoot();
    const env = fullEnvFixture();
    const { snapshot } = await buildRealTreeSnapshot(8);
    await writeHappyFixture(stateRoot, env, snapshot);
    mockChainReQueryOk();

    writeFileSync(join(stateRoot, "historical_withdraw_txs.json"), "not valid json {{{");

    const result = await buildFinalReport(happySnapshotArg(env), env, "/", stateRoot);
    if (!result.ok) {
      throw new Error(
        `expected ok=true with malformed historical (fallback to empty), got: ${JSON.stringify(result, null, 2)}`,
      );
    }
    // The malformed file should have been overwritten with a clean shape.
    const written = JSON.parse(readFileSync(join(stateRoot, "historical_withdraw_txs.json"), "utf8"));
    expect(Array.isArray(written.txs)).toBe(true);
    expect(written.txs).toEqual([TX_HASH_OK]);
  });
});

// =============================================================================================
// M10-i — two-gate env bypass helpers
//
// The orchestrator delegates the two-gate decision to evaluateReplayBypass and
// evaluateSkipTreeBuild so the logic is unit-testable in isolation from the rest of
// testnet_e2e_v2.mjs (which can't run in CI without the aptos CLI, profiles, and chain
// reachability). These helpers are pure: env → boolean.
// =============================================================================================

describe("evaluateReplayBypass (M10-i two-gate replay)", () => {
  it("ALLOW_REPLAY_LOCAL=1 without LOCAL_SMOKE → false (replay blocked)", () => {
    expect(evaluateReplayBypass({ EUNOMA_TESTNET_ALLOW_REPLAY_LOCAL: "1" })).toBe(false);
  });

  it("LOCAL_SMOKE=1 without ALLOW_REPLAY_LOCAL → false (replay blocked)", () => {
    expect(evaluateReplayBypass({ EUNOMA_LOCAL_SMOKE: "1" })).toBe(false);
  });

  it("legacy EUNOMA_TESTNET_ALLOW_REPLAY=1 alone has NO effect → false", () => {
    // Critical: the old single-env flag must be DEAD. Any caller relying on it has to set the
    // new *_LOCAL flag + the local-smoke marker.
    expect(evaluateReplayBypass({ EUNOMA_TESTNET_ALLOW_REPLAY: "1" })).toBe(false);
    expect(
      evaluateReplayBypass({
        EUNOMA_TESTNET_ALLOW_REPLAY: "1",
        EUNOMA_TESTNET_ALLOW_REPLAY_LOCAL: "1",
        // LOCAL_SMOKE missing — should STILL be blocked.
      }),
    ).toBe(false);
  });

  it("both gates set (LOCAL_SMOKE=1 + ALLOW_REPLAY_LOCAL=1) → true (replay allowed)", () => {
    expect(
      evaluateReplayBypass({
        EUNOMA_LOCAL_SMOKE: "1",
        EUNOMA_TESTNET_ALLOW_REPLAY_LOCAL: "1",
      }),
    ).toBe(true);
  });

  it("non-'1' values do not satisfy the gate (e.g. 'true', 'yes', 'TRUE')", () => {
    expect(
      evaluateReplayBypass({
        EUNOMA_LOCAL_SMOKE: "true",
        EUNOMA_TESTNET_ALLOW_REPLAY_LOCAL: "1",
      }),
    ).toBe(false);
    expect(
      evaluateReplayBypass({
        EUNOMA_LOCAL_SMOKE: "1",
        EUNOMA_TESTNET_ALLOW_REPLAY_LOCAL: "yes",
      }),
    ).toBe(false);
  });

  it("empty env → false", () => {
    expect(evaluateReplayBypass({})).toBe(false);
    expect(evaluateReplayBypass(null)).toBe(false);
    expect(evaluateReplayBypass(undefined)).toBe(false);
  });
});

describe("evaluateSkipTreeBuild (M10-i two-gate skip-tree-build)", () => {
  it("SKIP_TREE_BUILD_LOCAL=1 without LOCAL_SMOKE → false (must rebuild)", () => {
    expect(evaluateSkipTreeBuild({ EUNOMA_TESTNET_SKIP_TREE_BUILD_LOCAL: "1" })).toBe(false);
  });

  it("LOCAL_SMOKE=1 without SKIP_TREE_BUILD_LOCAL → false (must rebuild)", () => {
    expect(evaluateSkipTreeBuild({ EUNOMA_LOCAL_SMOKE: "1" })).toBe(false);
  });

  it("legacy EUNOMA_TESTNET_SKIP_TREE_BUILD=1 alone has NO effect → false", () => {
    expect(evaluateSkipTreeBuild({ EUNOMA_TESTNET_SKIP_TREE_BUILD: "1" })).toBe(false);
  });

  it("both gates set (LOCAL_SMOKE=1 + SKIP_TREE_BUILD_LOCAL=1) → true (skip allowed)", () => {
    expect(
      evaluateSkipTreeBuild({
        EUNOMA_LOCAL_SMOKE: "1",
        EUNOMA_TESTNET_SKIP_TREE_BUILD_LOCAL: "1",
      }),
    ).toBe(true);
  });

  it("empty env → false", () => {
    expect(evaluateSkipTreeBuild({})).toBe(false);
    expect(evaluateSkipTreeBuild(null)).toBe(false);
  });
});

// =============================================================================================
// M10-i — orchestrator wiring smoke check
//
// Reads testnet_e2e_v2.mjs source and asserts it routes its replay/skip-tree-build decisions
// through the unit-tested helpers. This is the structural pin that prevents a future refactor
// from re-introducing the single-env bypass. Source-level pinning beats spawning the script
// because the orchestrator's preflight needs the `aptos` CLI + a funded testnet profile, which
// cannot be assumed in CI.
// =============================================================================================

const TESTNET_E2E_V2_SRC = readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), "..", "testnet_e2e_v2.mjs"),
  "utf8",
);

describe("testnet_e2e_v2.mjs — M10-i wiring", () => {
  it("imports the two-gate env helpers from _lib/testnet_e2e_checks.mjs", () => {
    expect(TESTNET_E2E_V2_SRC).toMatch(/evaluateReplayBypass/);
    expect(TESTNET_E2E_V2_SRC).toMatch(/evaluateSkipTreeBuild/);
  });

  it("uses evaluateReplayBypass(env) for the replay decision", () => {
    expect(TESTNET_E2E_V2_SRC).toMatch(/const\s+allowReplay\s*=\s*evaluateReplayBypass\(env\)/);
  });

  it("uses evaluateSkipTreeBuild(env) for the skip-tree-build decision", () => {
    expect(TESTNET_E2E_V2_SRC).toMatch(/const\s+skipTreeBuild\s*=\s*evaluateSkipTreeBuild\(env\)/);
  });

  it("no longer references the single-env legacy flags as decision gates", () => {
    // Comments still mention the legacy names (historical context); decision-bearing code
    // must NOT compare them with === "1". We assert no assignment uses the old single flag.
    expect(TESTNET_E2E_V2_SRC).not.toMatch(/env\.EUNOMA_TESTNET_ALLOW_REPLAY\s*!==\s*"1"/);
    expect(TESTNET_E2E_V2_SRC).not.toMatch(/env\.EUNOMA_TESTNET_SKIP_TREE_BUILD\s*!==\s*"1"/);
    expect(TESTNET_E2E_V2_SRC).not.toMatch(/env\.EUNOMA_TESTNET_ALLOW_REPLAY\s*===\s*"1"/);
    expect(TESTNET_E2E_V2_SRC).not.toMatch(/env\.EUNOMA_TESTNET_SKIP_TREE_BUILD\s*===\s*"1"/);
  });
});

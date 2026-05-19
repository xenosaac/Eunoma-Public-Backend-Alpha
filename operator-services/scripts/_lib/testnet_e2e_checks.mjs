// =============================================================================================
// M6 closure — chain-query, artifact-read, and final-report assembly helpers for testnet:e2e.
//
// This module is loaded by scripts/testnet_e2e_v2.mjs. It exists so the top-level orchestrator
// stays readable while the binding-final-gate validation logic lives in one place and stays
// testable in isolation.
//
// Hard contract (goal.md Final Acceptance, see /goal.md):
//   - Every prereq that's missing produces ONE structured entry in `missing[]` with
//     { key, message, remediation, priority }.
//   - On success, `snapshot` carries every value the final report will need, so the
//     orchestrator never re-queries the chain.
//   - On final-report assembly, ANY artifact missing or malformed produces a hard exit-1
//     with `final_report_artifacts_missing` — NO completion language is emitted.
// =============================================================================================
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve, join, dirname } from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

// M9: lazy-loaded helpers from circuits/scripts. Loaded once per process to avoid the
// circomlibjs WASM startup cost across each call.
let _commitmentTreeHelpers;
async function getCommitmentTreeHelpers() {
  if (_commitmentTreeHelpers) return _commitmentTreeHelpers;
  const here = dirname(fileURLToPath(import.meta.url));
  const tree = await import(`file://${resolve(here, "..", "..", "..", "circuits", "scripts", "commitment_tree_v2.mjs")}`);
  const poseidon = await import(`file://${resolve(here, "..", "..", "..", "circuits", "scripts", "poseidon_merkle.mjs")}`);
  _commitmentTreeHelpers = { ...tree, ...poseidon };
  return _commitmentTreeHelpers;
}

const HEX64 = /^(0x)?[0-9a-fA-F]{64}$/;
const TX_HASH_RE = /^(0x)?[0-9a-fA-F]{64}$/;

// =============================================================================================
// Low-level fetch + REST helpers
// =============================================================================================

export async function fetchJson(url, init) {
  let res;
  try {
    res = await fetch(url, init);
  } catch (err) {
    return { status: 0, ok: false, body: null, text: "", error: err?.message ?? String(err) };
  }
  const text = await res.text();
  let body = null;
  try {
    body = text.length === 0 ? null : JSON.parse(text);
  } catch {
    body = null;
  }
  return { status: res.status, ok: res.ok, body, text };
}

function trimSlash(s) {
  return s.replace(/\/+$/, "");
}

export async function getResource(nodeUrl, address, resourceType) {
  const url = `${trimSlash(nodeUrl)}/v1/accounts/${address}/resource/${encodeURIComponent(
    resourceType,
  )}`;
  return fetchJson(url);
}

export async function getModules(nodeUrl, address) {
  const url = `${trimSlash(nodeUrl)}/v1/accounts/${address}/modules?limit=200`;
  return fetchJson(url);
}

export async function getTransactionByHash(nodeUrl, txHash) {
  const url = `${trimSlash(nodeUrl)}/v1/transactions/by_hash/${txHash}`;
  return fetchJson(url);
}

export async function getAccount(nodeUrl, address) {
  return fetchJson(`${trimSlash(nodeUrl)}/v1/accounts/${address}`);
}

// =============================================================================================
// CLI / FS helpers
// =============================================================================================

export function checkAptosCli() {
  const r = spawnSync("aptos", ["--version"], { encoding: "utf8" });
  if (r.status !== 0 && r.status !== null) {
    return { ok: false, message: `aptos --version exited ${r.status}: ${r.stderr || r.stdout}` };
  }
  if (r.error) {
    return { ok: false, message: `aptos CLI not on PATH: ${r.error.message}` };
  }
  return { ok: true, version: (r.stdout || "").trim() };
}

/**
 * Find the nearest ancestor directory containing a .aptos/config.yaml. Returns null if not
 * found. We need this because the aptos CLI reads profiles from `${cwd}/.aptos/config.yaml`,
 * and the testnet:e2e script may run from operator-services/ while the .aptos lives at the
 * repo root.
 */
function findAptosConfigDir(startDir) {
  let dir = startDir;
  for (let i = 0; i < 8; i += 1) {
    if (existsSync(resolve(dir, ".aptos", "config.yaml"))) return dir;
    const parent = resolve(dir, "..");
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

export function listProfiles() {
  // The aptos CLI reads profiles from `${cwd}/.aptos/config.yaml`. In this repo the .aptos
  // lives at the repo root, NOT under operator-services/. Search ancestors for the config.
  const configDir = findAptosConfigDir(process.cwd()) ?? process.cwd();
  const r = spawnSync("aptos", ["config", "show-profiles"], {
    encoding: "utf8",
    cwd: configDir,
  });
  if (r.status !== 0 || r.error) {
    return { ok: false, profiles: [], error: r.stderr || r.error?.message || "" };
  }
  // Aptos CLI emits JSON when stdout is captured (Result envelope). Try JSON first.
  let profiles = [];
  try {
    const parsed = JSON.parse(r.stdout || "");
    if (parsed?.Result && typeof parsed.Result === "object") {
      profiles = Object.keys(parsed.Result);
    }
  } catch {
    // Fall back to the old line-by-line YAML-ish parser.
    for (const line of (r.stdout || "").split("\n")) {
      const m = line.match(/^\s*([A-Za-z0-9_.-]+):\s*$/);
      if (m) profiles.push(m[1]);
    }
  }
  return { ok: true, profiles };
}

export function readJsonIfExists(absPath) {
  if (!existsSync(absPath)) return null;
  try {
    return JSON.parse(readFileSync(absPath, "utf8"));
  } catch {
    return null;
  }
}

export function stateRootJoin(serviceRoot, stateRootEnv, ...segments) {
  return resolve(serviceRoot, stateRootEnv ?? ".agent-local/eunoma-v2", ...segments);
}

export function isHex64(s) {
  return typeof s === "string" && HEX64.test(s);
}

export function isTxHash(s) {
  return typeof s === "string" && TX_HASH_RE.test(s);
}

export function strip0x(s) {
  return typeof s === "string" && s.startsWith("0x") ? s.slice(2) : s;
}

export function add0x(s) {
  if (typeof s !== "string") return s;
  return s.startsWith("0x") ? s : `0x${s}`;
}

export function eqHexLoose(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  return strip0x(a).toLowerCase() === strip0x(b).toLowerCase();
}

// Aptos addresses are 32-byte values. Short forms (`0xabcd`) are equivalent to the
// 64-hex-char left-zero-padded canonical form (`0x000...0abcd`). REST responses always
// emit the canonical form; env values from operators often use short forms. Normalize
// both sides before comparison.
export function normalizeAptosAddress(s) {
  if (typeof s !== "string") return s;
  const stripped = strip0x(s).toLowerCase();
  if (stripped.length > 64) return `0x${stripped}`; // already long; return as-is + prefix
  return `0x${stripped.padStart(64, "0")}`;
}

export function eqAptosAddress(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  return normalizeAptosAddress(a) === normalizeAptosAddress(b);
}

// Safe BigInt — never throws. Returns null on malformed input.
export function safeBigInt(s) {
  if (s === null || s === undefined) return null;
  const str = String(s).trim();
  if (!/^[0-9]+$/.test(str)) return null;
  try {
    return BigInt(str);
  } catch {
    return null;
  }
}

// =============================================================================================
// validateRequiredEnv — pure helper that checks every required env var (and format-validates
// the ones with a strict format). Used by testnet_e2e_v2.mjs at the very top, BEFORE any chain
// query. Returns { ok: true } | { ok: false, missing: Array<{key, message, priority}> }.
//
// Format-validated:
//   - EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH must be 32-byte hex (0x optional).
//
// All other required vars are checked for non-empty string presence only.
// =============================================================================================

export function validateRequiredEnv(env) {
  const missing = [];

  function req(key, message) {
    const v = env[key];
    if (typeof v !== "string" || v.length === 0) {
      missing.push({ key, message, priority: "m6c-env" });
    }
  }

  function reqHex64(key, message) {
    const v = env[key];
    if (typeof v !== "string" || v.length === 0) {
      missing.push({ key, message, priority: "m6c-env" });
      return;
    }
    if (!isHex64(v)) {
      missing.push({
        key: `${key}_malformed`,
        message: `${key} must be 32-byte hex (0x prefix optional); got "${v.slice(0, 32)}${v.length > 32 ? "..." : ""}".`,
        priority: "m6c-env",
      });
    }
  }

  req(
    "APTOS_TESTNET_NODE_URL",
    "Aptos testnet fullnode REST endpoint (e.g. https://fullnode.testnet.aptoslabs.com).",
  );
  req(
    "BRIDGE_PACKAGE_ADDRESS",
    "0x-prefixed address of the published Eunoma bridge package on Aptos testnet.",
  );
  req(
    "RELAYER_SUBMIT_ENABLED",
    "Must be set to '1' to enable the relayer's chain-submit path.",
  );
  req(
    "ADMIN_PROFILE",
    "Name of an `aptos` CLI profile with admin rights for the bridge package.",
  );
  req(
    "RELAYER_BEARER_TOKEN",
    "Bearer auth token the coordinator uses to authenticate to the relayer.",
  );
  req(
    "EUNOMA_TESTNET_REQUEST_ID",
    "Unique requestId for this withdraw flow (ISafeId).",
  );
  req(
    "EUNOMA_TESTNET_DKG_EPOCH",
    "dkgEpoch (decimal string) this withdraw binds to.",
  );
  req(
    "EUNOMA_TESTNET_VAULT_ADDRESS",
    "0x-prefixed vault address (DO NOT fall back to BRIDGE_PACKAGE_ADDRESS on real testnet; vaults are resource accounts).",
  );
  req(
    "EUNOMA_TESTNET_ASSET_TYPE",
    "0x-prefixed Aptos Object<Metadata> address for the deposit asset.",
  );
  req(
    "EUNOMA_TESTNET_CHAIN_ID",
    "u8 chain id (2 for Aptos testnet); used by the M3 deposit observer payload.",
  );
  req(
    "EUNOMA_TESTNET_SENDER_ADDRESS",
    "0x-prefixed depositor address (used by the M3 deposit observer payload).",
  );
  req(
    "EUNOMA_TESTNET_DEPOSIT_TX_HASH",
    "0x-prefixed real chain-confirmed deposit tx hash. Submit via `aptos move run ...::deposit_with_commitment_v2 ...` first (see M6_OPERATOR_RUNBOOK.md Step 5).",
  );
  req(
    "EUNOMA_TESTNET_DEPOSIT_COUNT",
    "Chain-authoritative deposit_count (decimal string) from the DepositConfirmedV2 event.",
  );
  req(
    "EUNOMA_TESTNET_VAULT_EK",
    "0x-prefixed compressed-Ristretto vault EK (32 bytes hex) derived from CA DKG V2.",
  );
  reqHex64(
    "EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH",
    "Fr-safe ca_payload_hash (32-byte hex) you passed to deposit_with_commitment_v2. " +
      "Pre-compute via `caPayloadHashFrV2(payload)` from @eunoma/deop-protocol — it must equal " +
      "the value the chain emits in DepositConfirmedV2.",
  );

  return missing.length === 0 ? { ok: true } : { ok: false, missing };
}

// =============================================================================================
// compareObservedDepositArtifact — pure helper that cross-checks a coordinator-side
// vault_state_v2_observed/<dkgEpoch>__<depositCount>__<requestId>.json artifact against the
// chain DepositConfirmedV2 event and the operator env.
//
// NOTE: the artifact does NOT carry `vault_addr`. vault_addr ↔ env binding is enforced
// separately at the chain-event check inside runPreflight. The artifact's role is to bind
// the per-deposit event identity (caPayloadHash, txVersion, sequenceNumber, eventGuid) and
// the vault EK + chain context fields.
//
// Returns { ok: true } | { ok: false, mismatches: Array<{ key, message }> }.
// =============================================================================================

export function compareObservedDepositArtifact(artifact, chainEvent, env) {
  const mismatches = [];

  if (!artifact || typeof artifact !== "object") {
    mismatches.push({
      key: "vault_state_v2_observed_artifact_invalid",
      message: "Artifact is not an object",
    });
    return { ok: false, mismatches };
  }

  if (artifact.scheme !== "vault_state_v2_observe_deposit") {
    mismatches.push({
      key: "vault_state_v2_observed_scheme_invalid",
      message: `artifact.scheme=${JSON.stringify(artifact.scheme)} != "vault_state_v2_observe_deposit"`,
    });
  }

  // env-bound fields
  if (env.EUNOMA_TESTNET_DKG_EPOCH && String(artifact.dkgEpoch) !== String(env.EUNOMA_TESTNET_DKG_EPOCH)) {
    mismatches.push({
      key: "vault_state_v2_observed_epoch_mismatch",
      message: `artifact.dkgEpoch=${artifact.dkgEpoch} != env=${env.EUNOMA_TESTNET_DKG_EPOCH}`,
    });
  }
  if (env.EUNOMA_TESTNET_DEPOSIT_COUNT) {
    const wantCount = safeBigInt(env.EUNOMA_TESTNET_DEPOSIT_COUNT);
    const haveCount = safeBigInt(artifact.depositCount);
    if (wantCount === null || haveCount === null || wantCount !== haveCount) {
      mismatches.push({
        key: "vault_state_v2_observed_count_mismatch",
        message: `artifact.depositCount=${artifact.depositCount} != env=${env.EUNOMA_TESTNET_DEPOSIT_COUNT}`,
      });
    }
  }
  // The observed-deposit artifact's senderAddress is the CA-side SENDER of the vault
  // operation — i.e. the bridge vault resource address (the entity whose CA dk is
  // threshold-shared and that *signs* the on-chain confidential_transfer_raw). It is
  // NOT the depositor who submitted deposit_with_commitment_v2 (that's a separate
  // identity captured in DepositConfirmedV2.sender + EUNOMA_TESTNET_SENDER_ADDRESS).
  // Cross-check against EUNOMA_TESTNET_VAULT_ADDRESS, the canonical bridge vault address.
  if (
    env.EUNOMA_TESTNET_VAULT_ADDRESS &&
    !eqAptosAddress(artifact.senderAddress ?? "", env.EUNOMA_TESTNET_VAULT_ADDRESS)
  ) {
    mismatches.push({
      key: "vault_state_v2_observed_sender_mismatch",
      message: `artifact.senderAddress=${artifact.senderAddress} != EUNOMA_TESTNET_VAULT_ADDRESS=${env.EUNOMA_TESTNET_VAULT_ADDRESS} (vault is the CA-side sender of all vault-managed transfers; depositor identity lives in DepositConfirmedV2.sender)`,
    });
  }
  if (env.EUNOMA_TESTNET_ASSET_TYPE && !eqAptosAddress(artifact.assetType ?? "", env.EUNOMA_TESTNET_ASSET_TYPE)) {
    mismatches.push({
      key: "vault_state_v2_observed_asset_mismatch",
      message: `artifact.assetType=${artifact.assetType} != env=${env.EUNOMA_TESTNET_ASSET_TYPE}`,
    });
  }
  if (env.EUNOMA_TESTNET_CHAIN_ID) {
    const want = Number(env.EUNOMA_TESTNET_CHAIN_ID);
    if (!Number.isFinite(want) || Number(artifact.chainId) !== want) {
      mismatches.push({
        key: "vault_state_v2_observed_chain_mismatch",
        message: `artifact.chainId=${artifact.chainId} != env=${env.EUNOMA_TESTNET_CHAIN_ID}`,
      });
    }
  }
  if (env.EUNOMA_TESTNET_VAULT_EK && !eqHexLoose(artifact.vaultEk ?? "", env.EUNOMA_TESTNET_VAULT_EK)) {
    mismatches.push({
      key: "vault_state_v2_observed_vaultek_mismatch",
      message: `artifact.vaultEk differs from env.EUNOMA_TESTNET_VAULT_EK`,
    });
  }

  // chain-event-bound fields
  if (chainEvent && chainEvent.data) {
    const chainCaPayloadHash = chainEvent.data.ca_payload_hash;
    if (chainCaPayloadHash && !eqHexLoose(artifact.caPayloadHash ?? "", chainCaPayloadHash)) {
      mismatches.push({
        key: "vault_state_v2_observed_ca_payload_hash_mismatch",
        message: `artifact.caPayloadHash=${artifact.caPayloadHash} != chain.ca_payload_hash=${chainCaPayloadHash}`,
      });
    }
    const chainSeq = chainEvent.sequence_number;
    if (chainSeq !== undefined && chainSeq !== null && String(artifact.sequenceNumber) !== String(chainSeq)) {
      mismatches.push({
        key: "vault_state_v2_observed_sequence_number_mismatch",
        message: `artifact.sequenceNumber=${artifact.sequenceNumber} != chain.sequence_number=${chainSeq}`,
      });
    }
    const chainTxVersion = chainEvent.version;
    if (chainTxVersion !== undefined && chainTxVersion !== null && String(artifact.txVersion) !== String(chainTxVersion)) {
      mismatches.push({
        key: "vault_state_v2_observed_tx_version_mismatch",
        message: `artifact.txVersion=${artifact.txVersion} != chain.version=${chainTxVersion}`,
      });
    }
  }

  // structural fields
  if (typeof artifact.eventGuid !== "string" || artifact.eventGuid.length === 0) {
    mismatches.push({
      key: "vault_state_v2_observed_event_guid_missing",
      message: `artifact.eventGuid is missing or empty`,
    });
  }
  if (!Array.isArray(artifact.perSlotContributions) || artifact.perSlotContributions.length !== 5) {
    mismatches.push({
      key: "vault_state_v2_observed_per_slot_count_mismatch",
      message: `artifact.perSlotContributions.length=${artifact.perSlotContributions?.length} != 5`,
    });
  } else if (Array.isArray(artifact.selectedSlots)) {
    const slotSet = new Set(artifact.selectedSlots);
    for (const contrib of artifact.perSlotContributions) {
      if (contrib && typeof contrib.slot === "number" && !slotSet.has(contrib.slot)) {
        mismatches.push({
          key: "vault_state_v2_observed_per_slot_count_mismatch",
          message: `perSlotContributions includes slot=${contrib.slot} not in selectedSlots=[${[...slotSet].join(",")}]`,
        });
        break;
      }
    }
  }

  return mismatches.length === 0 ? { ok: true } : { ok: false, mismatches };
}

// =============================================================================================
// selectObservedDepositArtifact — pick the canonical artifact from a list of candidates
// matching the `<dkgEpoch>__<depositCount>__*.json` filename pattern. Refuses to pick
// silently when multiple candidates fully match (caller must resolve via requestId).
//
// Returns one of:
//   { ok: true, selected: { path, artifact } }
//   { ok: false, reason: "ambiguous", matchedPaths: string[] }
//   { ok: false, reason: "no_match", allMismatches: Array<{ path, mismatches }> }
//   { ok: false, reason: "no_candidates" }
// =============================================================================================

export function selectObservedDepositArtifact(candidates, chainEvent, env, requestId) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    return { ok: false, reason: "no_candidates" };
  }

  const matches = [];
  const allMismatches = [];

  for (const candidate of candidates) {
    const cmp = compareObservedDepositArtifact(candidate.artifact, chainEvent, env);
    if (cmp.ok) {
      matches.push(candidate);
    } else {
      allMismatches.push({ path: candidate.path, mismatches: cmp.mismatches });
    }
  }

  if (matches.length === 0) {
    return { ok: false, reason: "no_match", allMismatches };
  }
  if (matches.length === 1) {
    return { ok: true, selected: matches[0] };
  }

  // Multiple full matches — try to disambiguate by requestId in the filename.
  if (typeof requestId === "string" && requestId.length > 0) {
    const byRequestId = matches.filter((m) => m.path.includes(requestId));
    if (byRequestId.length === 1) {
      return { ok: true, selected: byRequestId[0] };
    }
  }

  return {
    ok: false,
    reason: "ambiguous",
    matchedPaths: matches.map((m) => m.path),
  };
}

// =============================================================================================
// runPreflight — the binding gate's structural validator
//
// Returns { ok: true, snapshot } | { ok: false, missing: Array<{key, message, remediation, priority}> }
//
// priorities (in exit-code precedence order):
//   "m6b"             — withdraw prover missing (exit 40)
//   "m6d-cli"         — Aptos CLI / profile / account-funding missing (exit 41)
//   "m6d-chain"       — bridge / module / VK / vault / config not on chain (exit 41)
//   "m6d-artifact"    — local artifact required to proceed is missing (exit 41)
//   "m6c-env"         — per-run env var missing or malformed (exit 2)
// =============================================================================================

export async function runPreflight(opts) {
  const { env, serviceRoot, stateRoot } = opts;
  const missing = [];
  const snapshot = {};

  const nodeUrl = env.APTOS_TESTNET_NODE_URL;
  const bridgeAddress = env.BRIDGE_PACKAGE_ADDRESS ? add0x(env.BRIDGE_PACKAGE_ADDRESS) : null;
  const vaultAddress = env.EUNOMA_TESTNET_VAULT_ADDRESS
    ? add0x(env.EUNOMA_TESTNET_VAULT_ADDRESS)
    : null;
  const assetType = env.EUNOMA_TESTNET_ASSET_TYPE ? add0x(env.EUNOMA_TESTNET_ASSET_TYPE) : null;
  const dkgEpoch = env.EUNOMA_TESTNET_DKG_EPOCH;
  const adminProfile = env.ADMIN_PROFILE;

  // ----- 1. aptos CLI -----
  const cli = checkAptosCli();
  if (!cli.ok) {
    missing.push({
      key: "aptos_cli",
      message: cli.message ?? "aptos CLI not on PATH",
      remediation:
        "Install the Aptos CLI: https://aptos.dev/cli-tools/aptos-cli — required for vault init, " +
        "deposit submission, and relayer CLI submitter.",
      priority: "m6d-cli",
    });
  } else {
    snapshot.aptosCliVersion = cli.version;
  }

  // ----- 2. ADMIN_PROFILE present in aptos config show-profiles -----
  if (adminProfile) {
    const profs = listProfiles();
    if (!profs.ok || !profs.profiles.includes(adminProfile)) {
      missing.push({
        key: "admin_profile",
        message: `aptos config show-profiles does not include '${adminProfile}'`,
        remediation: `aptos init --profile ${adminProfile} --network testnet (then fund the address from https://aptos.dev/network/faucet)`,
        priority: "m6d-cli",
      });
    }
  }

  // ----- 3. ADMIN_PROFILE account exists + funded -----
  // We can only check the account if we know its address. Resolve from `aptos account list`
  // for the profile, or fall back to the BRIDGE_PACKAGE_ADDRESS (which is the admin address in
  // the canonical setup).
  if (nodeUrl && adminProfile) {
    const adminAddr = resolveProfileAddress(adminProfile) ?? bridgeAddress;
    if (adminAddr) {
      const acctRes = await getAccount(nodeUrl, adminAddr);
      if (!acctRes.ok) {
        missing.push({
          key: "admin_account_funded",
          message: `Aptos /v1/accounts/${adminAddr} -> ${acctRes.status}: account not visible on testnet`,
          remediation: `aptos account fund-with-faucet --account ${adminProfile} --amount 100000000`,
          priority: "m6d-cli",
        });
      } else {
        snapshot.adminAddress = adminAddr;
        const coinRes = await getResource(
          nodeUrl,
          adminAddr,
          "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
        );
        if (coinRes.ok && coinRes.body?.data?.coin?.value !== undefined) {
          const balance = safeBigInt(coinRes.body.data.coin.value);
          if (balance === null) {
            missing.push({
              key: "admin_balance_unparseable",
              message: `${adminAddr} CoinStore.coin.value is not a non-negative integer (got ${coinRes.body.data.coin.value})`,
              remediation:
                "Aptos returned an unexpected CoinStore shape. Investigate the admin account manually.",
              priority: "m6d-cli",
            });
          } else {
            snapshot.adminBalanceOctas = balance.toString();
            if (balance < 10_000_000n) {
              missing.push({
                key: "admin_account_funded",
                message: `${adminAddr} balance ${balance} octas < 0.1 APT (10_000_000)`,
                remediation: `aptos account fund-with-faucet --account ${adminProfile} --amount 100000000`,
                priority: "m6d-cli",
              });
            }
          }
        }
      }
    }
  }

  // ----- 4. Bridge package published -----
  if (nodeUrl && bridgeAddress) {
    const modulesRes = await getModules(nodeUrl, bridgeAddress);
    if (!modulesRes.ok) {
      missing.push({
        key: "bridge_modules",
        message: `Aptos /v1/accounts/${bridgeAddress}/modules -> ${modulesRes.status}`,
        remediation:
          "Publish the bridge: `aptos move publish --package-dir move --profile $ADMIN_PROFILE` (see M6_OPERATOR_RUNBOOK.md Step 2).",
        priority: "m6d-chain",
      });
    } else {
      const mods = Array.isArray(modulesRes.body) ? modulesRes.body : [];
      const hasBridge = mods.some(
        (m) => m && m.abi && typeof m.abi.name === "string" && m.abi.name === "eunoma_bridge",
      );
      if (!hasBridge) {
        missing.push({
          key: "bridge_modules",
          message: `module 'eunoma_bridge' not published at ${bridgeAddress}`,
          remediation:
            "Publish the bridge: `aptos move publish --package-dir move --profile $ADMIN_PROFILE`.",
          priority: "m6d-chain",
        });
      }
    }
  }

  // ----- 5. PreparedWithdrawProofVK resource present -----
  if (nodeUrl && bridgeAddress) {
    const vkType = `${bridgeAddress}::eunoma_bridge::PreparedWithdrawProofVK`;
    const vkRes = await getResource(nodeUrl, bridgeAddress, vkType);
    if (!vkRes.ok) {
      missing.push({
        key: "prepared_withdraw_proof_vk",
        message: `${vkType} resource not present at ${bridgeAddress} (status=${vkRes.status})`,
        remediation:
          "Publish the prepared withdraw VK via aptos move run ...::publish_prepared_withdraw_proof_vk_v2 (see M6_OPERATOR_RUNBOOK.md Step 3).",
        priority: "m6d-chain",
      });
    }
  }

  // ----- 6. Vault init tx -----
  // Resolve from env, else from the persisted vault-init artifact at
  // <stateRoot>/coordinator/testnet_vault_init/<dkgEpoch>__init.json.
  let vaultInitTxHash = env.EUNOMA_TESTNET_VAULT_INIT_TX_HASH;
  if ((!vaultInitTxHash || !isTxHash(vaultInitTxHash)) && dkgEpoch && serviceRoot) {
    const path = stateRootJoin(
      serviceRoot,
      stateRoot,
      "coordinator",
      "testnet_vault_init",
      `${dkgEpoch}__init.json`,
    );
    const artifact = readJsonIfExists(path);
    if (artifact && typeof artifact.txHash === "string") {
      vaultInitTxHash = artifact.txHash;
      snapshot.vaultInitArtifactPath = path;
    }
  }
  if (!vaultInitTxHash || !isTxHash(vaultInitTxHash)) {
    missing.push({
      key: "vault_init_tx_hash",
      message:
        "EUNOMA_TESTNET_VAULT_INIT_TX_HASH is not set and no persisted artifact at " +
        "<stateRoot>/coordinator/testnet_vault_init/<dkgEpoch>__init.json carries a tx hash",
      remediation:
        "Run `npm run testnet:vault:init -- --submit --ca-registration-artifact ... --snapshot ... --roster ... --frost-roster ...` (see M6_OPERATOR_RUNBOOK.md Step 4) and capture the tx hash.",
      priority: "m6d-artifact",
    });
  } else if (nodeUrl) {
    const txRes = await getTransactionByHash(nodeUrl, vaultInitTxHash);
    if (!txRes.ok) {
      missing.push({
        key: "vault_init_tx_hash",
        message: `Aptos /v1/transactions/by_hash/${vaultInitTxHash} -> ${txRes.status}: ${txRes.text?.slice(0, 120) ?? ""}`,
        remediation:
          "Re-submit the vault init tx and supply the resulting tx hash via EUNOMA_TESTNET_VAULT_INIT_TX_HASH.",
        priority: "m6d-chain",
      });
    } else if (txRes.body?.success !== true || txRes.body?.vm_status !== "Executed successfully") {
      missing.push({
        key: "vault_init_tx_hash",
        message: `Vault init tx ${vaultInitTxHash} on chain but success=${txRes.body?.success}, vm_status=${txRes.body?.vm_status}`,
        remediation: "Investigate the vault init failure and re-submit before retrying.",
        priority: "m6d-chain",
      });
    } else {
      snapshot.vaultInitTx = {
        hash: vaultInitTxHash,
        version: txRes.body.version ?? null,
      };
    }
  }

  // ----- 7. BridgeVault resource lives under BRIDGE_PACKAGE_ADDRESS -----
  // goal.md fix: previous revision queried at EUNOMA_TESTNET_VAULT_ADDRESS (a resource
  // account that only carries 0x1::account::Account). The bridge keeps BridgeVault under
  // its package address (@eunoma); the vault address is a *value* inside that resource.
  // We now query at bridgeAddress and cross-check BridgeVault.vault_addr === vaultAddress.
  if (nodeUrl && bridgeAddress) {
    const vaultType = `${bridgeAddress}::eunoma_bridge::BridgeVault`;
    const vaultRes = await getResource(nodeUrl, bridgeAddress, vaultType);
    if (!vaultRes.ok) {
      missing.push({
        key: "bridge_vault_resource",
        message: `${vaultType} not present at ${bridgeAddress} (status=${vaultRes.status})`,
        remediation:
          "Run `npm run testnet:vault:init -- --submit ...` to publish the BridgeVault resource under the bridge package address.",
        priority: "m6d-chain",
      });
    } else {
      snapshot.bridgeVault = vaultRes.body?.data ?? null;
      // Aptos returns these address-shaped fields either as plain hex or as { inner: hex }.
      const vaultAssetType =
        typeof vaultRes.body?.data?.asset_type === "string"
          ? vaultRes.body.data.asset_type
          : vaultRes.body?.data?.asset_type?.inner ?? null;
      const vaultAddrOnChain =
        typeof vaultRes.body?.data?.vault_addr === "string"
          ? vaultRes.body.data.vault_addr
          : vaultRes.body?.data?.vault_addr?.inner ?? null;

      // Cross-check vault_addr inside the on-chain resource against env.
      if (vaultAddress) {
        if (vaultAddrOnChain && !eqAptosAddress(vaultAddrOnChain, vaultAddress)) {
          missing.push({
            key: "bridge_vault_addr_mismatch",
            message: `BridgeVault.vault_addr=${vaultAddrOnChain} != EUNOMA_TESTNET_VAULT_ADDRESS=${vaultAddress}`,
            remediation:
              "Set EUNOMA_TESTNET_VAULT_ADDRESS to BridgeVault.vault_addr emitted by VaultInitializedV2.",
            priority: "m6c-env",
          });
        } else if (!vaultAddrOnChain) {
          missing.push({
            key: "bridge_vault_addr_unparseable",
            message: `BridgeVault.vault_addr shape unrecognized (data=${JSON.stringify(vaultRes.body?.data?.vault_addr)})`,
            remediation: "Aptos returned an unexpected BridgeVault.vault_addr shape.",
            priority: "m6d-chain",
          });
        }
      }

      // Asset-type cross-check (defense-in-depth — observer also re-checks).
      if (assetType && vaultAssetType && !eqAptosAddress(vaultAssetType, assetType)) {
        missing.push({
          key: "vault_asset_type_mismatch",
          message: `BridgeVault.asset_type=${vaultAssetType} != EUNOMA_TESTNET_ASSET_TYPE=${assetType}`,
          remediation:
            "Fix EUNOMA_TESTNET_ASSET_TYPE to match the vault's actual asset_type, OR initialize the correct vault.",
          priority: "m6c-env",
        });
      } else if (assetType && !vaultAssetType) {
        missing.push({
          key: "vault_asset_type_unparseable",
          message: `BridgeVault.asset_type shape unrecognized (data=${JSON.stringify(vaultRes.body?.data?.asset_type)})`,
          remediation: "Aptos returned an unexpected BridgeVault.asset_type shape.",
          priority: "m6d-chain",
        });
      }
    }
  }

  // ----- 8. DeoperatorConfigV2 resource also lives under BRIDGE_PACKAGE_ADDRESS -----
  if (nodeUrl && bridgeAddress) {
    const cfgType = `${bridgeAddress}::eunoma_bridge::DeoperatorConfigV2`;
    const cfgRes = await getResource(nodeUrl, bridgeAddress, cfgType);
    if (!cfgRes.ok) {
      missing.push({
        key: "deoperator_config_v2",
        message: `${cfgType} not present at ${bridgeAddress} (status=${cfgRes.status})`,
        remediation:
          "Run `npm run testnet:vault:init -- --submit ...` — DeoperatorConfigV2 is published as part of vault init under the bridge package address.",
        priority: "m6d-chain",
      });
    } else {
      snapshot.deoperatorConfig = cfgRes.body?.data ?? null;
      if (dkgEpoch && snapshot.deoperatorConfig?.dkg_epoch !== undefined) {
        const onChain = String(snapshot.deoperatorConfig.dkg_epoch);
        if (onChain !== dkgEpoch) {
          missing.push({
            key: "dkg_epoch_mismatch",
            message: `DeoperatorConfigV2.dkg_epoch=${onChain} != EUNOMA_TESTNET_DKG_EPOCH=${dkgEpoch}`,
            remediation:
              "Use the dkg_epoch that's actually on chain, OR rotate the config to the desired epoch.",
            priority: "m6c-env",
          });
        }
      }
      if (snapshot.deoperatorConfig?.threshold !== undefined) {
        const threshold = Number(snapshot.deoperatorConfig.threshold);
        if (threshold !== 5) {
          missing.push({
            key: "threshold_violation",
            message: `DeoperatorConfigV2.threshold=${threshold} != 5 (strict 5-of-7 invariant)`,
            remediation:
              "This violates a goal.md hard invariant. Investigate the on-chain config before proceeding.",
            priority: "m6d-chain",
          });
        }
      }
    }
  }

  // ----- 9. Deposit tx -----
  const depositTxHash = env.EUNOMA_TESTNET_DEPOSIT_TX_HASH;
  if (!depositTxHash || !isTxHash(depositTxHash)) {
    missing.push({
      key: "deposit_tx_hash",
      message: "EUNOMA_TESTNET_DEPOSIT_TX_HASH is required (a real, chain-confirmed deposit tx)",
      remediation:
        "Submit a deposit via `aptos move run --function-id $BRIDGE::eunoma_bridge::deposit_with_commitment_v2 --args ...` (see M6_OPERATOR_RUNBOOK.md Step 5) and capture the tx hash.",
      priority: "m6c-env",
    });
  } else if (nodeUrl) {
    const dtxRes = await getTransactionByHash(nodeUrl, depositTxHash);
    if (!dtxRes.ok) {
      missing.push({
        key: "deposit_tx_hash",
        message: `Aptos /v1/transactions/by_hash/${depositTxHash} -> ${dtxRes.status}`,
        remediation:
          "Re-submit the deposit and supply the new tx hash via EUNOMA_TESTNET_DEPOSIT_TX_HASH.",
        priority: "m6d-chain",
      });
    } else if (dtxRes.body?.success !== true || dtxRes.body?.vm_status !== "Executed successfully") {
      missing.push({
        key: "deposit_tx_hash",
        message: `Deposit tx ${depositTxHash}: success=${dtxRes.body?.success} vm_status=${dtxRes.body?.vm_status}`,
        remediation: "Investigate the deposit failure and re-submit before retrying.",
        priority: "m6d-chain",
      });
    } else {
      // ----- 10. DepositConfirmedV2 event present -----
      // Match by event-type suffix so short-form bridge addresses (`0xabcd`) still match
      // chain-canonical padded forms (`0x000...0abcd::eunoma_bridge::DepositConfirmedV2`).
      const events = Array.isArray(dtxRes.body?.events) ? dtxRes.body.events : [];
      const ev = events.find(
        (e) => typeof e?.type === "string" && e.type.endsWith("::eunoma_bridge::DepositConfirmedV2"),
      );
      if (!ev) {
        missing.push({
          key: "deposit_confirmed_v2_event",
          message: `Deposit tx ${depositTxHash} has no event of type ...::eunoma_bridge::DepositConfirmedV2`,
          remediation:
            "Confirm the deposit was made via deposit_with_commitment_v2 (NOT a legacy deposit entry). Re-submit if necessary.",
          priority: "m6d-chain",
        });
      } else {
        // Bind-check fields. asset_type may be a struct { inner: hex } or a hex string
        // depending on the fullnode version.
        const evAssetType =
          typeof ev.data?.asset_type === "string"
            ? ev.data.asset_type
            : ev.data?.asset_type?.inner ?? null;
        const evVaultAddr =
          typeof ev.data?.vault_addr === "string"
            ? ev.data.vault_addr
            : ev.data?.vault_addr?.inner ?? null;
        const evDepositCount = ev.data?.deposit_count;

        // Also cross-check the event type's bridge prefix matches our env.
        if (bridgeAddress) {
          const evBridgePrefix = ev.type.split("::")[0];
          if (evBridgePrefix && !eqAptosAddress(evBridgePrefix, bridgeAddress)) {
            missing.push({
              key: "deposit_event_bridge_mismatch",
              message: `DepositConfirmedV2 emitted by ${evBridgePrefix} != BRIDGE_PACKAGE_ADDRESS=${bridgeAddress}`,
              remediation: "Use the BRIDGE_PACKAGE_ADDRESS that emitted this event.",
              priority: "m6c-env",
            });
          }
        }
        if (assetType && evAssetType && !eqAptosAddress(evAssetType, assetType)) {
          missing.push({
            key: "deposit_event_asset_mismatch",
            message: `DepositConfirmedV2.asset_type=${evAssetType} != EUNOMA_TESTNET_ASSET_TYPE=${assetType}`,
            remediation: "Use the asset_type that the deposit actually targeted.",
            priority: "m6c-env",
          });
        } else if (assetType && !evAssetType) {
          missing.push({
            key: "deposit_event_asset_unparseable",
            message: `DepositConfirmedV2.asset_type field shape unrecognized (data=${JSON.stringify(ev.data?.asset_type)})`,
            remediation:
              "Aptos returned an unexpected asset_type shape. Inspect the deposit tx event payload manually.",
            priority: "m6d-chain",
          });
        }
        if (vaultAddress && evVaultAddr && !eqAptosAddress(evVaultAddr, vaultAddress)) {
          missing.push({
            key: "deposit_event_vault_mismatch",
            message: `DepositConfirmedV2.vault_addr=${evVaultAddr} != EUNOMA_TESTNET_VAULT_ADDRESS=${vaultAddress}`,
            remediation: "Use the vault_addr that the deposit actually targeted.",
            priority: "m6c-env",
          });
        }
        // deposit_count cross-check (BigInt-safe).
        const evCountBI = safeBigInt(evDepositCount);
        const envCountBI = safeBigInt(env.EUNOMA_TESTNET_DEPOSIT_COUNT);
        if (env.EUNOMA_TESTNET_DEPOSIT_COUNT) {
          if (evCountBI === null) {
            missing.push({
              key: "deposit_event_count_unparseable",
              message: `DepositConfirmedV2.deposit_count is not a non-negative integer (got ${evDepositCount})`,
              remediation:
                "Aptos returned an unexpected deposit_count shape. Inspect the deposit tx event payload manually.",
              priority: "m6d-chain",
            });
          } else if (envCountBI === null) {
            missing.push({
              key: "deposit_count_env",
              message: `EUNOMA_TESTNET_DEPOSIT_COUNT=${env.EUNOMA_TESTNET_DEPOSIT_COUNT} is not a non-negative decimal string`,
              remediation: `Set EUNOMA_TESTNET_DEPOSIT_COUNT=${evDepositCount} from the on-chain DepositConfirmedV2 event.`,
              priority: "m6c-env",
            });
          } else if (evCountBI !== envCountBI) {
            missing.push({
              key: "deposit_event_count_mismatch",
              message: `DepositConfirmedV2.deposit_count=${evCountBI} != EUNOMA_TESTNET_DEPOSIT_COUNT=${envCountBI}`,
              remediation:
                "Use the chain-authoritative deposit_count from the DepositConfirmedV2 event.",
              priority: "m6c-env",
            });
          }
        } else {
          missing.push({
            key: "deposit_count_env",
            message: "EUNOMA_TESTNET_DEPOSIT_COUNT is required (chain-authoritative deposit_count)",
            remediation: `Set EUNOMA_TESTNET_DEPOSIT_COUNT=${evDepositCount} from the on-chain DepositConfirmedV2 event.`,
            priority: "m6c-env",
          });
        }
        // Cross-check the deposit tx's `sender` matches EUNOMA_TESTNET_SENDER_ADDRESS.
        if (
          env.EUNOMA_TESTNET_SENDER_ADDRESS &&
          dtxRes.body?.sender &&
          !eqAptosAddress(dtxRes.body.sender, env.EUNOMA_TESTNET_SENDER_ADDRESS)
        ) {
          missing.push({
            key: "deposit_tx_sender_mismatch",
            message: `Deposit tx sender=${dtxRes.body.sender} != EUNOMA_TESTNET_SENDER_ADDRESS=${env.EUNOMA_TESTNET_SENDER_ADDRESS}`,
            remediation:
              "Use the depositor address that actually signed the deposit tx. The observer payload depends on this.",
            priority: "m6c-env",
          });
        }
        // ----- ca_payload_hash: operator pre-commit ↔ chain-emitted -----
        // goal.md item 3 requires the deposit event proof to be "bound to bridge, vault, asset,
        // deposit_count, payload hash, and chain version". Without this binding, an attacker who
        // can replace the deposit with a different valid payload (same vault/asset/count) would
        // pass the gate. The operator pre-computes ca_payload_hash via caPayloadHashFrV2(payload)
        // BEFORE submitting deposit_with_commitment_v2 and supplies it via env so we can verify
        // the chain emitted the same value.
        if (env.EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH) {
          const evCaPayloadHash = ev.data?.ca_payload_hash;
          if (!eqHexLoose(evCaPayloadHash ?? "", env.EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH)) {
            missing.push({
              key: "deposit_ca_payload_hash_mismatch",
              message:
                `DepositConfirmedV2.ca_payload_hash (${evCaPayloadHash}) != ` +
                `EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH (${env.EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH}). ` +
                `The operator's pre-committed payload hash does not match what the chain emitted.`,
              remediation:
                "Re-derive ca_payload_hash via `caPayloadHashFrV2(payload)` against the exact " +
                "ConfidentialTransferRawPayloadV2 you submitted; re-set EUNOMA_TESTNET_DEPOSIT_CA_PAYLOAD_HASH.",
              priority: "m6d-chain",
            });
          }
        }
        snapshot.depositTx = {
          hash: depositTxHash,
          version: dtxRes.body.version ?? null,
        };
        snapshot.depositEvent = {
          type: ev.type,
          sequence_number: ev.sequence_number,
          version: dtxRes.body.version ?? null,
          data: ev.data,
        };
      }
    }
  }

  // ----- 11. MP-SPDZ runtime check -----
  // We avoid invoking mpc:check synchronously here (it can be slow). Instead surface a hint
  // that the operator should run it separately; mpc_spdz_check.mjs has its own exit codes.
  // If the bootstrap dir is missing entirely, that's a hard miss.
  if (serviceRoot) {
    const mpspdzDir = stateRootJoin(serviceRoot, stateRoot, "..", "mp-spdz");
    // Note: .agent-local/mp-spdz lives ABOVE .agent-local/eunoma-v2.
    const altMpspdzDir = resolve(serviceRoot, ".agent-local", "mp-spdz");
    if (!existsSync(mpspdzDir) && !existsSync(altMpspdzDir)) {
      missing.push({
        key: "mp_spdz_bootstrap",
        message: `MP-SPDZ runtime not bootstrapped (no .agent-local/mp-spdz directory)`,
        remediation: "Run `npm run mpc:bootstrap` then `npm run mpc:check` to verify.",
        priority: "m6d-cli",
      });
    }
  }

  // ----- 12. M6-b prover output -----
  // The orchestrator (testnet_e2e_v2.mjs) already validates EUNOMA_TESTNET_WITHDRAW_PROOF /
  // EUNOMA_TESTNET_WITHDRAW_WITNESS_JSON before invoking us, so we just sanity-check the
  // env value is present.
  if (
    !env.EUNOMA_TESTNET_WITHDRAW_PROOF ||
    !/^(0x)?[0-9a-fA-F]+$/.test(env.EUNOMA_TESTNET_WITHDRAW_PROOF)
  ) {
    missing.push({
      key: "withdraw_proof",
      message:
        "EUNOMA_TESTNET_WITHDRAW_PROOF (hex) is missing or malformed at the pre-flight stage — " +
        "if you supplied EUNOMA_TESTNET_WITHDRAW_WITNESS_JSON the orchestrator should have populated this earlier",
      remediation:
        "Set EUNOMA_TESTNET_WITHDRAW_PROOF (hex) directly, or supply a witness JSON via EUNOMA_TESTNET_WITHDRAW_WITNESS_JSON.",
      priority: "m6b",
    });
  }

  // ----- 13. Worker state — per-slot binding + cursor sync -----
  // Each worker slot persists a single `slot-{N}/vault_state_v2.json` that the M3 observer
  // updates in-place. The file binds the worker's state to the operator's intended
  // (bridge, vault, asset, sender, chain_id, dkg_epoch, vault_ek, roster_hash,
  // ca_dkg_transcript_hash) configuration AND records the chain-authoritative
  // deposit_count_observed.
  //
  // Goal.md item 4 requires fail-closed on: wrong hash, replay, stale sequence, wrong
  // bridge, wrong vault, wrong asset. We enforce this by reading every slot artifact and
  // confirming each field matches the operator's env + chain-snapshot.
  if (dkgEpoch && env.EUNOMA_TESTNET_DEPOSIT_COUNT && serviceRoot) {
    const wantCount = safeBigInt(env.EUNOMA_TESTNET_DEPOSIT_COUNT);
    if (wantCount === null) {
      missing.push({
        key: "deposit_count_env",
        message: `EUNOMA_TESTNET_DEPOSIT_COUNT=${env.EUNOMA_TESTNET_DEPOSIT_COUNT} is not a non-negative decimal string`,
        remediation: "Use the chain-authoritative deposit_count from DepositConfirmedV2 (a decimal integer).",
        priority: "m6c-env",
      });
    } else {
      const observedBySlot = {};
      const transcriptHashBySlot = {};
      const initTranscriptHashBySlot = {};
      // Threshold-aware: V2's CA DKG + vault_state_v2 init protocol is strict 5-of-7. Any
      // given init/observe run picks selectedSlots[5]; the other (7 - 5 = 2) slots never
      // receive vault_state_v2.json. The hardening must require AT LEAST THRESHOLD (5)
      // slots be present-and-consistent, NOT all 7 — over-strict gates would fail closed
      // on the actual deployed protocol.
      const DEOPERATOR_COUNT = 7;
      const DEOPERATOR_THRESHOLD = 5;
      const presentSlotsForBindChecks = [];
      const missingSlots = [];
      for (let slot = 0; slot < DEOPERATOR_COUNT; slot += 1) {
        const slotFile = resolve(
          serviceRoot,
          stateRoot ?? ".agent-local/eunoma-v2",
          `slot-${slot}`,
          "vault_state_v2.json",
        );
        const a = readJsonIfExists(slotFile);
        if (!a) {
          missingSlots.push({ slot, path: slotFile });
          observedBySlot[slot] = null;
          continue;
        }
        presentSlotsForBindChecks.push({ slot, artifact: a, path: slotFile });
      }
      if (presentSlotsForBindChecks.length < DEOPERATOR_THRESHOLD) {
        // Fail closed: under-quorum is a hard miss because no 5-of-7 op can run.
        for (const m of missingSlots) {
          missing.push({
            key: `worker_state_slot_${m.slot}_missing`,
            message: `slot-${m.slot}/vault_state_v2.json not found at ${m.path}; only ${presentSlotsForBindChecks.length}/${DEOPERATOR_COUNT} slots initialized (need ≥${DEOPERATOR_THRESHOLD} for 5-of-7 quorum)`,
            remediation:
              "Run the local cluster + `npm run local:vault-state:init` to materialize per-slot vault_state_v2 artifacts. The CA DKG V2 init protocol initializes 5 selected slots per call; re-running with different selectedSlots can cover the remaining ones if a future op needs ≥6 slots populated for audit.",
            priority: "m6d-artifact",
          });
        }
      }
      for (const { slot, artifact: a } of presentSlotsForBindChecks) {
        // ---- Bind-checks: every slot artifact must reference the same op intent. ----
        // dkg_epoch
        if (String(a.dkg_epoch) !== String(dkgEpoch)) {
          missing.push({
            key: `worker_state_slot_${slot}_dkg_epoch`,
            message: `slot-${slot} vault_state_v2.dkg_epoch=${a.dkg_epoch} != EUNOMA_TESTNET_DKG_EPOCH=${dkgEpoch}`,
            remediation:
              "The slot artifact was produced for a different dkg_epoch. Re-init the cluster for the current epoch, or use the matching dkg_epoch.",
            priority: "m6d-artifact",
          });
        }
        // sender_address — the worker's vault_state.sender_address is the CA SENDER of
        // the vault operation = the bridge vault resource address. NOT the depositor.
        // Compare against EUNOMA_TESTNET_VAULT_ADDRESS (the bridge vault), not
        // EUNOMA_TESTNET_SENDER_ADDRESS (the depositor address).
        if (
          env.EUNOMA_TESTNET_VAULT_ADDRESS &&
          !eqAptosAddress(a.sender_address ?? "", env.EUNOMA_TESTNET_VAULT_ADDRESS)
        ) {
          missing.push({
            key: `worker_state_slot_${slot}_sender_address`,
            message: `slot-${slot} vault_state_v2.sender_address=${a.sender_address} != EUNOMA_TESTNET_VAULT_ADDRESS=${env.EUNOMA_TESTNET_VAULT_ADDRESS} (vault is the CA-side sender; depositor identity lives elsewhere)`,
            remediation:
              "Re-run `npm run local:vault-state:init` keyed to the bridge vault address (the CA-side sender), not the depositor address.",
            priority: "m6d-artifact",
          });
        }
        // asset_type
        if (assetType && !eqAptosAddress(a.asset_type ?? "", assetType)) {
          missing.push({
            key: `worker_state_slot_${slot}_asset_type`,
            message: `slot-${slot} vault_state_v2.asset_type=${a.asset_type} != EUNOMA_TESTNET_ASSET_TYPE=${assetType}`,
            remediation:
              "Re-run `npm run local:vault-state:init` with the correct asset_type, or update EUNOMA_TESTNET_ASSET_TYPE.",
            priority: "m6d-artifact",
          });
        }
        // chain_id
        if (env.EUNOMA_TESTNET_CHAIN_ID) {
          const wantChainId = Number(env.EUNOMA_TESTNET_CHAIN_ID);
          if (Number(a.chain_id) !== wantChainId) {
            missing.push({
              key: `worker_state_slot_${slot}_chain_id`,
              message: `slot-${slot} vault_state_v2.chain_id=${a.chain_id} != EUNOMA_TESTNET_CHAIN_ID=${wantChainId}`,
              remediation:
                "Re-run `npm run local:vault-state:init` with the correct chain_id, or update EUNOMA_TESTNET_CHAIN_ID.",
              priority: "m6d-artifact",
            });
          }
        }
        // vault_ek
        if (
          env.EUNOMA_TESTNET_VAULT_EK &&
          a.vault_ek_hex &&
          !eqHexLoose(a.vault_ek_hex, env.EUNOMA_TESTNET_VAULT_EK)
        ) {
          missing.push({
            key: `worker_state_slot_${slot}_vault_ek`,
            message: `slot-${slot} vault_state_v2.vault_ek_hex differs from EUNOMA_TESTNET_VAULT_EK`,
            remediation:
              "The slot artifact's vault_ek does not match the operator's expected vault EK. Investigate before retrying.",
            priority: "m6d-artifact",
          });
        }
        // ca_dkg_transcript_hash — optional cross-check (env may not set it)
        if (
          env.EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH &&
          a.ca_dkg_transcript_hash &&
          !eqHexLoose(a.ca_dkg_transcript_hash, env.EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH)
        ) {
          missing.push({
            key: `worker_state_slot_${slot}_ca_dkg_transcript_hash`,
            message: `slot-${slot} vault_state_v2.ca_dkg_transcript_hash differs from env`,
            remediation:
              "The slot artifact's CA DKG V2 transcript hash does not match the operator's expected one. Investigate.",
            priority: "m6d-artifact",
          });
        }
        // ---- Cursor check ----
        const observed = safeBigInt(a.deposit_count_observed);
        observedBySlot[slot] = observed === null ? null : observed.toString();
        if (observed === null) {
          missing.push({
            key: `worker_state_slot_${slot}_cursor`,
            message: `slot-${slot} vault_state_v2.deposit_count_observed is not a non-negative integer (got ${a.deposit_count_observed})`,
            remediation:
              "Slot artifact is malformed; investigate before retrying.",
            priority: "m6d-artifact",
          });
        } else if (observed < wantCount) {
          missing.push({
            key: `worker_state_slot_${slot}_cursor`,
            message: `slot-${slot} vault_state_v2.deposit_count_observed=${observed} < EUNOMA_TESTNET_DEPOSIT_COUNT=${wantCount}`,
            remediation:
              "Run `npm run local:vault-state:observe-deposit -- --aptos-node-url $APTOS_TESTNET_NODE_URL --bridge-address $BRIDGE_PACKAGE_ADDRESS --dkg-epoch $EUNOMA_TESTNET_DKG_EPOCH --vault-ek $EUNOMA_TESTNET_VAULT_EK --sender-address $EUNOMA_TESTNET_SENDER_ADDRESS --asset-type $EUNOMA_TESTNET_ASSET_TYPE --chain-id $EUNOMA_TESTNET_CHAIN_ID --ca-dkg-transcript-hash $EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH` until every slot's cursor reaches the expected count.",
            priority: "m6d-artifact",
          });
        }
        transcriptHashBySlot[slot] = a.worker_transcript_hash ?? null;
        initTranscriptHashBySlot[slot] = a.init_transcript_hash ?? null;
      }
      snapshot.workerCursors = observedBySlot;
      snapshot.workerTranscriptHashes = transcriptHashBySlot;
      snapshot.workerInitTranscriptHashes = initTranscriptHashBySlot;
    }
  }

  // ----- 14. vault_state_v2_observed coordinator-side aggregate -----
  // Cursor parity (#13) is necessary but not sufficient: it doesn't prove workers observed THIS
  // exact deposit event. The coordinator persists per-deposit observation aggregates at
  // <stateRoot>/coordinator/vault_state_v2_observed/<dkgEpoch>__<depositCount>__<requestId>.json
  // carrying caPayloadHash, txVersion, sequenceNumber, eventGuid, vaultEk, senderAddress,
  // assetType, chainId, dkgEpoch, depositCount, plus a transcriptHash. We require an aggregate
  // that fully agrees with the chain event AND the env to exist.
  if (dkgEpoch && env.EUNOMA_TESTNET_DEPOSIT_COUNT && serviceRoot && snapshot.depositEvent) {
    const observedDir = stateRootJoin(
      serviceRoot,
      stateRoot,
      "coordinator",
      "vault_state_v2_observed",
    );
    const candidates = [];
    try {
      if (existsSync(observedDir)) {
        const entries = readdirSync(observedDir);
        const prefix = `${dkgEpoch}__${env.EUNOMA_TESTNET_DEPOSIT_COUNT}__`;
        for (const f of entries) {
          if (!f.startsWith(prefix) || !f.endsWith(".json")) continue;
          const abs = resolve(observedDir, f);
          const art = readJsonIfExists(abs);
          if (art !== null) candidates.push({ path: abs, artifact: art });
        }
      }
    } catch (_) {
      // fall through to no_candidates
    }

    const selection = selectObservedDepositArtifact(
      candidates,
      snapshot.depositEvent,
      env,
      env.EUNOMA_TESTNET_REQUEST_ID,
    );

    if (!selection.ok) {
      if (selection.reason === "no_candidates") {
        missing.push({
          key: "vault_state_v2_observed_artifact_missing",
          message:
            `No vault_state_v2_observed artifact at ${observedDir}/${dkgEpoch}__${env.EUNOMA_TESTNET_DEPOSIT_COUNT}__*.json. ` +
            `Workers may have advanced their cursor but the coordinator has not persisted the per-deposit observation transcript.`,
          remediation:
            "Run `npm run local:vault-state:observe-deposit -- --bridge-address $BRIDGE_PACKAGE_ADDRESS --aptos-node-url $APTOS_TESTNET_NODE_URL --dkg-epoch $EUNOMA_TESTNET_DKG_EPOCH --vault-ek $EUNOMA_TESTNET_VAULT_EK --sender-address $EUNOMA_TESTNET_SENDER_ADDRESS --asset-type $EUNOMA_TESTNET_ASSET_TYPE --chain-id $EUNOMA_TESTNET_CHAIN_ID --ca-dkg-transcript-hash $EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH` — this writes the coordinator-side aggregate.",
          priority: "m6d-artifact",
        });
      } else if (selection.reason === "ambiguous") {
        missing.push({
          key: "vault_state_v2_observed_ambiguous_candidates",
          message:
            `Multiple vault_state_v2_observed artifacts fully match chain event + env for dkgEpoch=${dkgEpoch}, depositCount=${env.EUNOMA_TESTNET_DEPOSIT_COUNT}: ${selection.matchedPaths.join(", ")}. ` +
            `The gate refuses to pick one silently.`,
          remediation:
            "Remove stale duplicate aggregate(s) so exactly one canonical artifact remains, OR set EUNOMA_TESTNET_REQUEST_ID to a value contained in the desired filename.",
          priority: "m6d-artifact",
        });
      } else if (selection.reason === "no_match") {
        for (const candidate of selection.allMismatches) {
          for (const m of candidate.mismatches) {
            missing.push({
              key: m.key,
              message: `${candidate.path}: ${m.message}`,
              remediation:
                "Re-run the deposit observer with the correct env values, OR investigate whether a prior observer run wrote a stale/incorrect aggregate. The coordinator should reject re-observation of the same depositCount if the workers' per-slot state disagrees.",
              priority: "m6d-artifact",
            });
          }
        }
      }
    } else {
      snapshot.observedDepositArtifactPath = selection.selected.path;
      snapshot.observedDepositTranscriptHash = selection.selected.artifact.transcriptHash ?? null;
    }
  }

  if (missing.length > 0) return { ok: false, missing };
  return { ok: true, snapshot };
}

function resolveProfileAddress(profileName) {
  // Search ancestors for .aptos/config.yaml (the operator-services dir may not contain one;
  // the repo root does).
  const configDir = findAptosConfigDir(process.cwd()) ?? process.cwd();
  const r = spawnSync("aptos", ["config", "show-profiles", "--profile", profileName], {
    encoding: "utf8",
    cwd: configDir,
  });
  if (r.status !== 0 || r.error) return null;
  // Aptos CLI emits JSON Result envelope; try JSON first.
  try {
    const parsed = JSON.parse(r.stdout || "");
    const acct = parsed?.Result?.[profileName]?.account;
    if (typeof acct === "string" && acct.length > 0) return add0x(acct);
  } catch {
    /* fall through */
  }
  const m = (r.stdout || "").match(/account:\s*(?:")?(0x?[0-9a-fA-F]+)(?:")?/);
  if (!m) return null;
  return add0x(m[1]);
}

// =============================================================================================
// =============================================================================================
// M9 — privacy invariant helpers
// =============================================================================================

/**
 * SHA-256 of the vault_state_v2.json content WITHOUT the slot-binding fields. Two slots that
 * share this signature are byte-identical except for `slot` + `player_id` — i.e. one is a
 * synthetic backfill of the other. Used to enforce M9 slot-truthfulness.
 */
export function vaultStateContentSignature(json) {
  if (!json || typeof json !== "object") return null;
  const { slot: _s, player_id: _p, ...rest } = json;
  const canonical = JSON.stringify(rest, Object.keys(rest).sort());
  return createHash("sha256").update(canonical).digest("hex");
}

/**
 * Returns the list of [slotA, slotB] index pairs whose vault_state content signatures collide.
 * Empty array → all slots are independent. Non-empty → at least one slot is a backfill.
 */
export function findSlotContentCollisions(slotStates) {
  const sigs = slotStates.map((s) => ({ slot: s.slot, sig: vaultStateContentSignature(s.json) }));
  const dups = [];
  for (let i = 0; i < sigs.length; i++) {
    for (let j = i + 1; j < sigs.length; j++) {
      if (sigs[i].sig && sigs[i].sig === sigs[j].sig) dups.push([sigs[i].slot, sigs[j].slot]);
    }
  }
  return dups;
}

// =============================================================================================
// buildFinalReport — reads all required artifacts and assembles the per-run evidence JSON.
// Returns { ok: true, report } | { ok: false, missingArtifacts: [{path, reason}] }.
// =============================================================================================

export async function buildFinalReport(snapshot, env, serviceRoot, stateRoot) {
  const missingArtifacts = [];

  const dkgEpoch = env.EUNOMA_TESTNET_DKG_EPOCH;
  const requestId = env.EUNOMA_TESTNET_REQUEST_ID;

  // ---- Submit artifact (M5b result) ----
  const submitPath = stateRootJoin(
    serviceRoot,
    stateRoot,
    "coordinator",
    "mpcca_withdraw_submit",
    `${dkgEpoch}__${requestId}.json`,
  );
  const submit = readJsonIfExists(submitPath);
  if (!submit) {
    missingArtifacts.push({
      path: submitPath,
      reason: "M5b submit-transcript artifact not found on disk after submit returned success",
    });
  } else if (submit.completed !== true) {
    missingArtifacts.push({
      path: submitPath,
      reason: `Submit artifact present but completed=${submit.completed}`,
    });
  } else if (!isTxHash(submit.txHash)) {
    missingArtifacts.push({
      path: submitPath,
      reason: `Submit artifact has no valid txHash (${submit.txHash})`,
    });
  } else if (submit.simulated === true) {
    // goal.md item 7 requires "Chain-confirmed withdraw tx hash" — a `--simulate`
    // pass-through is not a chain-confirmed withdraw. Refuse to declare V2 complete.
    missingArtifacts.push({
      path: submitPath,
      reason:
        "Submit artifact records simulated=true (relayer ran `aptos --simulate`). goal.md item 7 requires a chain-confirmed withdraw, not a simulation. Re-run after restarting the relayer with RELAYER_SUBMIT_ENABLED=1 so the relayer actually broadcasts.",
    });
  } else if (submit.chainSuccess !== true) {
    // The coordinator's submit route fails-closed on chainSuccess=false; if we see anything
    // other than true here, the submit was not chain-confirmed.
    missingArtifacts.push({
      path: submitPath,
      reason: `Submit artifact records chainSuccess=${submit.chainSuccess} (expected true). Not a chain-confirmed withdraw.`,
    });
  }

  // ---- Independent chain re-query of the submit tx hash ----
  // Defense in depth: a tampered local artifact OR a coordinator bug that records
  // chainSuccess=true for a failed submit would otherwise pass the gate. Re-query Aptos
  // directly and require success=true + vm_status="Executed successfully". Only do the
  // re-query if the on-disk validation above already passed (`submit` exists, txHash is
  // valid, not simulated, chainSuccess=true) — otherwise we'd waste a network call.
  let submitTxVersion = null;
  if (
    submit &&
    submit.completed === true &&
    isTxHash(submit.txHash) &&
    submit.simulated !== true &&
    submit.chainSuccess === true
  ) {
    const nodeUrl = env.APTOS_TESTNET_NODE_URL;
    if (nodeUrl) {
      const txQuery = await getTransactionByHash(nodeUrl, submit.txHash);
      if (!txQuery.ok || txQuery.body?.success !== true) {
        missingArtifacts.push({
          path: `${nodeUrl}/v1/transactions/by_hash/${submit.txHash}`,
          reason:
            `Independent on-chain re-query of relayer submit tx failed. ` +
            `status=${txQuery.status} success=${txQuery.body?.success} ` +
            `vm_status=${txQuery.body?.vm_status ?? "n/a"}. ` +
            `Local submit artifact claimed chainSuccess=true but the chain disagrees.`,
        });
      } else if (txQuery.body?.vm_status !== "Executed successfully") {
        missingArtifacts.push({
          path: `${nodeUrl}/v1/transactions/by_hash/${submit.txHash}`,
          reason:
            `Submit tx vm_status is "${txQuery.body?.vm_status ?? "missing"}", ` +
            `not "Executed successfully". Local artifact may be stale or tampered.`,
        });
      } else {
        submitTxVersion = txQuery.body?.version ?? null;
      }
    }
  }

  // ---- Finalize transcript (where transcript hashes live) ----
  const finalizePath = stateRootJoin(
    serviceRoot,
    stateRoot,
    "coordinator",
    "mpcca_withdraw",
    `${dkgEpoch}__${requestId}__finalize.json`,
  );
  const finalize = readJsonIfExists(finalizePath);
  if (!finalize) {
    missingArtifacts.push({
      path: finalizePath,
      reason: "MPCCA finalize transcript not found on disk",
    });
  }

  // ---- CA DKG V2 transcript ----
  let caDkgArtifact = null;
  if (dkgEpoch) {
    const candidates = [
      stateRootJoin(serviceRoot, stateRoot, "coordinator", "ca_dkg_v2", `${dkgEpoch}__phase2.json`),
      stateRootJoin(serviceRoot, stateRoot, "coordinator", "ca_dkg_v2", `${dkgEpoch}.json`),
    ];
    for (const c of candidates) {
      const a = readJsonIfExists(c);
      if (a) {
        caDkgArtifact = { path: c, data: a };
        break;
      }
    }
    if (!caDkgArtifact) {
      missingArtifacts.push({
        path: candidates[0],
        reason: "CA DKG V2 Phase-2 transcript not found",
      });
    }
  }

  // ---- FROST DKG V2 transcript ----
  let frostDkgArtifact = null;
  if (dkgEpoch) {
    const frostCandidates = [
      stateRootJoin(serviceRoot, stateRoot, "coordinator", "frost_dkg_v2", `${dkgEpoch}.json`),
      stateRootJoin(
        serviceRoot,
        stateRoot,
        "coordinator",
        "frost_dkg_v2",
        `${dkgEpoch}__final.json`,
      ),
    ];
    for (const c of frostCandidates) {
      const a = readJsonIfExists(c);
      if (a) {
        frostDkgArtifact = { path: c, data: a };
        break;
      }
    }
    if (!frostDkgArtifact) {
      missingArtifacts.push({
        path: frostCandidates[0],
        reason: "FROST DKG V2 transcript not found",
      });
    }
  }

  // ---- Worker state per-slot transcripts ----
  // Each slot persists a single `slot-{N}/vault_state_v2.json` with `worker_transcript_hash`
  // and `init_transcript_hash` fields. The pre-flight snapshot already validated bindings;
  // here we just confirm each file's transcript hashes are non-empty.
  // M9-f: scope vault_state checks to the SELECTED 5-of-7 active quorum, not all 7. The 2
  // unselected slots are part of the 5-of-7 threshold reserve and do not participate in init
  // or observe_deposit fan-out — they legitimately have no vault_state_v2.json. The slot-
  // collision detector enforces that the 5 selected slots have INDEPENDENT vault_state.
  const finalizeSelectedSlots = Array.isArray(finalize?.selectedSlots)
    ? finalize.selectedSlots
    : Array.isArray(finalize?.withdrawV2CallArgsFields?.selectedSlots)
      ? finalize.withdrawV2CallArgsFields.selectedSlots
      : null;
  const slotsToCheck = finalizeSelectedSlots ?? [0, 1, 2, 3, 4]; // sensible default; may be overridden

  const workerStateTranscripts = [];
  const workerInitTranscripts = [];
  const slotStatesForCollisionCheck = []; // M9-f: detect synthetic backfills within selected quorum
  if (dkgEpoch) {
    for (const slot of slotsToCheck) {
      const slotFile = resolve(
        serviceRoot,
        stateRoot ?? ".agent-local/eunoma-v2",
        `slot-${slot}`,
        "vault_state_v2.json",
      );
      const a = readJsonIfExists(slotFile);
      if (!a) {
        missingArtifacts.push({
          path: slotFile,
          reason: `Worker slot ${slot} (in selected quorum) vault_state_v2.json not found`,
        });
        continue;
      }
      slotStatesForCollisionCheck.push({ slot, json: a, path: slotFile });
      const workerHash = a.worker_transcript_hash ?? null;
      const initHash = a.init_transcript_hash ?? null;
      if (!isHex64(workerHash)) {
        missingArtifacts.push({
          path: slotFile,
          reason: `Worker slot ${slot} vault_state_v2.worker_transcript_hash is missing or malformed (${workerHash})`,
        });
      } else {
        workerStateTranscripts.push({ slot, path: slotFile, transcriptHash: workerHash });
      }
      if (!isHex64(initHash)) {
        missingArtifacts.push({
          path: slotFile,
          reason: `Worker slot ${slot} vault_state_v2.init_transcript_hash is missing or malformed (${initHash})`,
        });
      } else {
        workerInitTranscripts.push({ slot, path: slotFile, initTranscriptHash: initHash });
      }
    }
  }

  // ---- M9-f: slot-truthfulness — reject byte-identical (excluding slot/player_id) vault_state ----
  const slotCollisions = findSlotContentCollisions(slotStatesForCollisionCheck);
  if (slotCollisions.length > 0) {
    missingArtifacts.push({
      path: "<stateRoot>/slot-*/vault_state_v2.json",
      reason:
        `Slot truthfulness check failed: ${slotCollisions.length} pair(s) of slots share byte-identical ` +
        `content excluding slot/player_id fields: ${JSON.stringify(slotCollisions)}. ` +
        "This indicates a synthetic backfill (e.g. slot-5/6 copied from slot-0). " +
        "Re-run the observer + cluster so each of the 7 workers produces an independent vault_state.",
    });
  }

  // ---- M9-b/e: commitment tree artifact ----
  // M10-h (codex P1 fix): do not trust the raw JSON. CommitmentTreeV2.deserialize() re-derives
  // the root from leaves and re-computes the transcriptHash binding over
  // (scheme || depth || leafCount || rootLE || per-leaf{leafLE, depositCount, commitmentHex,
  //  sender, depositTxHash, txVersion, sequenceNumber}). It throws on root or transcript
  // mismatch, so a tampered tree file cannot silently pass the privacy gate.
  const commitmentTreePath = resolve(
    serviceRoot,
    stateRoot ?? ".agent-local/eunoma-v2",
    "coordinator",
    "commitment_tree_v2.json",
  );
  let commitmentTreeJson = null;
  let commitmentTreeVerified = null; // CommitmentTreeV2 instance after deserialize+verify
  let commitmentTreeDerivedRootHex = null;
  let commitmentTreeDerivedTranscriptHash = null;
  if (!existsSync(commitmentTreePath)) {
    missingArtifacts.push({
      path: commitmentTreePath,
      reason:
        "M9 commitment_tree_v2.json not found — run local_build_commitment_tree.mjs first to build the multi-leaf tree.",
    });
  } else {
    // Parse the JSON ourselves so we can distinguish parse-failure from
    // deserialize/integrity-failure error paths. We never trust treeJson values until
    // CommitmentTreeV2.deserialize() succeeds (which re-derives root + transcript).
    let parsedTreeJson;
    try {
      parsedTreeJson = JSON.parse(readFileSync(commitmentTreePath, "utf8"));
    } catch (e) {
      return {
        ok: false,
        missingArtifacts: [
          { path: commitmentTreePath, reason: `tree_deserialize_failed:${e?.message ?? String(e)}` },
        ],
      };
    }
    const { CommitmentTreeV2, le32ToHex: _le32ToHex, bigToLE32: _bigToLE32 } =
      await getCommitmentTreeHelpers();
    try {
      commitmentTreeVerified = await CommitmentTreeV2.deserialize(parsedTreeJson);
    } catch (e) {
      const msg = String(e?.message ?? e);
      // CommitmentTreeV2.deserialize() throws strings starting with these tags on integrity
      // failure. Translate to the M10-h integrityFailure contract.
      if (/^root_mismatch/.test(msg)) {
        return {
          ok: false,
          missingArtifacts: [],
          integrityFailure: "tree_root_mismatch",
          claimedRootHex: parsedTreeJson?.latestRootHex ?? null,
          errorMessage: msg,
        };
      }
      if (/^transcript_hash_mismatch/.test(msg)) {
        return {
          ok: false,
          missingArtifacts: [],
          integrityFailure: "tree_transcript_mismatch",
          claimedTranscriptHash: parsedTreeJson?.transcriptHash ?? null,
          errorMessage: msg,
        };
      }
      return {
        ok: false,
        missingArtifacts: [
          { path: commitmentTreePath, reason: `tree_deserialize_failed:${msg}` },
        ],
      };
    }
    // deserialize() succeeded — root and transcript are guaranteed to match the file's claim.
    // Re-derive locally so we can surface them on the report and to defensively assert the
    // contract one more time (cheap; consistent with the plan's explicit checks).
    const rootBig = await commitmentTreeVerified.root();
    commitmentTreeDerivedRootHex = _le32ToHex(_bigToLE32(rootBig));
    commitmentTreeDerivedTranscriptHash = commitmentTreeVerified._computeTranscriptHash(rootBig);
    if (
      String(commitmentTreeDerivedRootHex).toLowerCase() !==
      String(parsedTreeJson.latestRootHex ?? "").toLowerCase()
    ) {
      return {
        ok: false,
        missingArtifacts: [],
        integrityFailure: "tree_root_mismatch",
        derivedRootHex: commitmentTreeDerivedRootHex,
        claimedRootHex: parsedTreeJson.latestRootHex ?? null,
      };
    }
    if (commitmentTreeDerivedTranscriptHash !== parsedTreeJson.transcriptHash) {
      return {
        ok: false,
        missingArtifacts: [],
        integrityFailure: "tree_transcript_mismatch",
        derivedTranscriptHash: commitmentTreeDerivedTranscriptHash,
        claimedTranscriptHash: parsedTreeJson.transcriptHash,
      };
    }
    // All integrity checks pass. The JSON now mirrors a verified tree; downstream code may
    // safely read leafCount / latestRootHex / leaves / depositMeta from it.
    commitmentTreeJson = parsedTreeJson;
  }

  // ---- M9-d/e: public withdraw_tree_context side-car for this requestId ----
  const withdrawTreeContextPath = resolve(
    serviceRoot,
    stateRoot ?? ".agent-local/eunoma-v2",
    "coordinator",
    `withdraw_tree_context_${(requestId ?? "").replace(/[^A-Za-z0-9_-]/g, "_")}.json`,
  );
  const withdrawTreeContext = readJsonIfExists(withdrawTreeContextPath);
  if (!withdrawTreeContext) {
    missingArtifacts.push({
      path: withdrawTreeContextPath,
      reason:
        "M9 public withdraw_tree_context side-car for this requestId not found — " +
        "the withdraw orchestrator (local_v2_withdraw_full.mjs) writes it after the final witness build.",
    });
  } else {
    const FORBIDDEN = /^(amount|secret|nullifier|.*blind|dk|inverse)$/i;
    for (const k of Object.keys(withdrawTreeContext)) {
      if (FORBIDDEN.test(k)) {
        missingArtifacts.push({
          path: withdrawTreeContextPath,
          reason: `withdraw_tree_context contains forbidden private field "${k}". This file MUST contain only public chain-derivable values.`,
        });
        break;
      }
    }
  }

  // ---- If anything missing, return the structured failure ----
  if (missingArtifacts.length > 0) {
    return { ok: false, missingArtifacts };
  }

  // ---- All artifacts present. Pull every required hash. ----
  const submitArtifact = submit;
  const finalizeArtifact = finalize;

  const caPayloadHash =
    finalizeArtifact?.callArgs?.caPayloadHash ??
    finalizeArtifact?.withdrawV2CallArgsFields?.caPayloadHash ??
    finalizeArtifact?.caPayloadHashFr ??
    finalizeArtifact?.ca_payload_hash ??
    finalizeArtifact?.caPayloadHash ??
    null;
  const rosterHash =
    finalizeArtifact?.rosterHash ??
    finalizeArtifact?.roster_hash ??
    finalizeArtifact?.attestationConfig?.rosterHash ??
    finalizeArtifact?.attestationConfig?.caDkgV2RosterHash ??
    caDkgArtifact?.data?.caDkgV2RosterHash ??
    null;
  // Transcript hash on the withdraw finalize artifact itself is the canonical
  // quorum-binding hash post M5-c1 FROST attest (the artifact's `transcriptHash`).
  const quorumTranscriptHash =
    finalizeArtifact?.quorumTranscriptHash ??
    finalizeArtifact?.quorum_transcript_hash ??
    finalizeArtifact?.transcriptHash ??
    null;
  const mpccaTranscriptHash =
    finalizeArtifact?.mpccaWithdrawFinalTranscriptHash ??
    finalizeArtifact?.transcriptHash ??
    submitArtifact?.finalizeTranscriptHash ??
    null;

  const caDkgV2RosterHash =
    caDkgArtifact?.data?.rosterHash ??
    caDkgArtifact?.data?.caDkgV2RosterHash ??
    caDkgArtifact?.data?.transcript?.rosterHash ??
    null;
  const frostDkgV2RosterHash =
    frostDkgArtifact?.data?.rosterHash ??
    frostDkgArtifact?.data?.frostDkgV2RosterHash ??
    frostDkgArtifact?.data?.transcript?.rosterHash ??
    null;

  // Vault state init transcript hash — use the per-slot init_transcript_hash. All 7 slots
  // must agree (the worker code pins init_transcript_hash to the canonical final hash via
  // vault_state_v2_init_finalize). If they disagree, that's a hard miss.
  let vaultStateInitHash = null;
  if (workerInitTranscripts.length > 0) {
    const set = new Set(workerInitTranscripts.map((w) => w.initTranscriptHash));
    if (set.size !== 1) {
      missingArtifacts.push({
        path: "<stateRoot>/slot-*/vault_state_v2.json",
        reason: `Per-slot init_transcript_hash values disagree across slots: ${[...set].join(", ")}. All 7 workers must agree on the canonical init transcript hash.`,
      });
    } else {
      vaultStateInitHash = [...set][0];
    }
  }

  const report = {
    txHashes: {
      vaultInit: snapshot?.vaultInitTx?.hash ?? null,
      deposit: snapshot?.depositTx?.hash ?? null,
      relayerSubmit: submitArtifact.txHash,
      chainConfirmedWithdraw: submitArtifact.txHash, // same value — chain-confirmed after waitForTx
    },
    chainVersions: {
      vaultInit: snapshot?.vaultInitTx?.version ?? null,
      deposit: snapshot?.depositTx?.version ?? null,
      relayerSubmit: submitTxVersion,
    },
    depositEventProof: snapshot?.depositEvent ?? null,
    transcriptHashes: {
      caPayload: caPayloadHash,
      caDkgV2Roster: caDkgV2RosterHash,
      frostDkgV2Roster: frostDkgV2RosterHash,
      deoperatorRoster: rosterHash,
      quorum: quorumTranscriptHash,
      vaultStateInit: vaultStateInitHash,
      vaultStatePerSlot: workerStateTranscripts.map((w) => w.transcriptHash),
      mpcca: mpccaTranscriptHash,
      submit: submitArtifact.transcriptHash ?? null,
      observedDeposit: snapshot?.observedDepositTranscriptHash ?? null,
    },
    sources: {
      submitArtifactPath: submitPath,
      finalizeTranscriptPath: finalizePath,
      vaultInitArtifactPath: snapshot?.vaultInitArtifactPath ?? null,
      caDkgV2Path: caDkgArtifact?.path ?? null,
      frostDkgV2Path: frostDkgArtifact?.path ?? null,
      workerStatePaths: workerStateTranscripts.map((w) => w.path),
      observedDepositArtifactPath: snapshot?.observedDepositArtifactPath ?? null,
    },
    invariants: {
      threshold: snapshot?.deoperatorConfig?.threshold ?? null,
      operatorSetVersion: snapshot?.deoperatorConfig?.operator_set_version ?? null,
      dkgEpoch: snapshot?.deoperatorConfig?.dkg_epoch ?? null,
      simulated: submitArtifact.simulated === true,
      chainSuccess: submitArtifact.chainSuccess ?? null,
      allSlotsIndependent: slotCollisions.length === 0,
    },
  };

  // ---- M9-e: privacy block ----
  // M10-h (codex P1 fix): leafIndex and commitmentHex are intentionally omitted from
  // report.privacy because they directly de-anonymize the spent leaf in the multi-leaf
  // anonymity set. Use anonymitySetSize / distinctDepositSenders / rootHex / treeTranscriptHash
  // for verifier evidence. The M10-f side-car producer no longer publishes either field;
  // the consumer here mirrors that contract so the final report cannot leak them.
  const minAnonymitySet = Number(env.EUNOMA_MIN_ANONYMITY_SET ?? "8");
  const privacyFailures = [];
  let singleLeafRootRejected = null;
  let distinctDepositSenders = null;
  let treeRootHex = null;
  let usedRootHex = null;
  let treeTranscriptHash = null;
  let anonymitySetSize = null;
  if (commitmentTreeJson && withdrawTreeContext) {
    anonymitySetSize = commitmentTreeJson.leafCount ?? 0;
    treeRootHex = commitmentTreeJson.latestRootHex ?? null;
    treeTranscriptHash = commitmentTreeJson.transcriptHash ?? null;

    const senderSet = new Set();
    for (const m of commitmentTreeJson.depositMeta ?? []) {
      if (m.sender) senderSet.add(m.sender.toLowerCase());
    }
    distinctDepositSenders = senderSet.size;

    usedRootHex =
      finalizeArtifact?.withdrawV2CallArgsFields?.root ??
      finalizeArtifact?.callArgs?.root ??
      submitArtifact?.callArgs?.root ??
      submitArtifact?.withdrawV2CallArgsFields?.root ??
      null;

    if (usedRootHex && commitmentTreeJson.leaves?.length) {
      try {
        const { singleLeafRoot, hexToLE32, leBytesToBig, bigToLE32, le32ToHex } = await getCommitmentTreeHelpers();
        let collide = false;
        for (const leafHex of commitmentTreeJson.leaves) {
          const big = leBytesToBig(hexToLE32(leafHex));
          const sl = await singleLeafRoot(big, commitmentTreeJson.treeDepth ?? 20);
          const slHex = le32ToHex(bigToLE32(sl));
          if (slHex.toLowerCase() === usedRootHex.toLowerCase()) {
            collide = true;
            break;
          }
        }
        singleLeafRootRejected = !collide;
      } catch (e) {
        singleLeafRootRejected = false;
        privacyFailures.push(`single_leaf_root_check_error:${e?.message ?? String(e)}`);
      }
    } else {
      singleLeafRootRejected = false;
      privacyFailures.push("single_leaf_root_check_missing_inputs");
    }

    if (anonymitySetSize < minAnonymitySet) privacyFailures.push("anonymity_set_too_small");
    if (
      !usedRootHex ||
      !treeRootHex ||
      usedRootHex.toLowerCase() !== treeRootHex.toLowerCase()
    ) {
      privacyFailures.push("root_mismatch");
    }
    if (singleLeafRootRejected !== true) privacyFailures.push("single_leaf_root_match");
    // M10-h: leafIndex no longer present in side-car; do not check it. The privacy
    // claim is multi-leaf unlinkability — the verifier proves they spent SOME leaf
    // in the set, not which leaf. Demanding leafIndex on the report would force a
    // de-anonymization leak.
    if (distinctDepositSenders < 2) privacyFailures.push("distinct_depositor_senders_below_minimum");
  }

  // M10-h: balanceWitnessIntegrity — hard-pass iff the submit tx returned success and
  // vm_status == "Executed successfully" on chain. The submit-stage chain re-query above
  // already enforces this gate (any failure pushes to missingArtifacts and we return
  // before reaching here). So if execution reaches this point, the on-chain submit tx
  // is verified to have succeeded; surfacing the flag on report.privacy makes the
  // invariant explicit for downstream auditors.
  // Defense-in-depth: re-check the locally-recorded submit artifact's chainSuccess flag.
  // The pre-flight independent re-query (above) hard-fails if the chain disagrees with
  // the local flag, so both being true after the missing-artifact gate is the strongest
  // statement we can make from the helper module's vantage point.
  const balanceWitnessIntegrity = submitArtifact?.chainSuccess === true;

  report.privacy = {
    amountHidden: true,
    depositSenderPublic: true,
    withdrawRecipientPublic: true,
    depositWithdrawUnlinkability: "multi_leaf_root",
    anonymitySetSize,
    minAnonymitySet,
    rootDepositCount: anonymitySetSize,
    leafIndexPublic: false,
    // M10-h (codex P1 fix): leafIndexUsed and commitmentHex are intentionally omitted —
    // both directly de-anonymize the spent leaf. The side-car producer (local_v2_withdraw_full.mjs)
    // and this consumer mirror the contract.
    recipientPrivacy: false,
    singleLeafRootRejected,
    treeRootHex,
    usedRootHex,
    treeTranscriptHash,
    distinctDepositSenders,
    distinctDepositSendersMin: 2,
    balanceWitnessIntegrity,
    failures: privacyFailures,
  };
  report.sources.commitmentTreePath = commitmentTreeJson ? commitmentTreePath : null;
  report.sources.withdrawTreeContextPath = withdrawTreeContext ? withdrawTreeContextPath : null;

  // Hard cross-check: if any required hash is null, report it as a missing artifact instead of
  // declaring V2 complete with holes. This catches the "submit succeeded but transcripts are stubs"
  // race.
  const required = [
    ["txHashes.vaultInit", report.txHashes.vaultInit],
    ["txHashes.deposit", report.txHashes.deposit],
    ["txHashes.relayerSubmit", report.txHashes.relayerSubmit],
    ["txHashes.chainConfirmedWithdraw", report.txHashes.chainConfirmedWithdraw],
    ["depositEventProof", report.depositEventProof],
    ["transcriptHashes.caPayload", report.transcriptHashes.caPayload],
    ["transcriptHashes.caDkgV2Roster", report.transcriptHashes.caDkgV2Roster],
    ["transcriptHashes.frostDkgV2Roster", report.transcriptHashes.frostDkgV2Roster],
    ["transcriptHashes.deoperatorRoster", report.transcriptHashes.deoperatorRoster],
    ["transcriptHashes.quorum", report.transcriptHashes.quorum],
    ["transcriptHashes.vaultStateInit", report.transcriptHashes.vaultStateInit],
    ["transcriptHashes.mpcca", report.transcriptHashes.mpcca],
    ["transcriptHashes.submit", report.transcriptHashes.submit],
    ["transcriptHashes.observedDeposit", report.transcriptHashes.observedDeposit],
    ["invariants.chainSuccess", report.invariants.chainSuccess],
  ];
  // Reject null/undefined. Also reject invariants.chainSuccess !== true explicitly
  // (false would otherwise sneak through the null-only check).
  const badFields = required
    .filter(([k, v]) => {
      if (v === null || v === undefined) return true;
      if (k === "invariants.chainSuccess" && v !== true) return true;
      return false;
    })
    .map(([k, v]) => [k, v]);
  if (badFields.length > 0) {
    return {
      ok: false,
      missingArtifacts: badFields.map(([k, v]) => ({
        path: submitPath,
        reason: `Report field ${k} is ${v === null ? "null" : v === undefined ? "undefined" : String(v)} — required value missing or wrong`,
      })),
    };
  }
  // M9-f: vault_state truthfulness is scoped to the selected 5-of-7 active quorum.
  // Unselected slots do not run init/observe_deposit and have no vault_state_v2.json by design.
  const expectedSlotsLen = slotsToCheck.length;
  if (report.transcriptHashes.vaultStatePerSlot.length !== expectedSlotsLen) {
    return {
      ok: false,
      missingArtifacts: [
        {
          path: "<stateRoot>/slot-*/vault_state_v2/*",
          reason: `Expected ${expectedSlotsLen} per-selected-slot transcript hashes (matching finalize.selectedSlots), got ${report.transcriptHashes.vaultStatePerSlot.length}`,
        },
      ],
    };
  }

  // ---- M9-e: privacy + slot-truthfulness gate ----
  if (privacyFailures.length > 0) {
    return {
      ok: false,
      missingArtifacts: privacyFailures.map((f) => ({
        path: "<privacy>",
        reason: `privacy invariant failure: ${f}`,
      })),
    };
  }
  if (!report.invariants.allSlotsIndependent) {
    return {
      ok: false,
      missingArtifacts: [
        {
          path: "<slot-truthfulness>",
          reason: "invariants.allSlotsIndependent is false — at least two slot vault_state files are byte-identical excluding slot/player_id fields",
        },
      ],
    };
  }

  return { ok: true, report };
}

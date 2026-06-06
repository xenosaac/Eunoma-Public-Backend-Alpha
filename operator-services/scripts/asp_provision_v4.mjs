#!/usr/bin/env node
// Fresh V4 provisioning for the clean-replace testnet package:
//   - initializes cache/delegate resources required by V4 deposit/withdraw/ragequit;
//   - publishes V4-named deposit/withdraw VKs plus ragequit VK;
//   - writes <stateRoot>/coordinator/asset_registry.json from on-chain AssetRegistryV4.
//
// Env: BRIDGE_PACKAGE_ADDRESS, ADMIN_PROFILE, EUNOMA_LOCAL_STATE_ROOT, APTOS_NODE_URL,
//      RESERVE_ACCOUNT_ADDRESS, EUNOMA_DEPOSIT_RELAYER_GAS_FEE_OCTAS.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const repoRoot = resolve(serviceRoot, "..");

const BRIDGE = process.env.BRIDGE_PACKAGE_ADDRESS;
const PROFILE = process.env.ADMIN_PROFILE || "testnet-user";
const NODE_URL = normalizeNodeUrl(process.env.APTOS_NODE_URL || "https://fullnode.testnet.aptoslabs.com/v1");
const STATE_ROOT = resolve(serviceRoot, process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2-asp");
const GAS_FEE_OCTAS = decimalEnv(
  process.env.EUNOMA_DEPOSIT_RELAYER_GAS_FEE_OCTAS ??
    process.env.DEPOSIT_RELAYER_GAS_FEE_OCTAS ??
    "4000000",
  "EUNOMA_DEPOSIT_RELAYER_GAS_FEE_OCTAS",
);
const RESERVE_ACCOUNT = process.env.RESERVE_ACCOUNT_ADDRESS ?? process.env.RELAYER_RESERVE_ACCOUNT_ADDRESS;

if (!BRIDGE) {
  console.error("BRIDGE_PACKAGE_ADDRESS required");
  process.exit(2);
}
if (GAS_FEE_OCTAS !== "0" && !RESERVE_ACCOUNT) {
  console.error("RESERVE_ACCOUNT_ADDRESS required when deposit relayer gas fee is nonzero");
  process.exit(2);
}

const vkArgs = (extractor) => {
  const raw = execFileSync("node", [resolve(repoRoot, "circuits/scripts", extractor)], {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const j = JSON.parse(raw);
  const all = [j.alpha_g1, j.beta_g2, j.gamma_g2, j.delta_g2, ...j.ic];
  return all.map((h) => `hex:0x${strip0x(h)}`);
};
const withdrawVkPublishArgs = () => {
  const raw = execFileSync("node", [resolve(repoRoot, "circuits/scripts/extract_withdraw_vk.js")], {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const j = JSON.parse(raw);
  const dummyG1 = "00".repeat(64);
  const paddedIc = [...j.ic, ...Array.from({ length: 7 }, () => dummyG1)];
  const all = [j.alpha_g1, j.beta_g2, j.gamma_g2, j.delta_g2, ...paddedIc];
  return all.map((h) => `hex:0x${strip0x(h)}`);
};

const steps = [
  ["init_recorder_delegate", null],
  ["init_asp_recorder_delegate", null],
  ["ensure_gas_fee_config_v1", gasFeeArgs()],
  ["init_pending_deposit_bindings_v2", null],
  ["init_pending_deposit_bindings_v3", null],
  ["init_pending_deposit_finalizations_v3", null],
  ["init_circuit_versions_hash_cache_v2", null],
  ["init_pending_withdraw_attestations_v2", null],
  ["init_pending_withdraw_payloads_v2", null],
  ["init_pending_withdraw_proofs_v3b", null],
  ["init_pending_withdraw_attestations_v3", null],
  ["init_pending_withdraw_attestations_v2b", null],
  ["init_pending_withdraw_payloads_v3", null],
  ["init_pending_withdraw_finalizations_v3", null],
  ["init_pending_withdraw_conservations_v4", null],
  ["publish_deposit_binding_vk_v4", vkArgs("extract_deposit_binding_vk.js")],
  ["publish_prepared_deposit_binding_vk_v2", null],
  ["publish_withdraw_proof_vk_v4", withdrawVkPublishArgs()],
  ["publish_prepared_withdraw_proof_vk_v2", null],
  ["publish_ragequit_proof_vk", vkArgs("extract_ragequit_vk.js")],
  ["publish_prepared_ragequit_proof_vk", null],
];

const resourceByEntry = new Map([
  ["init_recorder_delegate", "RecorderDelegate"],
  ["init_asp_recorder_delegate", "ASPRecorderDelegate"],
  ["init_pending_deposit_bindings_v2", "PendingDepositBindingsV2"],
  ["init_pending_deposit_bindings_v3", "PendingDepositBindingsV3"],
  ["init_pending_deposit_finalizations_v3", "PendingDepositFinalizationsV3"],
  ["init_circuit_versions_hash_cache_v2", "CircuitVersionsHashCacheV2"],
  ["init_pending_withdraw_attestations_v2", "PendingWithdrawAttestationsV2"],
  ["init_pending_withdraw_payloads_v2", "PendingWithdrawPayloadsV2"],
  ["init_pending_withdraw_proofs_v3b", "PendingWithdrawProofsV3b"],
  ["init_pending_withdraw_attestations_v3", "PendingWithdrawAttestationsV3"],
  ["init_pending_withdraw_attestations_v2b", "PendingWithdrawAttestationsV2b"],
  ["init_pending_withdraw_payloads_v3", "PendingWithdrawPayloadsV3"],
  ["init_pending_withdraw_finalizations_v3", "PendingWithdrawFinalizationsV3"],
  ["init_pending_withdraw_conservations_v4", "PendingWithdrawConservationsV4"],
  ["publish_deposit_binding_vk_v4", "DepositBindingVK"],
  ["publish_prepared_deposit_binding_vk_v2", "PreparedDepositBindingVK"],
  ["publish_withdraw_proof_vk_v4", "WithdrawProofVK"],
  ["publish_prepared_withdraw_proof_vk_v2", "PreparedWithdrawProofVK"],
  ["publish_ragequit_proof_vk", "RagequitProofVK"],
  ["publish_prepared_ragequit_proof_vk", "PreparedRagequitProofVK"],
]);

const results = [];
for (const [entry, args] of steps) {
  process.stderr.write(`-> ${entry}${args ? ` (${args.length} args)` : ""} ... `);
  const result = runEntry(entry, args);
  process.stderr.write(
    `${result.ok ? (result.skipped ? "SKIP(exists)" : `OK ${result.txHash?.slice(0, 14)} gas=${result.gas}`) : "FAIL"}\n`,
  );
  results.push(result);
  if (!result.ok) {
    console.error(`  ${result.error}`);
    break;
  }
}

const allOk = results.every((r) => r.ok);
let registryPath = null;
if (allOk) {
  registryPath = await writeAssetRegistryArtifact();
}

const outDir = join(STATE_ROOT, "coordinator");
mkdirSync(outDir, { recursive: true });
const statePath = join(outDir, "v4_provision_state.json");
const prev = existsSync(statePath) ? JSON.parse(readFileSync(statePath, "utf8")) : {};
writeFileSync(
  statePath,
  JSON.stringify(
    {
      ...prev,
      bridge: normalizeAddress(BRIDGE),
      profile: PROFILE,
      nodeUrl: NODE_URL,
      registryPath,
      results,
      updatedAtUnixMs: Date.now(),
    },
    null,
    2,
  ) + "\n",
);

process.stdout.write(JSON.stringify({ allOk, statePath, registryPath, results }, null, 2) + "\n");
process.exit(allOk ? 0 : 1);

function runEntry(entry, args) {
  if (entry === "ensure_gas_fee_config_v1") {
    return runGasFeeConfig(args);
  }
  const resourceName = resourceByEntry.get(entry);
  if (resourceName && resourceExistsSync(resourceName)) {
    return { entry, ok: true, skipped: "resource_exists" };
  }
  return runMoveEntry(entry, args);
}

function runGasFeeConfig(args) {
  const reserveAddr = gasFeeReserveAddress();
  const existing = resourceReadSync("GasFeeConfigV1");
  if (existing) {
    const currentFee = String(existing.data?.flat_fee_octas ?? "");
    const currentReserve = existing.data?.reserve_addr ? normalizeAddress(existing.data.reserve_addr) : "";
    if (currentFee === GAS_FEE_OCTAS && currentReserve === reserveAddr) {
      return {
        entry: "ensure_gas_fee_config_v1",
        ok: true,
        skipped: "resource_matches",
        flatFeeOctas: GAS_FEE_OCTAS,
        reserveAddr,
      };
    }
    return {
      ...runMoveEntry("admin_set_gas_fee_config_v1", args, "ensure_gas_fee_config_v1"),
      action: "admin_set_gas_fee_config_v1",
      flatFeeOctas: GAS_FEE_OCTAS,
      reserveAddr,
    };
  }
  return {
    ...runMoveEntry("init_gas_fee_config_v1", args, "ensure_gas_fee_config_v1"),
    action: "init_gas_fee_config_v1",
    flatFeeOctas: GAS_FEE_OCTAS,
    reserveAddr,
  };
}

function runMoveEntry(entry, args, resultEntry = entry) {
  const cli = [
    "move",
    "run",
    "--function-id",
    `${normalizeAddress(BRIDGE)}::eunoma_bridge::${entry}`,
    "--profile",
    PROFILE,
    "--assume-yes",
  ];
  if (args && args.length > 0) {
    cli.push("--args", ...args);
  }
  try {
    const out = execFileSync("aptos", cli, {
      cwd: repoRoot,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
    const jsonStart = out.indexOf("{");
    const parsed = jsonStart >= 0 ? JSON.parse(out.slice(jsonStart)) : {};
    const r = parsed.Result ?? {};
    return {
      entry: resultEntry,
      action: entry,
      ok: r.success === true,
      txHash: r.transaction_hash,
      gas: r.gas_used,
      vmStatus: r.vm_status,
    };
  } catch (e) {
    const blob = `${e.stdout ?? ""}${e.stderr ?? ""}`;
    if (/E_ALREADY_INITIALIZED|ALREADY_INITIALIZED|RESOURCE_ALREADY_EXISTS|0x80003/.test(blob)) {
      return { entry: resultEntry, action: entry, ok: true, skipped: "already_initialized" };
    }
    return {
      entry: resultEntry,
      action: entry,
      ok: false,
      error: blob
        .split("\n")
        .filter(Boolean)
        .slice(-8)
        .join(" | ")
        .slice(0, 1200),
    };
  }
}

function gasFeeArgs() {
  return [`u64:${GAS_FEE_OCTAS}`, `address:${gasFeeReserveAddress()}`];
}

function gasFeeReserveAddress() {
  return RESERVE_ACCOUNT ? normalizeAddress(RESERVE_ACCOUNT) : normalizeAddress(BRIDGE);
}

function resourceExistsSync(resourceName) {
  return resourceReadSync(resourceName) !== null;
}

function resourceReadSync(resourceName) {
  const type = `${normalizeAddress(BRIDGE)}::eunoma_bridge::${resourceName}`;
  const url = `${NODE_URL}/accounts/${normalizeAddress(BRIDGE)}/resource/${encodeURIComponent(type)}`;
  try {
    const out = execFileSync(
      "node",
      [
        "-e",
        `
const url = process.argv[1];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
for (let attempt = 1; attempt <= 10; attempt += 1) {
  const res = await fetch(url, { headers: { accept: "application/json" } });
  const text = await res.text();
  if (res.status === 200) {
    console.log(text);
    process.exit(0);
  }
  if (res.status === 404) process.exit(1);
  const retryable =
    res.status === 408 ||
    res.status === 409 ||
    res.status === 425 ||
    res.status === 429 ||
    res.status >= 500 ||
    /rate limit|per anonymous ip/i.test(text);
  if (!retryable || attempt === 10) {
    console.error(text);
    process.exit(2);
  }
  await sleep(Math.min(3000 + attempt * 1000, 15000));
}
`,
        url,
      ],
      { encoding: "utf8", maxBuffer: 1024 * 1024 },
    );
    return JSON.parse(out);
  } catch (e) {
    if (e.status === 1) return null;
    throw new Error(`resource precheck failed for ${resourceName}: ${e.stdout ?? ""}${e.stderr ?? ""}`);
  }
}

async function writeAssetRegistryArtifact() {
  const core = await getResource(`${normalizeAddress(BRIDGE)}::eunoma_bridge::VaultCoreV4`);
  const registry = await getResource(`${normalizeAddress(BRIDGE)}::eunoma_bridge::AssetRegistryV4`);
  const tableHandle = registry.data?.by_asset?.handle;
  const assetList = registry.data?.asset_list;
  if (!core.data?.vault_addr || typeof tableHandle !== "string" || !Array.isArray(assetList)) {
    throw new Error("cannot read VaultCoreV4/AssetRegistryV4 shape from chain");
  }
  const vault = normalizeAddress(core.data.vault_addr);
  const assets = [];
  for (const metadata of assetList) {
    const row = await getTableItem(tableHandle, metadata);
    const assetType = row.asset_type?.inner ?? metadata;
    const metadataAddr = normalizeAddress(metadata);
    assets.push({
      symbol: metadataAddr === padAddress("0xa") ? "ConfidentialAPT" : `c${metadataAddr.slice(2, 8)}`,
      plainSymbol: metadataAddr === padAddress("0xa") ? "APT" : metadataAddr.slice(2, 8).toUpperCase(),
      metadata: metadataAddr,
      assetType: normalizeAddress(assetType),
      assetIdFr: normalizeHex32(row.asset_id_fr),
      vaultAddrHashFr: normalizeHex32(row.vault_addr_hash_fr),
      decimals: Number(row.decimals),
      vault,
      vaultEkHex: normalizeHex32(row.vault_ek),
      poolId: "0",
      status: statusName(row.status),
    });
  }

  const apt = assets.find((a) => a.metadata === padAddress("0xa"));
  const common = apt
    ? { vault: apt.vault, vaultEkHex: apt.vaultEkHex, poolId: "0" }
    : { vault, vaultEkHex: `0x${"00".repeat(32)}`, poolId: "0" };
  const withDormantStablecoins = [
    ...assets,
    {
      symbol: "cUSDC",
      plainSymbol: "USDC",
      metadata: padAddress("0xc01"),
      assetIdFr: `0x${"22".repeat(32)}`,
      decimals: 6,
      ...common,
      status: "DORMANT",
    },
    {
      symbol: "cUSDT",
      plainSymbol: "USDT",
      metadata: padAddress("0xc02"),
      assetIdFr: `0x${"33".repeat(32)}`,
      decimals: 6,
      ...common,
      status: "DORMANT",
    },
  ];

  const outDir = join(STATE_ROOT, "coordinator");
  mkdirSync(outDir, { recursive: true });
  const path = join(outDir, "asset_registry.json");
  writeFileSync(
    path,
    JSON.stringify(
      {
        bridge: normalizeAddress(BRIDGE),
        generatedAtUnixMs: Date.now(),
        source: "asp_provision_v4.mjs/on-chain AssetRegistryV4",
        assets: withDormantStablecoins,
      },
      null,
      2,
    ) + "\n",
  );
  return path;
}

async function getResource(type) {
  const res = await fetchWithRetry(
    `${NODE_URL}/accounts/${normalizeAddress(BRIDGE)}/resource/${encodeURIComponent(type)}`,
    undefined,
    `resource ${type}`,
  );
  if (!res.ok) {
    throw new Error(`resource ${type} failed: ${res.status} ${await res.text()}`);
  }
  return res.json();
}

async function getTableItem(handle, key) {
  const res = await fetchWithRetry(
    `${NODE_URL}/tables/${handle}/item`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        key_type: "address",
        value_type: `${normalizeAddress(BRIDGE)}::eunoma_bridge::AssetVaultStateV4`,
        key: normalizeAddress(key),
      }),
    },
    `table item ${handle}/${key}`,
  );
  if (!res.ok) {
    throw new Error(`table item ${handle}/${key} failed: ${res.status} ${await res.text()}`);
  }
  return res.json();
}

async function fetchWithRetry(url, init, label) {
  let lastText = "";
  for (let attempt = 1; attempt <= 10; attempt += 1) {
    const res = await fetch(url, init);
    if (res.ok || res.status === 404) return res;
    lastText = await res.text();
    if (!isRetryableHttp(res.status, lastText) || attempt === 10) {
      throw new Error(`${label} failed: ${res.status} ${lastText}`);
    }
    await sleep(Math.min(3000 + attempt * 1000, 15000));
  }
  throw new Error(`${label} failed: ${lastText}`);
}

function normalizeNodeUrl(value) {
  const s = String(value).replace(/\/+$/, "");
  return s.endsWith("/v1") ? s : `${s}/v1`;
}

function decimalEnv(value, name) {
  const s = String(value ?? "");
  if (!/^[0-9]+$/.test(s)) {
    throw new Error(`${name} must be a decimal u64 string`);
  }
  return s;
}

function isRetryableHttp(status, text) {
  return (
    status === 408 ||
    status === 409 ||
    status === 425 ||
    status === 429 ||
    status >= 500 ||
    /rate limit|per anonymous ip/i.test(text)
  );
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function strip0x(value) {
  return String(value).replace(/^0x/i, "").toLowerCase();
}

function normalizeAddress(value) {
  const clean = strip0x(value);
  if (!/^[0-9a-f]+$/.test(clean) || clean.length > 64) {
    throw new Error(`invalid address: ${value}`);
  }
  return `0x${clean.padStart(64, "0")}`;
}

function padAddress(value) {
  return normalizeAddress(value);
}

function normalizeHex32(value) {
  const clean = strip0x(value);
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error(`expected 32-byte hex: ${value}`);
  }
  return `0x${clean}`;
}

function statusName(value) {
  if (value === 1 || value === "1" || value === "ACTIVE") return "ACTIVE";
  if (value === 0 || value === "0" || value === "DORMANT") return "DORMANT";
  if (value === 2 || value === "2" || value === "PAUSED") return "PAUSED";
  throw new Error(`unknown asset status: ${value}`);
}

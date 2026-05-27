#!/usr/bin/env node
// =============================================================================================
// M9-b — Build the append-only commitment tree from confirmed `DepositConfirmedV2` events.
//
// Primary ingestion source: confirmed tx hashes from public deposit sidecars / legacy depositor
// witness JSONs (or `--tx-hashes`), fetched via `GET /v1/transactions/by_hash/<hash>`. This is the
// canonical Aptos REST path for confirmed-tx state and is stable across fullnode versions.
//
// Optional `--refresh-from-event-feed` additionally queries the bridge's module event feed and
// cross-checks that every feed entry's (version, sequence_number) is already in the primary set.
// Module event feed alone is NOT trusted to append leaves because the REST shape varies between
// Aptos fullnode versions.
//
// Persisted artifact (atomic write, 0o644): `<state-dir>/commitment_tree_v2.json`.
// =============================================================================================
import { mkdirSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CommitmentTreeV2,
  assertTreeArtifactPublicOnly,
} from "../../circuits/scripts/commitment_tree_v2.mjs";
import { hexToLE32, leBytesToBig } from "../../circuits/scripts/poseidon_merkle.mjs";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..", "..");

function parseArgs(argv) {
  const out = {
    bridgePackageAddress: null,
    vaultAddress: null,
    assetType: null,
    aptosNodeUrl: process.env.APTOS_TESTNET_NODE_URL ?? "https://fullnode.testnet.aptoslabs.com/v1",
    stateDir: join(REPO_ROOT, "operator-services", ".agent-local", "eunoma-v2", "coordinator"),
    depositorWitnessDir: join(
      REPO_ROOT,
      "operator-services",
      ".agent-local",
      "eunoma-v2",
      "depositor",
    ),
    txHashes: [],
    refreshFromEventFeed: false,
    dryRun: false,
    refresh: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--bridge-package-address": out.bridgePackageAddress = argv[++i]; break;
      case "--vault-address": out.vaultAddress = argv[++i]; break;
      case "--asset-type": out.assetType = argv[++i]; break;
      case "--aptos-node-url": out.aptosNodeUrl = argv[++i]; break;
      case "--state-dir": out.stateDir = argv[++i]; break;
      case "--depositor-witness-dir": out.depositorWitnessDir = argv[++i]; break;
      case "--tx-hashes":
        out.txHashes.push(...argv[++i].split(",").map((s) => s.trim()).filter(Boolean));
        break;
      case "--refresh-from-event-feed": out.refreshFromEventFeed = true; break;
      case "--dry-run": out.dryRun = true; break;
      case "--refresh": out.refresh = true; break;
      case "-h":
      case "--help":
        printHelpAndExit(0);
        break;
      default:
        if (a.startsWith("--")) {
          console.error(`unknown flag: ${a}`);
          printHelpAndExit(2);
        }
    }
  }
  return out;
}

function printHelpAndExit(code) {
  console.error(`
usage: local_build_commitment_tree.mjs --bridge-package-address HEX --vault-address HEX --asset-type ADDR

required:
  --bridge-package-address HEX     bridge package account (e.g. 0xa08850b1...)
  --vault-address HEX              bridge vault resource account
  --asset-type ADDR                e.g. 0xa for testnet APT FA

optional:
  --aptos-node-url URL             default APTOS_TESTNET_NODE_URL or testnet REST v1
  --state-dir PATH                 default <repo>/operator-services/.agent-local/eunoma-v2/coordinator
  --depositor-witness-dir PATH     default <repo>/operator-services/.agent-local/eunoma-v2/depositor
  --tx-hashes 0x..,0x..            override witness-dir scan with explicit tx-hash list
  --refresh-from-event-feed        cross-check primary tx-hash set against module event feed
  --dry-run                        build in memory + print summary; do not write artifact
  --refresh                        merge with existing artifact (preserve prior leaves)
`);
  process.exit(code);
}

function loadDepositorTxHashes(dir) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch (e) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
  const txHashes = [];
  for (const f of entries) {
    const publicSidecar = f.startsWith("deposit_public_") && f.endsWith(".json");
    const legacyWitness = f.startsWith("withdraw_witness_") && f.endsWith(".json");
    if (!publicSidecar && !legacyWitness) continue;
    const p = join(dir, f);
    let raw;
    try {
      raw = JSON.parse(readFileSync(p, "utf8"));
    } catch {
      continue;
    }
    if (raw?.schema !== "v2_deposit_public_v1" && raw?.schema !== "v2_depositor_witness_v1") {
      continue;
    }
    const h = raw.depositTxHash;
    if (typeof h === "string" && /^0x[0-9a-fA-F]{64}$/.test(h)) txHashes.push(h.toLowerCase());
  }
  return txHashes;
}

async function fetchJson(url) {
  const r = await fetch(url);
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error(`http_${r.status}:${url}:${body.slice(0, 200)}`);
  }
  return await r.json();
}

async function fetchDepositEventByTxHash({ aptosNodeUrl, txHash, bridgePackageAddress }) {
  const url = `${aptosNodeUrl.replace(/\/+$/, "")}/transactions/by_hash/${txHash}`;
  const tx = await fetchJson(url);
  if (tx.type !== "user_transaction") {
    throw new Error(`not_user_tx:${txHash}:${tx.type}`);
  }
  if (tx.success !== true) {
    throw new Error(`tx_failed:${txHash}`);
  }
  if (tx.vm_status !== "Executed successfully") {
    throw new Error(`vm_status:${txHash}:${tx.vm_status}`);
  }
  const eventType = `${bridgePackageAddress}::eunoma_bridge::DepositConfirmedV2`;
  const ev = tx.events?.find((e) => e.type === eventType);
  if (!ev) {
    throw new Error(`no_deposit_event:${txHash}`);
  }
  return { tx, ev };
}

function normalizeAddress(a) {
  if (typeof a !== "string") return "";
  let s = a.toLowerCase();
  if (!s.startsWith("0x")) s = "0x" + s;
  // pad to 32 bytes (0x + 64 hex)
  const hex = s.slice(2);
  return "0x" + hex.padStart(64, "0");
}

// R7-OPS-1: returns true if event should be included, false if cross-vault skip
// (warns to stderr). Hard-throws for other malformed shapes. Cross-vault events
// happen when an old BridgeVault was decommissioned and re-instantiated under
// the same bridge package — events from the old vault stay in the chain feed
// but are not part of the current vault's anonymity set.
function validateEvent({ tx, ev }, expected) {
  const vaultGot = normalizeAddress(ev.data?.vault_addr);
  const vaultWant = normalizeAddress(expected.vaultAddress);
  if (vaultGot !== vaultWant) {
    if (expected.allowCrossVaultSkip === true) {
      console.error(`[skip] cross-vault event ${tx.hash}: got=${vaultGot} want=${vaultWant}`);
      return false;
    }
    throw new Error(`wrong_vault:${tx.hash}:got=${vaultGot}:want=${vaultWant}`);
  }
  // Aptos REST returns `asset_type` for an `Object<fungible_asset::Metadata>` as either:
  //   - { inner: "0xa" } — Object struct shape (canonical)
  //   - "0xa"           — bare address fallback (some fullnode versions)
  // Normalize both sides via normalizeAddress for a robust byte-equality compare.
  const assetRaw = ev.data?.asset_type;
  let assetGot;
  if (typeof assetRaw === "object" && assetRaw !== null && typeof assetRaw.inner === "string") {
    assetGot = normalizeAddress(assetRaw.inner);
  } else if (typeof assetRaw === "string") {
    assetGot = normalizeAddress(assetRaw);
  } else {
    throw new Error(`wrong_asset:${tx.hash}:unparseable_shape=${JSON.stringify(assetRaw)}`);
  }
  const assetWant = normalizeAddress(expected.assetType);
  if (assetGot !== assetWant) {
    throw new Error(`wrong_asset:${tx.hash}:got=${assetGot}:want=${assetWant}`);
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(ev.data?.commitment ?? "")) {
    throw new Error(`bad_commitment_shape:${tx.hash}:${ev.data?.commitment}`);
  }
  if (!ev.data?.deposit_count) {
    throw new Error(`missing_deposit_count:${tx.hash}`);
  }
}

async function ingest({ argv }) {
  const opts = parseArgs(argv);
  if (!opts.bridgePackageAddress) {
    console.error("--bridge-package-address required");
    printHelpAndExit(2);
  }
  if (!opts.vaultAddress) {
    console.error("--vault-address required");
    printHelpAndExit(2);
  }
  if (!opts.assetType) {
    console.error("--asset-type required");
    printHelpAndExit(2);
  }
  const bridgeNorm = normalizeAddress(opts.bridgePackageAddress);
  const assetNorm = normalizeAddress(opts.assetType);
  // Existing tree state for --refresh
  const artifactPath = join(opts.stateDir, "commitment_tree_v2.json");
  let tree;
  let existingTxHashes = new Set();
  let existingVerSeq = new Set();
  if (opts.refresh) {
    try {
      const prior = JSON.parse(readFileSync(artifactPath, "utf8"));
      tree = await CommitmentTreeV2.deserialize(prior);
      for (const m of prior.depositMeta) {
        if (m.depositTxHash) existingTxHashes.add(m.depositTxHash.toLowerCase());
        existingVerSeq.add(`${m.txVersion}:${m.sequenceNumber}`);
      }
    } catch (e) {
      if (e.code !== "ENOENT") {
        console.error(`refresh: existing artifact unreadable: ${e.message}`);
        process.exit(3);
      }
    }
  }
  if (!tree) tree = new CommitmentTreeV2(20);

  // Resolve primary tx-hash set
  const primarySet = new Set();
  if (opts.txHashes.length) {
    for (const h of opts.txHashes) primarySet.add(h.toLowerCase());
  } else {
    for (const h of loadDepositorTxHashes(opts.depositorWitnessDir)) primarySet.add(h);
  }
  // Remove already-ingested in refresh mode
  for (const h of existingTxHashes) primarySet.delete(h);

  if (primarySet.size === 0 && tree.leaves.length === 0) {
    console.error(JSON.stringify({
      error: "no_tx_hashes_to_ingest",
      hint: "supply --tx-hashes or populate the depositor witness dir",
      depositorWitnessDir: opts.depositorWitnessDir,
    }));
    process.exit(4);
  }

  // Fetch + validate each
  const harvested = [];
  for (const txHash of primarySet) {
    const { tx, ev } = await fetchDepositEventByTxHash({
      aptosNodeUrl: opts.aptosNodeUrl,
      txHash,
      bridgePackageAddress: bridgeNorm,
    });
    // R7-OPS-1: validateEvent returns false on cross-vault skip (logs to stderr).
    // Skip those events from the harvested set so old-vault txs don't pollute the
    // current-vault Merkle tree.
    const ok = validateEvent(
      { tx, ev },
      {
        vaultAddress: opts.vaultAddress,
        assetType: assetNorm,
        allowCrossVaultSkip: opts.refresh,
      },
    );
    if (ok === false) {
      continue;
    }
    const verSeq = `${tx.version}:${ev.sequence_number}`;
    if (existingVerSeq.has(verSeq)) {
      throw new Error(`replay:${txHash}:${verSeq}`);
    }
    existingVerSeq.add(verSeq);
    harvested.push({ tx, ev });
  }

  // Sort by deposit_count ascending, then verify monotonic w/ existing
  harvested.sort((a, b) =>
    Number(BigInt(a.ev.data.deposit_count) - BigInt(b.ev.data.deposit_count)),
  );
  for (let i = 0; i < harvested.length; i++) {
    const expectedCount = BigInt(tree.leaves.length + i + 1);
    const got = BigInt(harvested[i].ev.data.deposit_count);
    if (got !== expectedCount) {
      throw new Error(
        `deposit_count_gap: at index ${i}, expected ${expectedCount}, got ${got}; tx=${harvested[i].tx.hash}`,
      );
    }
  }

  // Append using LE-correct decoder
  for (const { tx, ev } of harvested) {
    const commitmentHex = ev.data.commitment.toLowerCase();
    const commitmentBig = leBytesToBig(hexToLE32(commitmentHex));
    tree.append(commitmentBig, {
      depositCount: Number(ev.data.deposit_count),
      depositTxHash: tx.hash.toLowerCase(),
      txVersion: tx.version,
      sequenceNumber: ev.sequence_number,
      sender: normalizeAddress(tx.sender),
      commitmentHex,
    });
  }

  // Optional event-feed cross-check (advisory only)
  const eventFeedNotes = [];
  if (opts.refreshFromEventFeed) {
    try {
      const feedUrl =
        `${opts.aptosNodeUrl.replace(/\/+$/, "")}` +
        `/accounts/${bridgeNorm}/events/${bridgeNorm}::eunoma_bridge::DepositConfirmedV2`;
      const feed = await fetchJson(feedUrl);
      const knownVerSeq = new Set(
        tree.depositMeta.map((m) => `${m.txVersion}:${m.sequenceNumber}`),
      );
      for (const e of feed) {
        const v = `${e.version ?? ""}:${e.sequence_number ?? ""}`;
        if (!knownVerSeq.has(v)) {
          eventFeedNotes.push(`unreconciled_feed_entry:${v}`);
        }
      }
    } catch (e) {
      eventFeedNotes.push(`feed_unavailable:${e.message}`);
    }
  }

  const snapshot = await tree.serialize();
  assertTreeArtifactPublicOnly(snapshot);

  if (opts.dryRun) {
    console.log(JSON.stringify({
      mode: "dry_run",
      leafCount: snapshot.leafCount,
      rootHex: snapshot.latestRootHex,
      transcriptHash: snapshot.transcriptHash,
      depositTxHashes: snapshot.depositMeta.map((m) => m.depositTxHash),
      distinctSenders: new Set(snapshot.depositMeta.map((m) => m.sender)).size,
      eventFeedNotes,
    }, null, 2));
    return 0;
  }

  // Atomic write
  mkdirSync(opts.stateDir, { recursive: true });
  const tmp = artifactPath + ".tmp";
  writeFileSync(tmp, JSON.stringify(snapshot, null, 2) + "\n", { mode: 0o644 });
  renameSync(tmp, artifactPath);

  console.log(JSON.stringify({
    leafCount: snapshot.leafCount,
    rootHex: snapshot.latestRootHex,
    transcriptHash: snapshot.transcriptHash,
    depositTxHashes: snapshot.depositMeta.map((m) => m.depositTxHash),
    distinctSenders: new Set(snapshot.depositMeta.map((m) => m.sender)).size,
    stateFile: artifactPath,
    eventFeedNotes,
  }, null, 2));
  return 0;
}

export {
  parseArgs,
  loadDepositorTxHashes,
  fetchDepositEventByTxHash,
  validateEvent,
  normalizeAddress,
  ingest,
};

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const code = await ingest({ argv: process.argv.slice(2) });
    process.exit(code);
  } catch (e) {
    console.error(JSON.stringify({ error: e.message ?? String(e) }));
    process.exit(1);
  }
}

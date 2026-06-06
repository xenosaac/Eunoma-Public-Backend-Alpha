#!/usr/bin/env node
// =============================================================================================
// M9-b — Build the append-only commitment tree from confirmed deposit (+ change-note) events.
//
// V2 (default): single-asset `DepositConfirmedV2`, ordered by the per-asset `deposit_count`.
// V4 (--event-version v4 / --asset-allowlist): the UNIFIED multi-asset state tree. Leaves come from
//   BOTH `DepositConfirmedV4` AND `ChangeNoteAppendedV4` (partial-withdraw change leaves), merged
//   into ONE ordered stream by the GLOBAL on-chain `leaf_index` (NOT per-asset deposit_count). The
//   cross-vault skip becomes a {assetType → vault} allowlist so all registered assets share one tree.
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
// Persisted artifacts (atomic writes, 0o644):
//   `<state-dir>/commitment_tree_v2.json`   — legacy fixed-depth-20 snapshot (kept for the
//                                              `/v2/pool/state` liveness endpoint + back-compat).
//   `<state-dir>/state_leanimt_tree.json`   — NEW dynamic-depth LeanIMT snapshot. This is the
//                                              circuit/frontend/recorder source of truth: the
//                                              recorded on-chain state root is THIS snapshot's
//                                              `latestRootHex` (see local_record_known_root_v2.mjs
//                                              + ops/scripts/refresh_known_root_cycle.sh).
//
// Both trees are built from the SAME harvested leaves/depositMeta; only the tree shape differs
// (fixed-20 vs LeanIMT dynamic). The LeanIMT snapshot is byte-parity-proven against the withdraw
// circuit + the frontend lib/protocol/leanimt.ts.
// =============================================================================================
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  COMMITMENT_TREE_SCHEME,
  CommitmentTreeV2,
  TREE_DEPTH_DEFAULT,
  assertTreeArtifactPublicOnly,
} from "../../circuits/scripts/commitment_tree_v2.mjs";
import { LeanIMTTree } from "../../circuits/scripts/leanimt_tree.mjs";
import { hexToLE32, leBytesToBig } from "../../circuits/scripts/poseidon_merkle.mjs";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..", "..");

function parseArgs(argv) {
  const out = {
    bridgePackageAddress: null,
    vaultAddress: null,
    assetType: null,
    // V4 OB1: {assetType → vault} allowlist (repeatable `--asset-allowlist assetType=vault`). When
    // set, the multi-asset unified-tree path is used: events are accepted for ANY registered asset
    // and ordered by the GLOBAL on-chain leaf_index (DepositConfirmedV4 + ChangeNoteAppendedV4).
    assetAllowlistPairs: [],
    // V4 OB1: event-schema version. "v2" (default) = single-asset DepositConfirmedV2, ordered by
    // deposit_count. "v4" = DepositConfirmedV4 (+ ChangeNoteAppendedV4), ordered by global leaf_index.
    eventVersion: "v2",
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
      case "--asset-allowlist":
        // `assetType=vault` (repeatable, or comma-separated). Implies V4 multi-asset unless an
        // explicit --event-version is given.
        out.assetAllowlistPairs.push(
          ...argv[++i].split(",").map((s) => s.trim()).filter(Boolean),
        );
        break;
      case "--event-version": out.eventVersion = String(argv[++i] ?? "").toLowerCase(); break;
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

  V4 multi-asset (unified tree, global leaf_index ordering):
  --event-version v2|v4            v2 (default)=DepositConfirmedV2, ordered by deposit_count.
                                   v4=DepositConfirmedV4 (+ ChangeNoteAppendedV4), ordered by the
                                   GLOBAL on-chain leaf_index across all assets + both leaf classes.
  --asset-allowlist A=V[,A=V..]    {assetType → vault} allowlist (repeatable). Implies --event-version
                                   v4. Accepts leaves for ANY registered asset into the one tree.
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

function parsePositiveIntEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseNonNegativeIntEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function isRetryableFullnodeStatus(status) {
  return status === 429 || status >= 500;
}

async function fetchJson(url) {
  let lastStatus = 0;
  let lastBody = "";
  const attempts = parsePositiveIntEnv("EUNOMA_APTOS_REST_RETRY_ATTEMPTS", 12);
  const delayMs = parseNonNegativeIntEnv("EUNOMA_APTOS_REST_RETRY_DELAY_MS", 5_000);
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const r = await fetch(url);
    if (r.ok) return await r.json();
    lastStatus = r.status;
    lastBody = await r.text().catch(() => "");
    if (!isRetryableFullnodeStatus(r.status) || attempt >= attempts) break;
    console.error(
      `[fullnode] retryable status=${r.status} for ${url}; ` +
        `retrying attempt ${attempt + 1}/${attempts} in ${delayMs * attempt}ms`,
    );
    await new Promise((resolve) => setTimeout(resolve, delayMs * attempt));
  }
  throw new Error(`http_${lastStatus}:${url}:${lastBody.slice(0, 200)}`);
}

// V4 OB1: harvest ALL leaf-producing events from one confirmed tx. In V2 single-asset mode that is
// exactly one DepositConfirmedV2 (back-compat: `ev` is the single deposit event). In V4 mode a tx
// may carry the retained DepositConfirmedV2 deposit event and/or a ChangeNoteAppendedV4 (a partial
// withdraw emits the change leaf in the same tx), so we return every matching leaf event as
// `leafEvents[]`, each tagged with its `kind` and the global ordering index it claims.
async function fetchDepositEventByTxHash({ aptosNodeUrl, txHash, bridgePackageAddress, eventVersion = "v2" }) {
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
  const prefix = `${bridgePackageAddress}::eunoma_bridge`;
  if (eventVersion === "v4") {
    const leafEvents = [];
    for (const e of tx.events ?? []) {
      if (e.type === `${prefix}::DepositConfirmedV4` || e.type === `${prefix}::DepositConfirmedV2`) {
        leafEvents.push({ kind: "deposit", ev: e });
      }
      else if (e.type === `${prefix}::ChangeNoteAppendedV4`) leafEvents.push({ kind: "change", ev: e });
    }
    if (leafEvents.length === 0) {
      return { tx, ev: null, leafEvents, skippedNoLeafEvent: true };
    }
    // `ev` kept for back-compat with single-event callers; first leaf event of the tx.
    return { tx, ev: leafEvents[0].ev, leafEvents, skippedNoLeafEvent: false };
  }
  // V2 single-asset default.
  const eventType = `${prefix}::DepositConfirmedV2`;
  const ev = tx.events?.find((e) => e.type === eventType);
  if (!ev) {
    throw new Error(`no_deposit_event:${txHash}`);
  }
  return { tx, ev, leafEvents: [{ kind: "deposit", ev }] };
}

function normalizeAddress(a) {
  if (typeof a !== "string") return "";
  let s = a.toLowerCase();
  if (!s.startsWith("0x")) s = "0x" + s;
  // pad to 32 bytes (0x + 64 hex)
  const hex = s.slice(2);
  return "0x" + hex.padStart(64, "0");
}

// Normalize an Aptos REST `asset_type` field (Object<Metadata>) into a padded 32-byte address.
//   - { inner: "0xa" } — Object struct shape (canonical)
//   - "0xa"           — bare address fallback (some fullnode versions)
function parseEventAssetType(assetRaw, txHash) {
  if (typeof assetRaw === "object" && assetRaw !== null && typeof assetRaw.inner === "string") {
    return normalizeAddress(assetRaw.inner);
  }
  if (typeof assetRaw === "string") {
    return normalizeAddress(assetRaw);
  }
  throw new Error(`wrong_asset:${txHash}:unparseable_shape=${JSON.stringify(assetRaw)}`);
}

async function commitmentTreeFromRefreshSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object") {
    throw new Error("refresh_snapshot_missing");
  }
  if (snapshot.scheme === COMMITMENT_TREE_SCHEME) {
    return await CommitmentTreeV2.deserialize(snapshot);
  }
  if (snapshot.scheme !== "eunoma_leanimt_tree_v1") {
    throw new Error(`scheme_mismatch: ${snapshot.scheme}`);
  }
  if (!Array.isArray(snapshot.leaves) || !Array.isArray(snapshot.depositMeta)) {
    throw new Error("leaves_or_depositMeta_missing");
  }
  if (snapshot.leaves.length !== snapshot.depositMeta.length) {
    throw new Error(
      `length_mismatch: leaves=${snapshot.leaves.length} meta=${snapshot.depositMeta.length}`,
    );
  }
  if (snapshot.leafCount !== snapshot.leaves.length) {
    throw new Error(
      `leafCount_mismatch: declared=${snapshot.leafCount} actual=${snapshot.leaves.length}`,
    );
  }

  const tree = new CommitmentTreeV2(TREE_DEPTH_DEFAULT);
  tree.createdAtUnixMs = snapshot.createdAtUnixMs ?? Date.now();
  for (let i = 0; i < snapshot.leaves.length; i++) {
    const leafHex = snapshot.leaves[i];
    const meta = snapshot.depositMeta[i] ?? {};
    const commitmentHex = meta.commitmentHex ?? leafHex;
    tree.append(leBytesToBig(hexToLE32(leafHex)), {
      leafIndex: typeof meta.leafIndex === "number" ? meta.leafIndex : i,
      kind: meta.kind,
      assetType: meta.assetType,
      depositCount:
        typeof meta.depositCount === "number"
          ? meta.depositCount
          : typeof meta.count === "number"
            ? meta.count
            : 0,
      depositTxHash: meta.depositTxHash,
      txVersion: meta.txVersion,
      sequenceNumber: meta.sequenceNumber,
      sender: meta.sender,
      commitmentHex,
    });
  }
  return tree;
}

// R7-OPS-1 / V4 OB1: returns true if the event should be included, false if it is an out-of-scope
// (cross-vault / non-allow-listed-asset) skip (warns to stderr). Hard-throws for malformed shapes.
//
// V4 multi-asset: the cross-vault skip flips from a single "skip other-vault" check to a
// {assetType → vault} ALLOWLIST. An event is in-scope iff its (asset_type, vault_addr) pair matches
// a registered (asset_type → vault) entry. In the unified-tree topology T1 every asset shares ONE
// vault account, so the allowlist is {assetA→V, assetB→V, ...}; cross-asset leaves co-exist in one
// tree. A single-asset deploy degenerates to a one-entry allowlist (back-compat).
function validateEvent({ tx, ev }, expected) {
  const vaultGot = normalizeAddress(ev.data?.vault_addr);
  const assetGot = parseEventAssetType(ev.data?.asset_type, tx.hash);
  const commitmentHex = ev.data?.commitment ?? ev.data?.change_commitment;

  // Resolve the in-scope vault for this asset. Prefer a NON-EMPTY multi-asset allowlist; fall back
  // to the single-asset {assetType, vaultAddress} pair for legacy callers (an empty allowlist Map
  // is not authoritative).
  const allowlist =
    expected.assetAllowlist instanceof Map && expected.assetAllowlist.size > 0
      ? expected.assetAllowlist
      : expected.assetType
        ? new Map([[normalizeAddress(expected.assetType), normalizeAddress(expected.vaultAddress)]])
        : null;
  if (!allowlist) {
    throw new Error(`no_asset_scope:${tx.hash}:supply assetAllowlist or assetType+vaultAddress`);
  }

  const vaultWant = allowlist.get(assetGot);
  if (vaultWant === undefined) {
    // Asset not in the registry allowlist → out-of-scope leaf, skip (multi-asset filter).
    if (expected.allowCrossVaultSkip === true) {
      console.error(`[skip] non-allow-listed asset event ${tx.hash}: asset=${assetGot}`);
      return false;
    }
    throw new Error(`wrong_asset:${tx.hash}:asset=${assetGot}:not_in_allowlist`);
  }
  if (ev.data?.vault_addr !== undefined && vaultGot !== vaultWant) {
    // Asset is registered but the vault differs → stale/decommissioned vault for this asset, skip.
    if (expected.allowCrossVaultSkip === true) {
      console.error(`[skip] cross-vault event ${tx.hash}: asset=${assetGot} got=${vaultGot} want=${vaultWant}`);
      return false;
    }
    throw new Error(`wrong_vault:${tx.hash}:asset=${assetGot}:got=${vaultGot}:want=${vaultWant}`);
  }

  if (!/^0x[0-9a-fA-F]{64}$/.test(commitmentHex ?? "")) {
    throw new Error(`bad_commitment_shape:${tx.hash}:${commitmentHex}`);
  }
  // ChangeNoteAppendedV4 carries leaf_index. V4 deposit currently retains DepositConfirmedV2 and
  // reuses deposit_count as the global ordering key. Require at least one ordering key.
  if (ev.data?.leaf_index === undefined && ev.data?.deposit_count === undefined) {
    throw new Error(`missing_leaf_index_and_deposit_count:${tx.hash}`);
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

  // V4 OB1: build the {assetType → vault} allowlist + decide V2-vs-V4 ingestion.
  //   - V4 mode iff an explicit --asset-allowlist is supplied OR --event-version v4.
  //   - In V4 mode, leaves are ordered by the GLOBAL on-chain leaf_index (deposits + change notes,
  //     multi-asset, one unified tree). In V2 mode, by the single-asset deposit_count.
  const assetAllowlist = new Map();
  for (const pair of opts.assetAllowlistPairs) {
    const [aRaw, vRaw] = pair.split("=");
    if (!aRaw || !vRaw) {
      console.error(`--asset-allowlist entry must be assetType=vault, got "${pair}"`);
      printHelpAndExit(2);
    }
    assetAllowlist.set(normalizeAddress(aRaw), normalizeAddress(vRaw));
  }
  const v4Mode = opts.eventVersion === "v4" || assetAllowlist.size > 0;
  if (v4Mode && assetAllowlist.size === 0) {
    // --event-version v4 without an explicit allowlist: seed it from the single --asset-type/vault.
    assetAllowlist.set(assetNorm, normalizeAddress(opts.vaultAddress));
  }
  const eventVersion = v4Mode ? "v4" : "v2";

  // Existing tree state for --refresh
  const artifactPath = join(opts.stateDir, "commitment_tree_v2.json");
  const leanArtifactPath = join(opts.stateDir, "state_leanimt_tree.json");
  let tree;
  let existingTxHashes = new Set();
  let existingVerSeq = new Set();
  if (opts.refresh) {
    try {
      const refreshPath = existsSync(artifactPath) ? artifactPath : leanArtifactPath;
      const prior = JSON.parse(readFileSync(refreshPath, "utf8"));
      tree = await commitmentTreeFromRefreshSnapshot(prior);
      for (const m of tree.depositMeta) {
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

  // The ordering key: V4 = global 1-based leaf order (retained DepositConfirmedV2.deposit_count
  // for deposits, ChangeNoteAppendedV4.leaf_index for changes); V2 = per-asset deposit_count.
  const orderKeyOf = (ev) =>
    v4Mode ? BigInt(ev.data.leaf_index ?? ev.data.deposit_count) : BigInt(ev.data.deposit_count);

  // Fetch + validate each. In V4 mode a single tx can carry multiple leaf events (a
  // DepositConfirmedV4 and/or a ChangeNoteAppendedV4); each becomes its own harvested entry.
  const harvested = [];
  const eventFeedNotes = [];
  for (const txHash of primarySet) {
    const { tx, leafEvents } = await fetchDepositEventByTxHash({
      aptosNodeUrl: opts.aptosNodeUrl,
      txHash,
      bridgePackageAddress: bridgeNorm,
      eventVersion,
    });
    if (leafEvents.length === 0) {
      if (v4Mode) {
        eventFeedNotes.push(`skipped_no_leaf_event:${tx.hash.toLowerCase()}`);
        continue;
      }
      throw new Error(`no_deposit_event:${txHash}`);
    }
    for (const { kind, ev } of leafEvents) {
      // R7-OPS-1 / V4 OB1: validateEvent returns false on out-of-scope skip (cross-vault or
      // non-allow-listed asset). Skip those so stale/foreign leaves don't pollute the tree.
      const ok = validateEvent(
        { tx, ev },
        {
          // single-asset back-compat fields + the multi-asset allowlist (V4)
          vaultAddress: opts.vaultAddress,
          assetType: assetNorm,
          assetAllowlist,
          allowCrossVaultSkip: opts.refresh,
        },
      );
      if (ok === false) {
        continue;
      }
      // Each leaf event is uniquely keyed by (tx.version, ev.sequence_number) for replay dedup.
      const verSeq = `${tx.version}:${ev.sequence_number}`;
      if (existingVerSeq.has(verSeq)) {
        throw new Error(`replay:${txHash}:${verSeq}`);
      }
      existingVerSeq.add(verSeq);
      harvested.push({ tx, ev, kind });
    }
  }

  // Sort by the ordering key ascending, then verify dense-monotonic vs existing leaves.
  harvested.sort((a, b) => Number(orderKeyOf(a.ev) - orderKeyOf(b.ev)));
  const appendableHarvested = [];
  // V4 Move emits GLOBAL 1-based indexes (core.next_leaf_index is incremented before emit).
  // V2: deposit_count is 1-based dense ⇒ next expected = leaf count + 1.
  let expected = BigInt(tree.leaves.length + 1);
  const gapLabel = v4Mode ? "leaf_index_gap" : "deposit_count_gap";
  for (let i = 0; i < harvested.length; i++) {
    const got = orderKeyOf(harvested[i].ev);
    if (got < expected && opts.refresh) {
      eventFeedNotes.push(
        `stale_${gapLabel}:expected_at_least:${expected}:got:${got}:tx:${harvested[i].tx.hash}`,
      );
      continue;
    }
    if (got === expected) {
      appendableHarvested.push(harvested[i]);
      expected += 1n;
      continue;
    }
    if (opts.refresh) {
      eventFeedNotes.push(
        `deferred_${gapLabel}:expected:${expected}:got:${got}:tx:${harvested[i].tx.hash}`,
      );
      continue;
    }
    if (got !== expected) {
      throw new Error(
        `${gapLabel}: at index ${i}, expected ${expected}, got ${got}; tx=${harvested[i].tx.hash}`,
      );
    }
  }

  // Append using LE-correct decoder.
  for (const { tx, ev, kind } of appendableHarvested) {
    const commitmentHex = (ev.data.commitment ?? ev.data.change_commitment).toLowerCase();
    const commitmentBig = leBytesToBig(hexToLE32(commitmentHex));
    const assetGot = parseEventAssetType(ev.data?.asset_type, tx.hash);
    const orderKey = orderKeyOf(ev);
    tree.append(commitmentBig, {
      // V4: explicit global leaf_index ordering key. V2: legacy 1-based depositCount (mapped to a
      // 0-based global index inside CommitmentTreeV2.append).
      leafIndex: v4Mode ? Number(orderKey - 1n) : undefined,
      kind, // "deposit" | "change"
      assetType: assetGot,
      // Per-asset observer cursor (change-note leaves carry none).
      depositCount:
        ev.data.deposit_count !== undefined ? Number(ev.data.deposit_count) : undefined,
      depositTxHash: tx.hash.toLowerCase(),
      txVersion: tx.version,
      sequenceNumber: ev.sequence_number,
      sender: normalizeAddress(tx.sender),
      commitmentHex,
    });
  }

  // Optional event-feed cross-check (advisory only)
  if (opts.refreshFromEventFeed) {
    try {
      const feedEventName = v4Mode ? "DepositConfirmedV4" : "DepositConfirmedV2";
      const feedUrl =
        `${opts.aptosNodeUrl.replace(/\/+$/, "")}` +
        `/accounts/${bridgeNorm}/events/${bridgeNorm}::eunoma_bridge::${feedEventName}`;
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

  // Build the dynamic-depth LeanIMT over the SAME leaves (in deposit_count order) — this is the
  // circuit/frontend/recorder source-of-truth snapshot. Its `latestRootHex` is what the on-chain
  // state root recorder commits (NOT the fixed-20 root above).
  const leanTree = new LeanIMTTree();
  for (let i = 0; i < tree.leaves.length; i++) {
    const m = tree.depositMeta[i];
    leanTree.append(tree.leaves[i], {
      commitmentHex: m.commitmentHex,
      sender: m.sender,
      depositTxHash: m.depositTxHash,
      txVersion: m.txVersion,
      sequenceNumber: m.sequenceNumber,
    });
  }
  // The unified state tree's leaf order IS the fixed-20 snapshot's order (both built from the same
  // leaf_index-ordered leaf stream), so the LeanIMT root is the canonical state root recorded on-chain.
  const leanSnapshot = await leanTree.serialize();
  if (eventFeedNotes.length > 0) {
    snapshot.eventFeedNotes = eventFeedNotes;
    leanSnapshot.eventFeedNotes = eventFeedNotes;
  }
  assertTreeArtifactPublicOnly(snapshot);
  assertTreeArtifactPublicOnly(leanSnapshot);

  if (opts.dryRun) {
    console.log(JSON.stringify({
      mode: "dry_run",
      leafCount: snapshot.leafCount,
      rootHex: snapshot.latestRootHex,
      transcriptHash: snapshot.transcriptHash,
      leanImtRootHex: leanSnapshot.latestRootHex,
      leanImtTreeDepth: leanSnapshot.treeDepth,
      depositTxHashes: snapshot.depositMeta.map((m) => m.depositTxHash),
      distinctSenders: new Set(snapshot.depositMeta.map((m) => m.sender)).size,
      eventFeedNotes,
    }, null, 2));
    return 0;
  }

  // Atomic writes — both the legacy fixed-20 snapshot and the LeanIMT snapshot.
  mkdirSync(opts.stateDir, { recursive: true });
  const tmp = artifactPath + ".tmp";
  writeFileSync(tmp, JSON.stringify(snapshot, null, 2) + "\n", { mode: 0o644 });
  renameSync(tmp, artifactPath);

  const leanTmp = leanArtifactPath + ".tmp";
  writeFileSync(leanTmp, JSON.stringify(leanSnapshot, null, 2) + "\n", { mode: 0o644 });
  renameSync(leanTmp, leanArtifactPath);

  console.log(JSON.stringify({
    leafCount: snapshot.leafCount,
    rootHex: snapshot.latestRootHex,
    transcriptHash: snapshot.transcriptHash,
    leanImtRootHex: leanSnapshot.latestRootHex,
    leanImtTreeDepth: leanSnapshot.treeDepth,
    depositTxHashes: snapshot.depositMeta.map((m) => m.depositTxHash),
    distinctSenders: new Set(snapshot.depositMeta.map((m) => m.sender)).size,
    stateFile: artifactPath,
    leanImtStateFile: leanArtifactPath,
    eventFeedNotes,
  }, null, 2));
  return 0;
}

export {
  parseArgs,
  loadDepositorTxHashes,
  fetchDepositEventByTxHash,
  validateEvent,
  parseEventAssetType,
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

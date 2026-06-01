import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "ops",
  "scripts",
  "refresh_known_root_cycle.sh",
);

const OLD_ROOT = `0x${"11".repeat(32)}`;
const NEW_ROOT = `0x${"22".repeat(32)}`;
const FETCH_TX_A = `0x${"aa".repeat(32)}`;
const FETCH_TX_B = `0x${"bb".repeat(32)}`;
const EXTRA_TX = `0x${"ee".repeat(32)}`;

let tmpRoot;
let repoRoot;
let stateDir;
let fakeBin;
let fakeFetchScript;
let opLogPath;
let txHashLogPath;

beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "eunoma-refresh-cycle-"));
  repoRoot = join(tmpRoot, "repo");
  stateDir = join(tmpRoot, "state");
  fakeBin = join(tmpRoot, "bin");
  fakeFetchScript = join(tmpRoot, "fetch_deposit_tx_hashes.sh");
  opLogPath = join(tmpRoot, "ops.log");
  txHashLogPath = join(tmpRoot, "tx-hashes.log");
  mkdirSync(repoRoot, { recursive: true });
  mkdirSync(stateDir, { recursive: true });
  mkdirSync(fakeBin, { recursive: true });
  writeTree(OLD_ROOT, 8);
  writeFakeNode();
  writeFileSync(join(fakeBin, "flock"), "#!/usr/bin/env bash\nexit 0\n");
  chmodSync(join(fakeBin, "flock"), 0o755);
  writeFileSync(fakeFetchScript, `#!/usr/bin/env bash\nprintf '${FETCH_TX_A},${FETCH_TX_B}\\n'\n`);
  chmodSync(fakeFetchScript, 0o755);
});

afterEach(() => {
  if (tmpRoot) rmSync(tmpRoot, { recursive: true, force: true });
});

describe("refresh_known_root_cycle.sh route-ready publication", () => {
  it("keeps the public tree unchanged when record_known_root fails", () => {
    const result = runWrapper({ FAKE_RECORD_FAIL: "1", FAKE_TREE_ROOT: NEW_ROOT });

    expect(result.status).toBe(31);
    expect(readTree().latestRootHex).toBe(OLD_ROOT);
    expect(existsSync(join(stateDir, ".refresh-staging", "commitment_tree_v2.json"))).toBe(true);
    expect(result.stdout).toContain("build staged tree");
    expect(result.stdout).toContain("record known root");
    expect(result.stdout).not.toContain("publish tree");
    expect(readOps()).toEqual(["normalize", "build", "rollover", "normalize", "record"]);
  });

  it("publishes the staged tree only after rollover, normalize, and record succeed", () => {
    const result = runWrapper({ FAKE_TREE_ROOT: NEW_ROOT });

    expect(result.status).toBe(0);
    expect(readTree().latestRootHex).toBe(NEW_ROOT);
    expect(existsSync(join(stateDir, ".refresh-staging"))).toBe(false);
    expect(result.stdout).toContain("build staged tree");
    expect(result.stdout).toContain("rollover");
    expect(result.stdout).toContain("record known root");
    expect(result.stdout).toContain("publish tree");
    expect(result.stdout).toContain("done");
    expect(readOps()).toEqual(["normalize", "build", "rollover", "normalize", "record", "asp"]);
  });

  it("skips rollover for a root with an existing sidecar and still finishes cleanly", () => {
    const prefix = NEW_ROOT.replace(/^0x/, "").slice(0, 8);
    writeFileSync(join(stateDir, `known_root_v2_${prefix}.json`), "{}\n");

    const result = runWrapper({ FAKE_TREE_ROOT: NEW_ROOT, FAKE_RECORD_STATUS: "already_recorded" });

    expect(result.status).toBe(0);
    expect(readTree().latestRootHex).toBe(NEW_ROOT);
    expect(result.stdout).toContain("already has side-car; skipping rollover");
    expect(result.stdout).toContain("publish tree");
    expect(readOps()).toEqual(["normalize", "build", "record", "asp"]);
  });

  it("uses an extra observed deposit hash when the indexer fetch has not listed it yet", () => {
    writeFileSync(fakeFetchScript, "#!/usr/bin/env bash\nexit 0\n");
    chmodSync(fakeFetchScript, 0o755);

    const result = runWrapper({
      FAKE_TREE_ROOT: NEW_ROOT,
      EUNOMA_EXTRA_DEPOSIT_TX_HASHES: EXTRA_TX,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("queued 1 observed tx hashes for durable retry");
    expect(result.stdout).toContain("including 1 persisted observed tx hashes");
    expect(readTree().latestRootHex).toBe(NEW_ROOT);
    expect(readTxHashes()).toBe(EXTRA_TX);
    expect(readQueue()).toBe("");
    expect(readOps()).toEqual(["normalize", "build", "rollover", "normalize", "record", "asp"]);
  });

  it("deduplicates extra observed hashes before building the staged tree", () => {
    const mixedCaseExtra = FETCH_TX_A.toUpperCase().replace(/^0X/, "0x");
    const result = runWrapper({
      FAKE_TREE_ROOT: NEW_ROOT,
      EUNOMA_EXTRA_DEPOSIT_TX_HASHES: `${mixedCaseExtra},${EXTRA_TX},not-a-tx`,
    });

    expect(result.status).toBe(0);
    expect(readTxHashes()).toBe(`${FETCH_TX_A},${EXTRA_TX},${FETCH_TX_B}`);
  });

  it("keeps observed deposit hashes queued when route-ready publication fails", () => {
    writeFileSync(fakeFetchScript, "#!/usr/bin/env bash\nexit 0\n");
    chmodSync(fakeFetchScript, 0o755);

    const result = runWrapper({
      FAKE_RECORD_FAIL: "1",
      FAKE_TREE_ROOT: NEW_ROOT,
      EUNOMA_EXTRA_DEPOSIT_TX_HASHES: EXTRA_TX,
    });

    expect(result.status).toBe(31);
    expect(readQueue()).toBe(EXTRA_TX);
  });

  it("retries persisted observed hashes on the next cycle without a new HTTP trigger", () => {
    writeFileSync(fakeFetchScript, "#!/usr/bin/env bash\nexit 0\n");
    chmodSync(fakeFetchScript, 0o755);
    writeFileSync(join(stateDir, "observed_deposit_tx_hashes.queue"), `${EXTRA_TX}\n`);

    const result = runWrapper({ FAKE_TREE_ROOT: NEW_ROOT });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("including 1 persisted observed tx hashes");
    expect(readTxHashes()).toBe(EXTRA_TX);
    expect(readQueue()).toBe("");
  });

  it("derives coordinator state dir from EUNOMA_STATE_ROOT when no explicit state dir is set", () => {
    const stateRoot = join(tmpRoot, "state-root");
    stateDir = join(stateRoot, "coordinator");
    mkdirSync(stateDir, { recursive: true });
    writeTree(OLD_ROOT, 8);

    const result = runWrapper({
      FAKE_TREE_ROOT: NEW_ROOT,
      EUNOMA_COORDINATOR_STATE_DIR: "",
      EUNOMA_STATE_ROOT: stateRoot,
    });

    expect(result.status).toBe(0);
    expect(readTree().latestRootHex).toBe(NEW_ROOT);
  });
});

function runWrapper(env = {}) {
  return spawnSync("bash", [SCRIPT_PATH], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fakeBin}:${process.env.PATH}`,
      REAL_NODE_PATH: process.execPath,
      FAKE_OP_LOG: opLogPath,
      FAKE_TX_HASH_LOG: txHashLogPath,
      EUNOMA_REPO_ROOT: repoRoot,
      EUNOMA_COORDINATOR_STATE_DIR: stateDir,
      EUNOMA_FETCH_DEPOSIT_TX_HASHES_SCRIPT: fakeFetchScript,
      EUNOMA_REFRESH_KNOWN_ROOT_LOCK: join(tmpRoot, "refresh.lock"),
      BRIDGE_PACKAGE_ADDRESS: `0x${"a".repeat(64)}`,
      BRIDGE_VAULT_ADDRESS: `0x${"b".repeat(64)}`,
      BRIDGE_ASSET_TYPE: "0xa",
      EUNOMA_MIN_ANONYMITY_SET: "8",
      CHAINALYSIS_API_KEY: "fake-test-key",
      ...env,
    },
  });
}

function writeTree(root, leafCount) {
  const leaves = Array.from({ length: leafCount }, (_, i) => `0x${String(i + 1).padStart(64, "0")}`);
  writeFileSync(
    join(stateDir, "commitment_tree_v2.json"),
    JSON.stringify(
      {
        scheme: "commitment_tree_v2_snapshot",
        treeDepth: 20,
        latestRootHex: root,
        leafCount,
        leaves,
        depositMeta: leaves.map((commitmentHex, i) => ({
          depositTxHash: `0x${String(i + 1).padStart(64, "f")}`,
          commitmentHex,
        })),
        transcriptHash: `0x${"33".repeat(32)}`,
      },
      null,
      2,
    ),
  );
}

function readTree() {
  return JSON.parse(readFileSync(join(stateDir, "commitment_tree_v2.json"), "utf8"));
}

function readOps() {
  if (!existsSync(opLogPath)) return [];
  return readFileSync(opLogPath, "utf8").trim().split(/\n/).filter(Boolean);
}

function readTxHashes() {
  if (!existsSync(txHashLogPath)) return "";
  return readFileSync(txHashLogPath, "utf8").trim();
}

function readQueue() {
  const p = join(stateDir, "observed_deposit_tx_hashes.queue");
  if (!existsSync(p)) return "";
  return readFileSync(p, "utf8").trim();
}

function writeFakeNode() {
  const implPath = join(tmpRoot, "fake_node_impl.mjs");
  writeFileSync(
    implPath,
    `
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";

const args = process.argv.slice(2);
const script = args[0] ?? "";
const opLog = process.env.FAKE_OP_LOG;
function append(op) {
  appendFileSync(opLog, op + "\\n");
}
function valueOf(flag) {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

if (script.endsWith("local_v2_normalize_full.mjs")) {
  append("normalize");
  process.exit(0);
}
if (script.endsWith("local_build_commitment_tree.mjs")) {
  append("build");
  const txHashes = (valueOf("--tx-hashes") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  writeFileSync(process.env.FAKE_TX_HASH_LOG, txHashes.join(",") + "\\n");
  const stateDir = valueOf("--state-dir");
  mkdirSync(stateDir, { recursive: true });
  const leafCount = Number(process.env.FAKE_TREE_LEAF_COUNT ?? "9");
  const leaves = Array.from({ length: leafCount }, (_, i) => "0x" + String(i + 1).padStart(64, "0"));
  writeFileSync(
    stateDir + "/commitment_tree_v2.json",
    JSON.stringify(
      {
        scheme: "commitment_tree_v2_snapshot",
        treeDepth: 20,
        latestRootHex: process.env.FAKE_TREE_ROOT,
        leafCount,
        leaves,
        depositMeta: leaves.map((commitmentHex, i) => ({
          depositTxHash: txHashes[i] ?? "0x" + String(i + 1).padStart(64, "a"),
          commitmentHex,
          sender: "0x" + String(i + 1).padStart(64, "b"),
        })),
        transcriptHash: "0x" + "44".repeat(32),
      },
      null,
      2,
    ) + "\\n",
  );
  // The real builder also emits the LeanIMT snapshot; the wrapper records ITS root.
  writeFileSync(
    stateDir + "/state_leanimt_tree.json",
    JSON.stringify(
      {
        scheme: "eunoma_leanimt_tree_v1",
        version: 1,
        treeDepth: 4,
        latestRootHex: process.env.FAKE_TREE_ROOT,
        leafCount,
        leaves,
        depositMeta: leaves.map((commitmentHex, i) => ({
          commitmentHex,
          depositTxHash: txHashes[i] ?? "0x" + String(i + 1).padStart(64, "a"),
          sender: "0x" + String(i + 1).padStart(64, "b"),
        })),
        transcriptHash: "0x" + "55".repeat(32),
      },
      null,
      2,
    ) + "\\n",
  );
  process.exit(0);
}
if (script.endsWith("local_rollover_vault_pending.mjs")) {
  append("rollover");
  process.exit(0);
}
if (script.endsWith("local_record_known_root_v2.mjs")) {
  append("record");
  if (process.env.FAKE_RECORD_FAIL === "1") {
    console.error("fake record_known_root failure");
    process.exit(31);
  }
  process.stdout.write(JSON.stringify({ ok: true, status: process.env.FAKE_RECORD_STATUS ?? "recorded" }) + "\\n");
  process.exit(0);
}
if (script.endsWith("local_run_asp_cycle.mjs")) {
  append("asp");
  const aspSetOut = valueOf("--asp-set-out");
  if (aspSetOut) {
    writeFileSync(
      aspSetOut,
      JSON.stringify(
        {
          scheme: "eunoma_asp_set_v1",
          rootHex: process.env.FAKE_ASP_ROOT ?? process.env.FAKE_TREE_ROOT,
          treeDepth: 4,
          commitments: [],
          ipfsCid: "local-test-cid",
        },
        null,
        2,
      ) + "\\n",
    );
  }
  process.stdout.write(JSON.stringify({ ok: true, rootHex: process.env.FAKE_ASP_ROOT ?? process.env.FAKE_TREE_ROOT }) + "\\n");
  process.exit(0);
}

console.error("unexpected fake node command: " + args.join(" "));
process.exit(97);
`,
  );

  const fakeNodePath = join(fakeBin, "node");
  writeFileSync(
    fakeNodePath,
    `#!/usr/bin/env bash
if [ "$1" = "-e" ]; then
  exec "$REAL_NODE_PATH" "$@"
fi
exec "$REAL_NODE_PATH" "${implPath}" "$@"
`,
  );
  chmodSync(fakeNodePath, 0o755);
}

// Tests for scripts/local_record_known_root_v2.mjs.
//
// Strategy: drive the CLI as a subprocess in --dry-run mode so we never call
// `aptos move run` or hit real network. We exercise the M9 anonymity gate + the
// legacy single-leaf rejection paths via stdout/exitCode.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CommitmentTreeV2 } from "../../../circuits/scripts/commitment_tree_v2.mjs";
import {
  bigToLE32,
  le32ToHex,
} from "../../../circuits/scripts/poseidon_merkle.mjs";

const SCRIPT_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "local_record_known_root_v2.mjs",
);
const BRIDGE = "0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1";

const FR_MOD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function frFromSeed(seed) {
  let v = 0n;
  for (let i = 0; i < seed.length; i++) {
    v = (v * 1099511628211n + BigInt(seed.charCodeAt(i) + i)) & ((1n << 254n) - 1n);
  }
  return v % FR_MOD;
}

async function makeTreeFixture(stateDir, leafCount) {
  const t = new CommitmentTreeV2(20);
  for (let i = 1; i <= leafCount; i++) {
    const big = frFromSeed("rec-fix-" + i);
    const commitmentHex = le32ToHex(bigToLE32(big));
    t.append(big, {
      depositCount: i,
      depositTxHash: "0x" + i.toString(16).padStart(64, "0"),
      txVersion: String(2000 + i),
      sequenceNumber: String(i),
      sender: "0x" + i.toString(16).padStart(64, "f"),
      commitmentHex,
    });
  }
  const snapshot = await t.serialize();
  const p = join(stateDir, "commitment_tree_v2.json");
  writeFileSync(p, JSON.stringify(snapshot, null, 2));
  return { path: p, snapshot };
}

function makeLegacyWitness(witnessPath, commitmentHex) {
  writeFileSync(
    witnessPath,
    JSON.stringify(
      {
        schema: "v2_depositor_witness_v1",
        commitmentHex,
        depositTxHash: "0x" + "1".repeat(64),
        depositCount: "1",
      },
      null,
      2,
    ),
  );
}

function runCli(args, env = {}) {
  return spawnSync("node", [SCRIPT_PATH, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function runCliAsync(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn("node", [SCRIPT_PATH, ...args], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      resolve({ status: null, signal: null, stdout, stderr: `${stderr}${error.message}` });
    });
    child.on("close", (status, signal) => {
      resolve({ status, signal, stdout, stderr });
    });
  });
}

function parseStdoutJson(stdout) {
  // Last JSON-shaped block at end of stdout.
  const m = stdout.match(/\{[\s\S]*\}\s*$/);
  if (!m) return null;
  try {
    return JSON.parse(m[0]);
  } catch {
    return null;
  }
}

let tmpRoot;
let stateDir;
let witnessPath;
beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "m9c-record-"));
  stateDir = join(tmpRoot, "coordinator");
  mkdirSync(stateDir, { recursive: true });
  witnessPath = join(tmpRoot, "withdraw_witness.json");
});
afterEach(() => {
  if (tmpRoot) rmSync(tmpRoot, { recursive: true, force: true });
});

describe("local_record_known_root_v2 — usage gates", () => {
  it("missing source: --commitment-tree and --deposit-witness-path both absent → exit 2", () => {
    const r = runCli(["--bridge-package-address", BRIDGE, "--dry-run"]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/supply --commitment-tree/);
  });

  it("both --commitment-tree and --deposit-witness-path supplied → exit 2", async () => {
    const { path } = await makeTreeFixture(stateDir, 8);
    makeLegacyWitness(witnessPath, "0x" + "a".repeat(64));
    const r = runCli([
      "--bridge-package-address", BRIDGE,
      "--commitment-tree", path,
      "--deposit-witness-path", witnessPath,
      "--dry-run",
    ]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/cannot pass both/);
  });

  it("missing --bridge-package-address → exit 2", () => {
    const r = runCli(["--dry-run", "--commitment-tree", "/nope"]);
    expect(r.status).toBe(2);
  });

  it("invalid --min-anonymity-set → exit 2", () => {
    const r = runCli([
      "--bridge-package-address", BRIDGE,
      "--commitment-tree", "/nope",
      "--min-anonymity-set", "not-a-number",
      "--dry-run",
    ]);
    expect(r.status).toBe(2);
  });
});

describe("local_record_known_root_v2 — M9 multi-leaf anonymity gate", () => {
  it("leafCount=8 ≥ default min 8 → dry-run succeeds with mode=multi_leaf", async () => {
    const { path, snapshot } = await makeTreeFixture(stateDir, 8);
    const r = runCli([
      "--bridge-package-address", BRIDGE,
      "--commitment-tree", path,
      "--dry-run",
    ]);
    expect(r.status).toBe(0);
    const body = parseStdoutJson(r.stdout);
    expect(body).toMatchObject({
      ok: true,
      mode: "multi_leaf",
      leafCount: 8,
      minAnonymitySet: 8,
      status: "dry_run",
    });
    expect(body.root.toLowerCase()).toBe(snapshot.latestRootHex.toLowerCase());
    expect(body.treeTranscriptHash).toBe(snapshot.transcriptHash);
  });

  it("leafCount=4 < default min 8 → exit 3 anonymity_set_too_small", async () => {
    const { path } = await makeTreeFixture(stateDir, 4);
    const r = runCli([
      "--bridge-package-address", BRIDGE,
      "--commitment-tree", path,
      "--dry-run",
    ]);
    expect(r.status).toBe(3);
    expect(r.stderr).toMatch(/anonymity_set_too_small/);
  });

  it("leafCount=4 < min 8 + EUNOMA_LOCAL_SMOKE=1 + --allow-local-smoke-anonymity → dry-run succeeds", async () => {
    const { path } = await makeTreeFixture(stateDir, 4);
    const r = runCli([
      "--bridge-package-address", BRIDGE,
      "--commitment-tree", path,
      "--allow-local-smoke-anonymity",
      "--dry-run",
    ], { EUNOMA_LOCAL_SMOKE: "1" });
    expect(r.status).toBe(0);
    const body = parseStdoutJson(r.stdout);
    expect(body.mode).toBe("multi_leaf");
    expect(body.leafCount).toBe(4);
  });

  it("leafCount=4 < min 8 + --allow-local-smoke-anonymity but EUNOMA_LOCAL_SMOKE unset → exit 3", async () => {
    const { path } = await makeTreeFixture(stateDir, 4);
    const r = runCli([
      "--bridge-package-address", BRIDGE,
      "--commitment-tree", path,
      "--allow-local-smoke-anonymity",
      "--dry-run",
    ], { EUNOMA_LOCAL_SMOKE: "" });
    expect(r.status).toBe(3);
  });

  it("EUNOMA_MIN_ANONYMITY_SET env override is honored", async () => {
    const { path } = await makeTreeFixture(stateDir, 5);
    const r = runCli([
      "--bridge-package-address", BRIDGE,
      "--commitment-tree", path,
      "--dry-run",
    ], { EUNOMA_MIN_ANONYMITY_SET: "4" });
    expect(r.status).toBe(0);
    const body = parseStdoutJson(r.stdout);
    expect(body.minAnonymitySet).toBe(4);
  });

  it("--commitment-tree pointing at tampered artifact → exit 2", async () => {
    const { path, snapshot } = await makeTreeFixture(stateDir, 8);
    const tampered = JSON.parse(JSON.stringify(snapshot));
    tampered.depositMeta[3].sender = "0x" + "9".repeat(64);
    writeFileSync(path, JSON.stringify(tampered, null, 2));
    const r = runCli([
      "--bridge-package-address", BRIDGE,
      "--commitment-tree", path,
      "--dry-run",
    ]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/transcript_hash_mismatch|deserialize/);
  });

  it("uses BridgeVaultTablesV2.known_roots precheck to skip duplicate tx submission", async () => {
    const { path, snapshot } = await makeTreeFixture(stateDir, 8);
    const fakeBin = join(tmpRoot, "bin");
    const aptosInvokedPath = join(tmpRoot, "aptos_invoked");
    mkdirSync(fakeBin, { recursive: true });
    writeFileSync(
      join(fakeBin, "aptos"),
      `#!/usr/bin/env bash
echo invoked > "${aptosInvokedPath}"
exit 99
`,
    );
    chmodSync(join(fakeBin, "aptos"), 0o755);

    let tableRequestBody = null;
    const server = createServer((req, res) => {
      if (req.method === "GET" && req.url?.includes("/accounts/") && req.url.includes("/resource/")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ data: { known_roots: { handle: "known-roots-handle" } } }));
        return;
      }
      if (req.method === "POST" && req.url?.endsWith("/tables/known-roots-handle/item")) {
        let body = "";
        req.setEncoding("utf8");
        req.on("data", (chunk) => {
          body += chunk;
        });
        req.on("end", () => {
          tableRequestBody = JSON.parse(body);
          res.writeHead(200, { "content-type": "application/json" });
          res.end("true");
        });
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end("{}");
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    try {
      const r = await runCliAsync(
        [
          "--bridge-package-address",
          BRIDGE,
          "--commitment-tree",
          path,
          "--state-dir",
          stateDir,
          "--aptos-node-url",
          `http://127.0.0.1:${port}/v1`,
        ],
        {
          PATH: `${fakeBin}:${process.env.PATH}`,
          EUNOMA_KNOWN_ROOT_PRECHECK_RETRY_ATTEMPTS: "1",
          EUNOMA_KNOWN_ROOT_PRECHECK_RETRY_DELAY_MS: "1",
        },
      );
      expect(r.status).toBe(0);
      const body = parseStdoutJson(r.stdout);
      expect(body).toMatchObject({
        ok: true,
        status: "already_recorded",
        root: snapshot.latestRootHex,
        tableHandle: "known-roots-handle",
      });
      expect(tableRequestBody).toMatchObject({
        key_type: "vector<u8>",
        value_type: "bool",
        key: snapshot.latestRootHex,
      });
      expect(existsSync(aptosInvokedPath)).toBe(false);
      const sidecar = JSON.parse(
        readFileSync(join(stateDir, `known_root_v2_${snapshot.latestRootHex.slice(2, 10)}.json`), "utf8"),
      );
      expect(sidecar).toMatchObject({
        rootHex: snapshot.latestRootHex,
        status: "already_recorded",
      });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it("defers instead of submitting when the known_roots precheck is unavailable", async () => {
    const { path } = await makeTreeFixture(stateDir, 8);
    const fakeBin = join(tmpRoot, "bin-precheck-defer");
    const aptosInvokedPath = join(tmpRoot, "aptos_precheck_defer_invoked");
    mkdirSync(fakeBin, { recursive: true });
    writeFileSync(
      join(fakeBin, "aptos"),
      `#!/usr/bin/env bash
echo invoked > "${aptosInvokedPath}"
exit 99
`,
    );
    chmodSync(join(fakeBin, "aptos"), 0o755);

    const server = createServer((_req, res) => {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: "fullnode unavailable" }));
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    try {
      const r = await runCliAsync(
        [
          "--bridge-package-address",
          BRIDGE,
          "--commitment-tree",
          path,
          "--state-dir",
          stateDir,
          "--aptos-node-url",
          `http://127.0.0.1:${port}/v1`,
        ],
        {
          PATH: `${fakeBin}:${process.env.PATH}`,
          EUNOMA_KNOWN_ROOT_PRECHECK_RETRY_ATTEMPTS: "1",
          EUNOMA_KNOWN_ROOT_PRECHECK_RETRY_DELAY_MS: "1",
        },
      );
      expect(r.status).toBe(32);
      expect(r.stderr).toMatch(/not submitting duplicate-prone record_known_root tx/);
      expect(existsSync(aptosInvokedPath)).toBe(false);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it("retries transient fullnode 429 during known_roots precheck before submitting", async () => {
    const { path, snapshot } = await makeTreeFixture(stateDir, 8);
    const fakeBin = join(tmpRoot, "bin-precheck-429-retry");
    mkdirSync(fakeBin, { recursive: true });
    const txHash = "0x" + "c".repeat(64);
    writeFileSync(
      join(fakeBin, "aptos"),
      `#!/usr/bin/env bash
cat <<'JSON'
{
  "Result": {
    "transaction_hash": "${txHash}"
  }
}
JSON
exit 0
`,
    );
    chmodSync(join(fakeBin, "aptos"), 0o755);

    let tableResourceRequests = 0;
    let tableItemRequests = 0;
    const server = createServer((req, res) => {
      if (req.method === "GET" && req.url?.includes("/accounts/") && req.url.includes("/resource/")) {
        tableResourceRequests += 1;
        if (tableResourceRequests < 3) {
          res.writeHead(429, { "content-type": "application/json" });
          res.end(JSON.stringify({ message: "rate limited" }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ data: { known_roots: { handle: "known-roots-handle" } } }));
        return;
      }
      if (req.method === "POST" && req.url?.endsWith("/tables/known-roots-handle/item")) {
        tableItemRequests += 1;
        res.writeHead(404, { "content-type": "application/json" });
        res.end("{}");
        return;
      }
      if (req.method === "GET" && req.url?.startsWith(`/v1/transactions/by_hash/${txHash}`)) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            type: "user_transaction",
            version: "9999",
            success: true,
            vm_status: "Executed successfully",
            events: [
              {
                type: `${BRIDGE}::eunoma_bridge::RootRecordedV2`,
                data: { root: snapshot.latestRootHex },
              },
            ],
          }),
        );
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end("{}");
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    try {
      const r = await runCliAsync(
        [
          "--bridge-package-address",
          BRIDGE,
          "--commitment-tree",
          path,
          "--state-dir",
          stateDir,
          "--aptos-node-url",
          `http://127.0.0.1:${port}/v1`,
        ],
        {
          PATH: `${fakeBin}:${process.env.PATH}`,
          EUNOMA_KNOWN_ROOT_PRECHECK_RETRY_ATTEMPTS: "4",
          EUNOMA_KNOWN_ROOT_PRECHECK_RETRY_DELAY_MS: "1",
        },
      );
      expect(r.status).toBe(0);
      expect(r.stderr).not.toMatch(/not submitting duplicate-prone record_known_root tx/);
      expect(tableResourceRequests).toBe(3);
      expect(tableItemRequests).toBe(1);
      const body = parseStdoutJson(r.stdout);
      expect(body).toMatchObject({
        ok: true,
        status: "recorded",
        root: snapshot.latestRootHex,
        txHash,
        eventVerified: true,
      });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it("can preserve legacy submit-on-precheck-failure behavior behind an explicit env override", async () => {
    const { path } = await makeTreeFixture(stateDir, 8);
    const fakeBin = join(tmpRoot, "bin-precheck-override");
    const aptosInvokedPath = join(tmpRoot, "aptos_precheck_override_invoked");
    mkdirSync(fakeBin, { recursive: true });
    writeFileSync(
      join(fakeBin, "aptos"),
      `#!/usr/bin/env bash
echo invoked > "${aptosInvokedPath}"
exit 99
`,
    );
    chmodSync(join(fakeBin, "aptos"), 0o755);

    const server = createServer((_req, res) => {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: "fullnode unavailable" }));
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    try {
      const r = await runCliAsync(
        [
          "--bridge-package-address",
          BRIDGE,
          "--commitment-tree",
          path,
          "--state-dir",
          stateDir,
          "--aptos-node-url",
          `http://127.0.0.1:${port}/v1`,
        ],
        {
          PATH: `${fakeBin}:${process.env.PATH}`,
          EUNOMA_RECORD_KNOWN_ROOT_SUBMIT_ON_PRECHECK_FAILURE: "1",
          EUNOMA_KNOWN_ROOT_PRECHECK_RETRY_ATTEMPTS: "1",
          EUNOMA_KNOWN_ROOT_PRECHECK_RETRY_DELAY_MS: "1",
        },
      );
      expect(r.status).toBe(31);
      expect(r.stderr).toMatch(/submitting anyway because EUNOMA_RECORD_KNOWN_ROOT_SUBMIT_ON_PRECHECK_FAILURE=1/);
      expect(existsSync(aptosInvokedPath)).toBe(true);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});

describe("local_record_known_root_v2 — legacy single-leaf rejection", () => {
  it("--deposit-witness-path without local smoke → exit 4 legacy_single_leaf_rejected_on_testnet", () => {
    const commitmentHex = "0x" + "a".repeat(64);
    makeLegacyWitness(witnessPath, commitmentHex);
    const r = runCli([
      "--bridge-package-address", BRIDGE,
      "--deposit-witness-path", witnessPath,
      "--dry-run",
    ]);
    expect(r.status).toBe(4);
    expect(r.stderr).toMatch(/legacy_single_leaf_rejected_on_testnet/);
  });

  it("--deposit-witness-path + EUNOMA_LOCAL_SMOKE=1 + --allow-local-smoke-anonymity → dry-run succeeds, mode=legacy_single_leaf", () => {
    // Fr-safe commitment (we used frFromSeed above; here we just use one matching the depositor witness)
    const big = frFromSeed("legacy-leaf");
    const commitmentHex = le32ToHex(bigToLE32(big));
    makeLegacyWitness(witnessPath, commitmentHex);
    const r = runCli([
      "--bridge-package-address", BRIDGE,
      "--deposit-witness-path", witnessPath,
      "--allow-local-smoke-anonymity",
      "--dry-run",
    ], { EUNOMA_LOCAL_SMOKE: "1" });
    expect(r.status).toBe(0);
    const body = parseStdoutJson(r.stdout);
    expect(body.mode).toBe("legacy_single_leaf");
    expect(body.depositCommitment).toBe(commitmentHex);
  });
});

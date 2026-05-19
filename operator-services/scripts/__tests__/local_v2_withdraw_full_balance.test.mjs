// operator-services/scripts/__tests__/local_v2_withdraw_full_balance.test.mjs
//
// M10-d Step d.5 — orchestrator integration tests for the threshold-decrypt
// balance reconstruction path. Drives `local_v2_withdraw_full.mjs` as a
// subprocess in `--check-balance-only` mode and points it at a mock HTTP
// server that simulates both the Aptos fullnode (for recipient_ek +
// available_balance views) and the coordinator (for /v2/balance/decrypt).
//
// Run via:
//
//     cd operator-services && node --test scripts/__tests__/local_v2_withdraw_full_balance.test.mjs
//
// Tests:
//   1. balance_witness_check failure -> exit nonzero; stderr mentions
//      `balance_witness_check_failed` OR `bsgs_decode_failed_at_chunk_*`.
//   2. Forbidden field in coordinator response -> orchestrator throws
//      `forbidden_field_in_decrypt_response`.
//   3. `--check-balance-only` does NOT write any withdraw_tree_context side-car
//      or sigma_proof artifact (the script must exit before the witness
//      builder or side-car write).
//
// The mock balance is encrypted under a synthetic vault ek and "decrypted"
// via a 1-of-1 quorum (lambda=[1], partial = dk * D), bypassing the real
// Shamir fan-out. The orchestrator never sees the dk directly — it only sees
// the C, D ciphertext from /v1/view and the partials from /v2/balance/decrypt.
//
// Cross-references:
//   * Plan task M10-d Step d.5
//   * Recover impl:    circuits/scripts/recover_balance_chunks.mjs
//   * Coord response:  operator-services/coordinator/src/routes/balance_decrypt.ts
//   * SDK ciphertext:  operator-services/node_modules/@aptos-labs/confidential-asset/
//                        src/crypto/twistedElGamal.ts

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  AVAILABLE_BALANCE_CHUNK_COUNT,
  ChunkedAmount,
  RistrettoPoint,
  TwistedEd25519PrivateKey,
  TwistedElGamal,
} from "@aptos-labs/confidential-asset";
import { ed25519 } from "@noble/curves/ed25519";

const ED_N = ed25519.CURVE.n;

const SCRIPT_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "local_v2_withdraw_full.mjs",
);

const VAULT_ADDRESS = "0x" + "a".repeat(64);
const ASSET_TYPE = "0x" + "1".repeat(64);
const DEPOSITOR_ADDRESS = "0x" + "b".repeat(64);

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function hexToBytes(h) {
  const norm = h.replace(/^0x/i, "");
  const out = new Uint8Array(norm.length / 2);
  for (let i = 0; i < norm.length; i += 2) {
    out[i / 2] = parseInt(norm.slice(i, i + 2), 16);
  }
  return out;
}

/**
 * Encode a bigint scalar as 32-byte little-endian hex — same wire shape the
 * coordinator's `scalarHexFromBigint` (vault_ek_derivation.ts:448) emits, and
 * thus the same shape the orchestrator's `lagrangeCoeffs.map(...)` parser
 * expects.
 */
function scalarHexLE(value) {
  let v = value % ED_N;
  if (v < 0n) v += ED_N;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytesToHex(out);
}

/**
 * Build a balance ciphertext + threshold-decrypt fixture for a synthetic
 * `dk`. Encrypts `balanceOctas` under `ek = dk^-1 * H` (SDK convention) and
 * exposes the matching partial[k] = real_dk * D[k] needed by a 1-of-1 quorum.
 * For test 1 (balance_witness_check failure) we tamper the partial so the
 * reconstructed plaintext is wrong.
 */
function buildBalanceFixture({ balanceOctas, tamperPartial = false }) {
  const dkPriv = TwistedEd25519PrivateKey.generate();
  const vaultEk = dkPriv.publicKey();
  const vaultEkHex = bytesToHex(vaultEk.toUint8Array());

  // Recipient ek (chain-registered).
  const recipientPriv = TwistedEd25519PrivateKey.generate();
  const recipientEk = recipientPriv.publicKey();
  const recipientEkHex = bytesToHex(recipientEk.toUint8Array());

  // Encrypt balance.
  const ell = AVAILABLE_BALANCE_CHUNK_COUNT;
  const chunks = ChunkedAmount.fromAmount(BigInt(balanceOctas)).amountChunks;
  assert.equal(chunks.length, ell);
  const ct = chunks.map((c) => TwistedElGamal.encryptWithPK(c, vaultEk));
  const CHex = ct.map((x) => bytesToHex(x.C.toRawBytes()));
  const DHex = ct.map((x) => bytesToHex(x.D.toRawBytes()));

  // Compute the threshold-decrypt partial = real_dk * D[k]. For Twisted ElGamal
  // with the SDK convention, `real_dk` is `bytesToNumberLE(dkPriv.toUint8Array())`.
  let dk = 0n;
  const dkBytes = dkPriv.toUint8Array();
  for (let i = dkBytes.length - 1; i >= 0; i--) dk = (dk << 8n) | BigInt(dkBytes[i]);
  dk = ((dk % ED_N) + ED_N) % ED_N;

  // Partial[k] = dk * D[k] (or a tampered scalar for the failure-mode test).
  const partialScalar = tamperPartial ? ((dk + 13n) % ED_N) : dk;
  const partialHex = ct.map((x) => {
    const D = RistrettoPoint.fromHex(x.D.toRawBytes());
    return bytesToHex(D.multiply(partialScalar === 0n ? 1n : partialScalar).toRawBytes());
  });

  return {
    vaultEkHex,
    recipientEkHex,
    CHex,
    DHex,
    partialHex,
    chunks,
    dk,
  };
}

/**
 * Stand up a one-port mock server that handles both /v1/view (Aptos) and
 * /v2/balance/decrypt (coordinator) on the same origin. The orchestrator
 * reads both `APTOS_TESTNET_NODE_URL` and `COORDINATOR_URL` so we can point
 * them at the same URL in the test env.
 */
async function startMockServer({
  recipientEkHex,
  CHex,
  DHex,
  partialHex,
  lagrangeHex = scalarHexLE(1n),
  decryptResponseOverride = null,
}) {
  const calls = [];
  const server = createServer(async (req, res) => {
    const buf = [];
    for await (const c of req) buf.push(c);
    const bodyStr = Buffer.concat(buf).toString("utf8");
    let body = {};
    try {
      body = JSON.parse(bodyStr || "{}");
    } catch {
      /* ignore */
    }
    calls.push({ url: req.url, method: req.method, body });

    if (req.method === "POST" && req.url === "/v1/view") {
      if (body?.function === "0x1::confidential_asset::get_encryption_key") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify([{ data: "0x" + recipientEkHex }]));
        return;
      }
      if (body?.function === "0x1::confidential_asset::get_available_balance") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify([
            {
              P: CHex.map((h) => ({ data: "0x" + h })),
              R: DHex.map((h) => ({ data: "0x" + h })),
            },
          ]),
        );
        return;
      }
      res.writeHead(404).end();
      return;
    }

    if (req.method === "POST" && req.url === "/v2/balance/decrypt") {
      const defaultResp = {
        slots: [
          {
            slot: 0,
            partial_hex: partialHex,
            signature: "00".repeat(32),
            transcript_domain: "EUNOMA_M10B_BALANCE_DECRYPT_PARTIAL_V1",
          },
        ],
        lagrangeCoeffs: [lagrangeHex],
      };
      const resp = decryptResponseOverride
        ? decryptResponseOverride(defaultResp)
        : defaultResp;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(resp));
      return;
    }

    res.writeHead(404).end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  const url = `http://127.0.0.1:${addr.port}`;
  return { server, url, calls };
}

/**
 * Build a per-test scratch dir with minimal-but-valid fixtures (deposit witness,
 * caDkgV2 roster, frost roster) and side-car coordinator state dir.
 */
function buildScratchDir() {
  const root = mkdtempSync(join(tmpdir(), "m10d-balance-"));
  const stateDir = join(root, "state");
  mkdirSync(stateDir, { recursive: true });
  // The orchestrator's side-car write target — we point it here via cwd.
  // Side-car path is resolve(serviceRoot, ".agent-local/...") which depends on
  // the script's own __dirname, not on cwd. So we cannot redirect it; instead
  // we check the well-known location after the run.
  const depositWitnessPath = join(root, "deposit_witness.json");
  writeFileSync(
    depositWitnessPath,
    JSON.stringify({
      schema: "v2_depositor_witness_v1",
      depositorAddress: DEPOSITOR_ADDRESS,
      depositCount: 1,
      commitmentHex: "0x" + "11".repeat(32),
    }),
  );
  const caDkgRosterPath = join(root, "ca_dkg_v2_roster.json");
  writeFileSync(
    caDkgRosterPath,
    JSON.stringify({
      schema: "ca_dkg_v2_roster",
      dkgEpoch: 1,
      operatorSetVersion: 1,
      caDkgV2RosterHash: "0x" + "ab".repeat(32),
      nodes: [
        {
          slot: 0,
          endpoint: "http://127.0.0.1:0",
          hpkePublicKey: "00".repeat(32),
        },
      ],
    }),
  );
  const frostRosterPath = join(root, "frost_roster.json");
  writeFileSync(
    frostRosterPath,
    JSON.stringify({
      schema: "frost_dkg_v2_roster",
      frostGroupPubkey: "00".repeat(32),
      nodes: [],
    }),
  );
  return { root, depositWitnessPath, caDkgRosterPath, frostRosterPath, stateDir };
}

/**
 * Snapshot the side-car / proof artifact files that the orchestrator would
 * write so we can assert they are NOT touched in --check-balance-only mode.
 * The script writes to `.agent-local/eunoma-v2/coordinator/withdraw_tree_context_*.json`
 * relative to its own serviceRoot (operator-services/), not cwd.
 */
function snapshotArtifactDir() {
  const ctxDir = resolve(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "..",
    ".agent-local",
    "eunoma-v2",
    "coordinator",
  );
  if (!existsSync(ctxDir)) return new Set();
  return new Set(readdirSync(ctxDir).filter((f) => f.startsWith("withdraw_tree_context_")));
}

/**
 * Run the orchestrator as an async subprocess with mock URLs wired up.
 * MUST be async — `spawnSync` blocks the test process's event loop, which
 * starves the in-process mock HTTP server and causes undici's
 * `HeadersTimeoutError` when the child tries to fetch from it.
 *
 * Returns `{ status, signal, stdout, stderr }` like spawnSync would.
 */
async function runOrchestrator({
  scratch,
  mockUrl,
  vaultEkHex,
  args = [],
  extraEnv = {},
  bridge = "0x" + "c".repeat(64),
}) {
  const child = spawn(
    "node",
    [
      SCRIPT_PATH,
      "--deposit-witness",
      scratch.depositWitnessPath,
      "--vault-address",
      VAULT_ADDRESS,
      "--vault-ek",
      vaultEkHex,
      "--root",
      "0x" + "0".repeat(64),
      "--asset-type",
      ASSET_TYPE,
      "--vault-sequence",
      "1",
      "--request-id",
      "m10d-test-" + Date.now() + "-" + Math.floor(Math.random() * 1e6),
      ...args,
    ],
    {
      env: {
        ...process.env,
        APTOS_TESTNET_NODE_URL: mockUrl,
        COORDINATOR_URL: mockUrl,
        COORDINATOR_BEARER_TOKEN: "test-bearer",
        CA_DKG_V2_ROSTER_JSON_PATH: scratch.caDkgRosterPath,
        FROST_DKG_V2_ROSTER_JSON_PATH: scratch.frostRosterPath,
        CHAIN_ID: "2",
        BRIDGE_PACKAGE_ADDRESS: bridge,
        WITHDRAW_AMOUNT_OCTAS: "100",
        ...extraEnv,
      },
    },
  );
  const stdoutChunks = [];
  const stderrChunks = [];
  child.stdout.on("data", (d) => stdoutChunks.push(d));
  child.stderr.on("data", (d) => stderrChunks.push(d));
  const { code, signal } = await new Promise((r) =>
    child.on("close", (code, signal) => r({ code, signal })),
  );
  return {
    status: code,
    signal,
    stdout: Buffer.concat(stdoutChunks).toString("utf8"),
    stderr: Buffer.concat(stderrChunks).toString("utf8"),
  };
}

// =============================================================================
// Test 1 — balance_witness_check failure
// =============================================================================
test("balance_witness_check failure → exit nonzero", async () => {
  // Tamper the worker partials so the aggregated dk-reconstruction is WRONG.
  // The BSGS step will fail to find a plaintext in [0, 2^16) and the
  // orchestrator must throw `bsgs_decode_failed_at_chunk_*` (or, if BSGS
  // accidentally finds a different valid integer, the chunk-witness sanity
  // check downstream catches it as `balance_witness_check_failed`). Either
  // way: nonzero exit, error in stderr.
  const fx = buildBalanceFixture({ balanceOctas: 828, tamperPartial: true });
  const mock = await startMockServer({
    recipientEkHex: fx.recipientEkHex,
    CHex: fx.CHex,
    DHex: fx.DHex,
    partialHex: fx.partialHex,
  });
  try {
    const scratch = buildScratchDir();
    try {
      const result = await runOrchestrator({
        scratch,
        mockUrl: mock.url,
        vaultEkHex: fx.vaultEkHex,
        args: ["--check-balance-only"],
      });
      assert.notEqual(result.status, 0, `expected nonzero exit, got ${result.status}`);
      const combined = (result.stderr ?? "") + (result.stdout ?? "");
      assert.match(
        combined,
        /(bsgs_decode_failed_at_chunk_|balance_witness_check_failed)/,
        `expected balance-witness failure marker; got stderr=${result.stderr?.slice(0, 1000)}`,
      );
    } finally {
      rmSync(scratch.root, { recursive: true, force: true });
    }
  } finally {
    await new Promise((r) => mock.server.close(r));
  }
});

// =============================================================================
// Test 2 — forbidden field in coordinator response
// =============================================================================
test("forbidden field in coordinator response → throw", async () => {
  const fx = buildBalanceFixture({ balanceOctas: 828 });
  const mock = await startMockServer({
    recipientEkHex: fx.recipientEkHex,
    CHex: fx.CHex,
    DHex: fx.DHex,
    partialHex: fx.partialHex,
    decryptResponseOverride: (defaultResp) => ({
      ...defaultResp,
      // M10-c's outbound forbidden-key guard would normally block this on the
      // server side; the orchestrator's defense-in-depth check must also reject
      // it in case the coordinator is compromised or a future protocol revision
      // accidentally adds the field.
      leafIndex: 17,
    }),
  });
  try {
    const scratch = buildScratchDir();
    try {
      const result = await runOrchestrator({
        scratch,
        mockUrl: mock.url,
        vaultEkHex: fx.vaultEkHex,
        args: ["--check-balance-only"],
      });
      assert.notEqual(result.status, 0, `expected nonzero exit, got ${result.status}`);
      const combined = (result.stderr ?? "") + (result.stdout ?? "");
      assert.match(
        combined,
        /forbidden_field_in_decrypt_response/,
        `expected forbidden-field rejection; got stderr=${result.stderr?.slice(0, 1000)}`,
      );
    } finally {
      rmSync(scratch.root, { recursive: true, force: true });
    }
  } finally {
    await new Promise((r) => mock.server.close(r));
  }
});

// =============================================================================
// Test 3 — --check-balance-only does NOT write side-car or sigma_proof
// =============================================================================
test("--check-balance-only does not write side-car or σ-proof", async () => {
  const fx = buildBalanceFixture({ balanceOctas: 828 });
  const mock = await startMockServer({
    recipientEkHex: fx.recipientEkHex,
    CHex: fx.CHex,
    DHex: fx.DHex,
    partialHex: fx.partialHex,
  });
  try {
    const scratch = buildScratchDir();
    const before = snapshotArtifactDir();
    try {
      const result = await runOrchestrator({
        scratch,
        mockUrl: mock.url,
        vaultEkHex: fx.vaultEkHex,
        args: ["--check-balance-only"],
      });
      assert.equal(
        result.status,
        0,
        `expected exit 0 (balance recovers cleanly); got ${result.status}, stderr=${result.stderr?.slice(0, 1000)}`,
      );
      // Stdout should be a single JSON payload with check=balance.
      // M10-l: default redacts plaintext chunks/sums; only the integrity
      // verdict + balanceVectorHash bind the (private) recovered vectors.
      const stdout = (result.stdout ?? "").trim();
      const parsed = JSON.parse(stdout);
      assert.equal(parsed.check, "balance");
      assert.equal(parsed.balance_witness_check, "ok");
      assert.match(parsed.balanceVectorHash, /^[0-9a-f]{64}$/);
      assert.ok(
        !("balanceChunks" in parsed),
        "default mode must NOT leak plaintext balanceChunks to stdout (codex iter-2 P2)",
      );
      assert.ok(
        !("balanceChunksSum" in parsed),
        "default mode must NOT leak plaintext balanceChunksSum to stdout (codex iter-2 P2)",
      );

      // No new side-car was written.
      const after = snapshotArtifactDir();
      const added = [...after].filter((f) => !before.has(f));
      assert.deepEqual(added, [], `expected no new withdraw_tree_context_*.json side-car, got ${added}`);

      // The orchestrator also writes /tmp/m8-<requestId>-witness.json + -proof.json
      // when it runs the witness builder + Groth16 prover. --check-balance-only
      // must exit BEFORE either of those is invoked, so neither file should
      // exist for this requestId.
      const tmpFiles = readdirSync(tmpdir()).filter((f) =>
        f.startsWith("m8-m10d-test-"),
      );
      assert.deepEqual(
        tmpFiles,
        [],
        `expected no /tmp/m8-*-witness.json or -proof.json; got ${tmpFiles}`,
      );
    } finally {
      rmSync(scratch.root, { recursive: true, force: true });
    }
  } finally {
    await new Promise((r) => mock.server.close(r));
  }
});

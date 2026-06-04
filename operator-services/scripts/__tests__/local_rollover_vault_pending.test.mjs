import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "local_rollover_vault_pending.mjs",
);
const BRIDGE = `0x${"a".repeat(64)}`;

let tmpRoot;
let fakeBin;

beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "eunoma-rollover-"));
  fakeBin = join(tmpRoot, "bin");
  mkdirSync(fakeBin, { recursive: true });
});

afterEach(() => {
  if (tmpRoot) rmSync(tmpRoot, { recursive: true, force: true });
});

describe("local_rollover_vault_pending", () => {
  it("treats CA E_NOTHING_TO_ROLLOVER as an idempotent no-op", () => {
    writeFileSync(
      join(fakeBin, "aptos"),
      `#!/usr/bin/env bash
echo 'Transaction submitted: https://explorer.aptoslabs.com/txn/0x69b?network=testnet' >&2
echo '{"error":"E_NOTHING_TO_ROLLOVER"}'
exit 1
`,
    );
    chmodSync(join(fakeBin, "aptos"), 0o755);

    const result = spawnSync(
      "node",
      [
        SCRIPT_PATH,
        "--bridge-package-address",
        BRIDGE,
        "--via-delegate",
        "--delegate-profile",
        "testnet-relayer",
      ],
      {
        encoding: "utf8",
        env: { ...process.env, PATH: `${fakeBin}:${process.env.PATH}` },
      },
    );

    expect(result.status).toBe(0);
    const body = JSON.parse(result.stdout);
    expect(body).toMatchObject({
      ok: true,
      status: "nothing_to_rollover",
      txHash: "0x69b",
      functionId: `${BRIDGE}::eunoma_bridge::operator_rollover_vault_pending_via_delegate`,
    });
  });

  it("treats confirmed CA E_NOTHING_TO_ROLLOVER abort as an idempotent no-op", async () => {
    writeFileSync(
      join(fakeBin, "aptos"),
      `#!/usr/bin/env bash
echo 'Transaction submitted: https://explorer.aptoslabs.com/txn/0xabc123?network=testnet' >&2
exit 0
`,
    );
    chmodSync(join(fakeBin, "aptos"), 0o755);
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          type: "user_transaction",
          success: false,
          version: "123",
          gas_used: "42",
          vm_status:
            "Move abort in 0x1::confidential_asset: E_NOTHING_TO_ROLLOVER(0x3000d): There are no pending transfers to roll over.",
        }),
      );
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();

    try {
      const result = await spawnNode([
        SCRIPT_PATH,
        "--bridge-package-address",
        BRIDGE,
        "--admin-profile",
        "testnet-user",
        "--aptos-node-url",
        `http://127.0.0.1:${port}`,
      ]);

      expect(result.status).toBe(0);
      const body = JSON.parse(result.stdout);
      expect(body).toMatchObject({
        ok: true,
        status: "nothing_to_rollover",
        txHash: "0xabc123",
        version: "123",
        vmStatus:
          "Move abort in 0x1::confidential_asset: E_NOTHING_TO_ROLLOVER(0x3000d): There are no pending transfers to roll over.",
      });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it("honors APTOS_CLI_CWD for Aptos profile lookup", () => {
    const cliCwd = join(tmpRoot, "aptos-cwd");
    mkdirSync(cliCwd, { recursive: true });
    const pwdFile = join(tmpRoot, "aptos-pwd.txt");
    writeFileSync(
      join(fakeBin, "aptos"),
      `#!/usr/bin/env bash
pwd > ${JSON.stringify(pwdFile)}
echo '{"error":"E_NOTHING_TO_ROLLOVER"}'
exit 1
`,
    );
    chmodSync(join(fakeBin, "aptos"), 0o755);

    const result = spawnSync(
      "node",
      [
        SCRIPT_PATH,
        "--bridge-package-address",
        BRIDGE,
        "--admin-profile",
        "testnet-user",
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          APTOS_CLI_CWD: cliCwd,
          PATH: `${fakeBin}:${process.env.PATH}`,
        },
      },
    );

    expect(result.status).toBe(0);
    expect(realpathSync(readFileSync(pwdFile, "utf8").trim())).toBe(realpathSync(cliCwd));
  });

  it("retries transient Aptos CLI rate limits before requiring a transaction hash", async () => {
    const attemptsFile = join(tmpRoot, "aptos-attempts.txt");
    const txHash = `0x${"12".repeat(32)}`;
    writeFileSync(
      join(fakeBin, "aptos"),
      `#!/usr/bin/env bash
count=$(cat ${JSON.stringify(attemptsFile)} 2>/dev/null || echo 0)
count=$((count + 1))
echo "$count" > ${JSON.stringify(attemptsFile)}
if [ "$count" = "1" ]; then
  echo 'API error: Per anonymous IP rate limit exceeded. Limit: 40000 compute units per 300 seconds window.' >&2
  exit 0
fi
echo '{"Result":{"transaction_hash":"${txHash}"}}'
exit 0
`,
    );
    chmodSync(join(fakeBin, "aptos"), 0o755);

    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          type: "user_transaction",
          success: true,
          version: "456",
          gas_used: "23",
          vm_status: "Executed successfully",
        }),
      );
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();

    try {
      const result = await spawnNode(
        [
          SCRIPT_PATH,
          "--bridge-package-address",
          BRIDGE,
          "--admin-profile",
          "testnet-user",
          "--aptos-node-url",
          `http://127.0.0.1:${port}`,
        ],
        {
          EUNOMA_APTOS_CLI_RETRY_ATTEMPTS: "2",
          EUNOMA_APTOS_CLI_RETRY_DELAY_MS: "0",
        },
      );

      expect(result.status).toBe(0);
      expect(readFileSync(attemptsFile, "utf8").trim()).toBe("2");
      expect(result.stderr).toContain("retryable Aptos CLI transport failure");
      const body = JSON.parse(result.stdout);
      expect(body).toMatchObject({
        ok: true,
        status: "rolled_over",
        txHash,
        version: "456",
      });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it("defaults to a retry window long enough for the Aptos anonymous rate-limit window", async () => {
    const attemptsFile = join(tmpRoot, "aptos-default-attempts.txt");
    const txHash = `0x${"34".repeat(32)}`;
    writeFileSync(
      join(fakeBin, "aptos"),
      `#!/usr/bin/env bash
count=$(cat ${JSON.stringify(attemptsFile)} 2>/dev/null || echo 0)
count=$((count + 1))
echo "$count" > ${JSON.stringify(attemptsFile)}
if [ "$count" -lt "12" ]; then
  echo 'API error: Unknown error Per anonymous IP rate limit exceeded. Limit: 40000 compute units per 300 seconds window.' >&2
  exit 0
fi
echo '{"Result":{"transaction_hash":"${txHash}"}}'
exit 0
`,
    );
    chmodSync(join(fakeBin, "aptos"), 0o755);

    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          type: "user_transaction",
          success: true,
          version: "789",
          gas_used: "23",
          vm_status: "Executed successfully",
        }),
      );
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();

    try {
      const result = await spawnNode(
        [
          SCRIPT_PATH,
          "--bridge-package-address",
          BRIDGE,
          "--admin-profile",
          "testnet-user",
          "--aptos-node-url",
          `http://127.0.0.1:${port}`,
        ],
        {
          EUNOMA_APTOS_CLI_RETRY_DELAY_MS: "0",
        },
      );

      expect(result.status).toBe(0);
      expect(readFileSync(attemptsFile, "utf8").trim()).toBe("12");
      expect(result.stderr).toContain("attempt 11/12");
      const body = JSON.parse(result.stdout);
      expect(body).toMatchObject({
        ok: true,
        status: "rolled_over",
        txHash,
        version: "789",
      });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});

function spawnNode(args, envOverrides = {}) {
  return new Promise((resolve) => {
    const child = spawn("node", args, {
      encoding: "utf8",
      env: { ...process.env, ...envOverrides, PATH: `${fakeBin}:${process.env.PATH}` },
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
    child.on("close", (status) => {
      resolve({ status, stdout, stderr });
    });
  });
}

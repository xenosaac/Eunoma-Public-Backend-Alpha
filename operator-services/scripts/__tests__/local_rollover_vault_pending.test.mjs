import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
});

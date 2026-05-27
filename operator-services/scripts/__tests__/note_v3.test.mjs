import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { decodeNoteV2, decodeNoteV3, encodeNoteV3, isNoteV2, isNoteV3 } from "../_lib/note_v3.mjs";

const serviceRoot = resolve(fileURLToPath(new URL("../..", import.meta.url)));

test("note-v3 encrypts and decrypts with the right passphrase", () => {
  const plaintext = {
    schema: "v2_depositor_witness_v1",
    amountOctas: "123",
    nullifierHex: `0x${"11".repeat(32)}`,
    secretHex: `0x${"22".repeat(32)}`,
    depositBlindHex: `0x${"33".repeat(32)}`,
    amountPHex: `0x${"44".repeat(128)}`,
  };
  const encoded = encodeNoteV3(plaintext, "passphrase");

  assert.equal(isNoteV3(encoded), true);
  assert.equal(encoded.includes("amountOctas"), false);
  assert.equal(encoded.includes("secretHex"), false);
  assert.deepEqual(decodeNoteV3(encoded, "passphrase"), plaintext);
  assert.throws(() => decodeNoteV3(encoded, "wrong"), /decrypt/);
});

test("note-v2 plaintext import decodes legacy notes without passphrase", () => {
  const legacy = {
    version: 2,
    amountOctas: "123",
    depositTxHash: `0x${"ab".repeat(32)}`,
    leafIndex: 1,
    commitmentHex: `0x${"44".repeat(32)}`,
  };
  const encoded = `eunoma-note-v2.${Buffer.from(JSON.stringify(legacy), "utf8").toString("base64url")}`;

  assert.equal(isNoteV2(encoded), true);
  assert.equal(isNoteV3(encoded), false);
  assert.deepEqual(decodeNoteV2(encoded), legacy);
});

test("local_v2_deposit_submit hard-fails before chain work without note passphrase", () => {
  const stateRoot = mkdtempSync(join(tmpdir(), "eunoma-note-v3-preflight-"));
  try {
    const childEnv = { ...process.env };
    delete childEnv.EUNOMA_NOTE_PASSPHRASE;
    const result = spawnSync(process.execPath, ["scripts/local_v2_deposit_submit.mjs"], {
      cwd: serviceRoot,
      encoding: "utf8",
      env: {
        ...childEnv,
        EUNOMA_LOCAL_STATE_ROOT: stateRoot,
        BRIDGE_PACKAGE_ADDRESS: `0x${"aa".repeat(32)}`,
        COORDINATOR_BEARER_TOKEN: "test-token",
        CA_DKG_V2_ROSTER_JSON_PATH: join(stateRoot, "unused-ca-roster.json"),
      },
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /EUNOMA_NOTE_PASSPHRASE/);
    const depositorDir = join(stateRoot, "depositor");
    const files = readdirSync(depositorDir);
    assert.deepEqual(
      files.filter((name) => /withdraw_(witness|note)_|deposit_public_/.test(name)),
      [],
    );
  } finally {
    rmSync(stateRoot, { recursive: true, force: true });
  }
});

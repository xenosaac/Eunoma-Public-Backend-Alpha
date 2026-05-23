import test from "node:test";
import assert from "node:assert/strict";

import { decodeNoteV3, encodeNoteV3, isNoteV3 } from "../_lib/note_v3.mjs";

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

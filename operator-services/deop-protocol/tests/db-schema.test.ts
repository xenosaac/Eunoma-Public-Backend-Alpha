import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

describe("V2 DB schemas", () => {
  it("do not persist plaintext witness columns", () => {
    const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
    const sql = [
      "coordinator/db/migrations/0001_v2_transcript.sql",
      "deoperator-node/db/migrations/0001_v2_node_transcript.sql",
    ]
      .map((path) => readFileSync(resolve(root, path), "utf8").toLowerCase())
      .join("\n");

    expect(sql).not.toMatch(/\bamount\b/);
    expect(sql).not.toMatch(/\bblind\b/);
    expect(sql).not.toMatch(/\bsecret\b/);
    expect(sql).not.toMatch(/\bnullifier\b/);
  });
});

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC_DIR = resolve(__dirname, "..", "src");

describe("secret log safety regression", () => {
  it("console output in src does not include sensitive field names", () => {
    const files = execFileSync("rg", ["--files", SRC_DIR], { encoding: "utf-8" })
      .trim()
      .split("\n")
      .filter(Boolean);
    const forbidden = [
      "private" + "_key",
      "bear" + "er",
      "null" + "ifier",
      "deposit" + "_blind",
      "withdraw" + "_blind",
      "sec" + "ret",
      "key" + "_derivation",
      "wallet" + "_signature",
    ];
    const hits: string[] = [];
    for (const file of files) {
      const lines = readFileSync(file, "utf-8").split("\n");
      lines.forEach((line, idx) => {
        if (!/\bconsole\.(log|warn|error|info|debug)\b/.test(line)) return;
        const lower = line.toLowerCase();
        for (const term of forbidden) {
          if (lower.includes(term)) hits.push(`${file}:${idx + 1}:${term}`);
        }
      });
    }
    expect(hits).toEqual([]);
  });
});

import { describe, expect, it } from "vitest";
import {
  hexArg,
  hexVector3Arg,
  hexVectorArg,
  u64Arg,
} from "../src/index.js";

// The TS helpers must produce strings byte-compatible with
// `scripts/_lib/format_aptos_args.mjs`. The .mjs lib only exports depths 1 and
// 2, so depth-3 behavior is tested fresh here.
//
// We compare against literal expected strings rather than executing the .mjs
// lib so the test runner does not need a worker-thread or fetch round-trip.
// If `format_aptos_args.mjs` ever drifts from these literals, the round-trip
// will break and the local cluster scripts will fail loudly.

describe("u64Arg", () => {
  it("formats a decimal string", () => {
    expect(u64Arg("42")).toBe("u64:42");
  });
  it("formats zero", () => {
    expect(u64Arg("0")).toBe("u64:0");
  });
  it("formats a bigint", () => {
    expect(u64Arg(42n)).toBe("u64:42");
  });
  it("formats the u64 max", () => {
    expect(u64Arg(18446744073709551615n)).toBe("u64:18446744073709551615");
    expect(u64Arg("18446744073709551615")).toBe("u64:18446744073709551615");
  });
  it("rejects values larger than u64", () => {
    expect(() => u64Arg(18446744073709551616n)).toThrow(/overflow/i);
    expect(() => u64Arg("18446744073709551616")).toThrow(/overflow/i);
  });
  it("rejects negative bigints", () => {
    expect(() => u64Arg(-1n)).toThrow(/non-negative/i);
  });
  it("rejects non-decimal strings", () => {
    expect(() => u64Arg("0x42")).toThrow();
    expect(() => u64Arg("not-a-number")).toThrow();
  });
  it("rejects leading zeros (must be canonical decimal)", () => {
    expect(() => u64Arg("042")).toThrow();
  });
});

describe("hexArg", () => {
  it("formats a 0x-prefixed string lowercase", () => {
    expect(hexArg("0xDEADBEEF")).toBe("hex:0xdeadbeef");
  });
  it("formats a string with no prefix", () => {
    expect(hexArg("DEAD")).toBe("hex:0xdead");
  });
  it("formats an empty string as the empty hex literal", () => {
    expect(hexArg("")).toBe("hex:0x");
  });
  it("rejects odd nibbles", () => {
    expect(() => hexArg("0xabc")).toThrow();
  });
  it("rejects non-hex characters", () => {
    expect(() => hexArg("0xGG")).toThrow();
  });
});

describe("hexVectorArg (vector<vector<u8>>)", () => {
  it("formats a non-empty array", () => {
    expect(hexVectorArg(["0xaa", "0xbb"])).toBe("hex:[0xaa,0xbb]");
  });
  it("formats an empty array", () => {
    expect(hexVectorArg([])).toBe("hex:[]");
  });
  it("preserves item order", () => {
    expect(hexVectorArg(["0x01", "0x02", "0x03"])).toBe("hex:[0x01,0x02,0x03]");
  });
  it("normalizes prefix and casing per item", () => {
    expect(hexVectorArg(["AA", "0xBB"])).toBe("hex:[0xaa,0xbb]");
  });
  it("rejects a non-array argument", () => {
    expect(() => hexVectorArg("0xaa" as unknown as string[])).toThrow();
  });
  it("rejects a per-item bad-hex entry with an index-precise error", () => {
    expect(() => hexVectorArg(["0xaa", "0xGG"])).toThrow(/\[1\]/);
  });
});

describe("hexVector3Arg (vector<vector<vector<u8>>>)", () => {
  it("formats an empty outer array", () => {
    expect(hexVector3Arg([])).toBe("hex:[]");
  });
  it("formats an outer array with one empty inner array", () => {
    expect(hexVector3Arg([[]])).toBe("hex:[[]]");
  });
  it("formats a depth-3 fixture (two auditors, each with two ciphertexts)", () => {
    expect(
      hexVector3Arg([
        ["0xaa", "0xbb"],
        ["0xcc", "0xdd"],
      ]),
    ).toBe("hex:[[0xaa,0xbb],[0xcc,0xdd]]");
  });
  it("preserves nested order", () => {
    expect(
      hexVector3Arg([
        ["0x01", "0x02"],
        ["0x03"],
        [],
      ]),
    ).toBe("hex:[[0x01,0x02],[0x03],[]]");
  });
  it("rejects a depth-2 input (string[] instead of string[][])", () => {
    expect(() =>
      hexVector3Arg(["0xaa" as unknown as string[]]),
    ).toThrow(/\[0\]/);
  });
  it("rejects a per-item bad-hex entry with an outer+inner index error", () => {
    expect(() => hexVector3Arg([["0xaa"], ["0xbb", "0xGG"]])).toThrow(/\[1\]\[1\]/);
  });
  it("formats long fixture matching depth-3 vector encoding contract", () => {
    // Sanity: round-trip the encoding rule "outer-comma-separated inner-arrays".
    const values: string[][] = [
      ["0x" + "11".repeat(32), "0x" + "22".repeat(32)],
      ["0x" + "33".repeat(32)],
    ];
    const out = hexVector3Arg(values);
    // Decompose: must start hex:[ , contain 0x repeated, end with ]]
    expect(out.startsWith("hex:[")).toBe(true);
    expect(out.endsWith("]")).toBe(true);
    expect(out).toContain("[0x" + "11".repeat(32) + ",0x" + "22".repeat(32) + "]");
    expect(out).toContain("[0x" + "33".repeat(32) + "]");
  });
});

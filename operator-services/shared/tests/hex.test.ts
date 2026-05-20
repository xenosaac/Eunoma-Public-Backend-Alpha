import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes } from "../src/index.js";

describe("hex helpers", () => {
  it("round trips prefixed and unprefixed hex", () => {
    expect(bytesToHex(hexToBytes("0x00Aa"))).toBe("00aa");
    expect(bytesToHex(hexToBytes("ff"), true)).toBe("0xff");
  });

  it("rejects malformed hex", () => {
    expect(() => hexToBytes("abc")).toThrow(/even/);
    expect(() => hexToBytes("zz")).toThrow(/non-hex/);
  });
});

import { describe, expect, it } from "vitest";
import { RelayerSubmitterError, type SpawnAptosFn } from "../src/server.js";
import {
  DEPOSIT_V3_DELEGATE_ENTRIES,
  type DepositV3DelegateArgs,
  createDepositV3Submitter,
  encodeDepositV3EntryArgs,
} from "../src/deposit_v3_submitter.js";

function fixtureArgs(): DepositV3DelegateArgs {
  const hex32 = (seed: number): string =>
    Array.from({ length: 32 }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");
  const hexN = (n: number, seed: number): string =>
    Array.from({ length: n }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");
  return {
    userAddr: hex32(0x01),
    commitment: hex32(0x02),
    amountTag: hex32(0x03),
    amountP: Array.from({ length: 4 }, (_, i) => hex32(0x10 + i)),
    depositBindingProof: hexN(192, 0x20),
    caPayloadHash: hex32(0x04),
    depositNonce: hex32(0x05),
    expirySecs: "1800000000",
    groupSignature: hexN(64, 0x30),
    fallbackBitmap: 0,
    fallbackSignatures: [],
    newBalanceP: Array.from({ length: 8 }, (_, i) => hex32(0x40 + i)),
    newBalanceR: Array.from({ length: 8 }, (_, i) => hex32(0x50 + i)),
    newBalanceREffAud: [],
    amountRSender: Array.from({ length: 4 }, (_, i) => hex32(0x70 + i)),
    amountRRecip: Array.from({ length: 4 }, (_, i) => hex32(0x80 + i)),
    amountREffAud: [],
    ekVolunAuds: [],
    amountRVolunAuds: [],
    zkrpNewBalance: hexN(672, 0x90),
    zkrpAmount: hexN(672, 0xa0),
    sigmaProtoComm: Array.from({ length: 30 }, (_, i) => hex32(0xb0 + i)),
    sigmaProtoResp: Array.from({ length: 25 }, (_, i) => hex32(0xc0 + i)),
    memo: "",
  };
}

function buildMultiMockSpawn(opts: { exitCodes?: Array<number | null>; stderr?: string } = {}): {
  fn: SpawnAptosFn;
  calls: Array<{ command: string; args: string[] }>;
} {
  const calls: Array<{ command: string; args: string[] }> = [];
  const fn: SpawnAptosFn = (command, args) => {
    const idx = calls.length;
    calls.push({ command, args });
    const exitCode = opts.exitCodes ? opts.exitCodes[idx] ?? 0 : 0;
    const stdout =
      exitCode === 0
        ? JSON.stringify({ Result: { transaction_hash: `0x${idx.toString(16).padStart(64, "0")}` } })
        : "";
    async function* o() {
      if (stdout) yield stdout;
    }
    async function* e() {
      if (exitCode !== 0 && opts.stderr) yield opts.stderr;
    }
    return { stdout: o(), stderr: e(), done: Promise.resolve(exitCode) };
  };
  return { fn, calls };
}

describe("DEPOSIT_V3_DELEGATE_ENTRIES — field mapping", () => {
  it("has prepare + step2a in order with arg counts matching the Move signatures", () => {
    expect(DEPOSIT_V3_DELEGATE_ENTRIES.map((e) => e.fn)).toEqual([
      "prepare_deposit_binding_v3_for_user",
      "deposit_step2a_eunoma_verify_v3",
    ]);
    expect(DEPOSIT_V3_DELEGATE_ENTRIES[0].keys.length).toBe(5);
    expect(DEPOSIT_V3_DELEGATE_ENTRIES[1].keys.length).toBe(24);
    // step2b is NOT delegated (user-signed CA debit).
    expect(DEPOSIT_V3_DELEGATE_ENTRIES.some((e) => e.fn.includes("step2b"))).toBe(false);
  });

  it("encodes every entry without throwing (all keys valid)", () => {
    const args = fixtureArgs();
    for (const entry of DEPOSIT_V3_DELEGATE_ENTRIES) {
      expect(encodeDepositV3EntryArgs(entry, args).length).toBe(entry.keys.length);
    }
    // userAddr encodes as an address: arg (not hex:) so the Move `address` param deserializes.
    const prepare = encodeDepositV3EntryArgs(DEPOSIT_V3_DELEGATE_ENTRIES[0], args);
    expect(prepare[0]).toMatch(/^address:0x/);
  });
});

describe("createDepositV3Submitter", () => {
  it("submits prepare + step2a in order, same profile, --simulate default, 2 tx hashes", async () => {
    const { fn, calls } = buildMultiMockSpawn();
    const submitter = createDepositV3Submitter("0xabc", "relayer-lowpriv", { spawnAptos: fn });
    const result = await submitter(fixtureArgs());

    expect(calls.length).toBe(2);
    expect(result.txHashes.length).toBe(2);
    expect(result.simulated).toBe(true);

    const fnNames = ["prepare_deposit_binding_v3_for_user", "deposit_step2a_eunoma_verify_v3"];
    calls.forEach((call, i) => {
      const fnIdx = call.args.indexOf("--function-id");
      expect(call.args[fnIdx + 1]).toBe(`0xabc::eunoma_bridge::${fnNames[i]}`);
      const profIdx = call.args.indexOf("--profile");
      expect(call.args[profIdx + 1]).toBe("relayer-lowpriv");
      expect(call.args).toContain("--simulate");
    });
  });

  it("submit=true without RELAYER_SUBMIT_ENABLED=1 throws at construction", () => {
    expect(() => createDepositV3Submitter("0xabc", "r", { submit: true, env: {} })).toThrow(
      /RELAYER_SUBMIT_ENABLED=1/,
    );
  });

  it("aborts on a failing tx and does not leak stderr", async () => {
    const { fn, calls } = buildMultiMockSpawn({ exitCodes: [0, 1], stderr: "secret-WALLET_PATH=/x" });
    const buffered: string[] = [];
    const submitter = createDepositV3Submitter("0xabc", "r", {
      spawnAptos: fn,
      stderrSink: { write: (c) => buffered.push(c) },
    });
    try {
      await submitter(fixtureArgs());
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(RelayerSubmitterError);
      expect((err as RelayerSubmitterError).message).not.toContain("WALLET_PATH");
    }
    expect(calls.length).toBe(2); // stopped after the failing step2a
    expect(buffered.join("")).toContain("WALLET_PATH"); // logged locally only
  });
});

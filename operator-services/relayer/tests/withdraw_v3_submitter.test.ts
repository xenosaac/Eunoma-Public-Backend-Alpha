import { describe, expect, it } from "vitest";
import { type WithdrawV2CallArgs } from "@eunoma/deop-protocol";
import { RelayerSubmitterError, type SpawnAptosFn } from "../src/server.js";
import {
  WITHDRAW_V3_ENTRIES,
  createWithdrawV3Submitter,
  encodeV3EntryArgs,
} from "../src/withdraw_v3_submitter.js";

/** Same deterministic 27-field fixture as aptos_cli_submitter.test.ts. */
function fixtureCallArgs(): WithdrawV2CallArgs {
  const hex32 = (seed: number): string =>
    Array.from({ length: 32 }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");
  const hexN = (n: number, seed: number): string =>
    Array.from({ length: n }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");
  return {
    root: hex32(0x10),
    nullifierHash: hex32(0x11),
    recipient: hex32(0x12),
    recipientHash: hex32(0x13),
    amountTag: hex32(0x14),
    caPayloadHash: hex32(0x15),
    requestHash: hex32(0x16),
    vaultSequence: "42",
    withdrawProof: hexN(192, 0x20),
    expirySecs: "1800000000",
    groupSignature: hexN(64, 0x30),
    fallbackBitmap: 0,
    fallbackSignatures: [],
    newBalanceP: Array.from({ length: 8 }, (_, i) => hex32(0x40 + i)),
    newBalanceR: Array.from({ length: 8 }, (_, i) => hex32(0x50 + i)),
    newBalanceREffAud: [],
    amountP: Array.from({ length: 4 }, (_, i) => hex32(0x60 + i)),
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

/** Multi-call mock spawn: records every invocation; per-call exit codes drive failure tests. */
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
    async function* stdoutGen() {
      if (stdout) yield stdout;
    }
    async function* stderrGen() {
      if (exitCode !== 0 && opts.stderr) yield opts.stderr;
    }
    return { stdout: stdoutGen(), stderr: stderrGen(), done: Promise.resolve(exitCode) };
  };
  return { fn, calls };
}

const EXPECTED_ORDER = [
  "prepare_withdraw_proof_v3",
  "prepare_withdraw_attestation_v3",
  "prepare_withdraw_payload_v3",
  "withdraw_step2a_eunoma_verify_v3",
  "withdraw_step2b_invoke_framework_v3",
];

describe("WITHDRAW_V3_ENTRIES — field mapping", () => {
  it("has the 5 entries in submission order with the expected arg counts", () => {
    expect(WITHDRAW_V3_ENTRIES.map((e) => e.fn)).toEqual(EXPECTED_ORDER);
    // Arg counts match the Move signatures (leading &signer excluded).
    const counts = Object.fromEntries(WITHDRAW_V3_ENTRIES.map((e) => [e.fn, e.keys.length]));
    expect(counts).toEqual({
      prepare_withdraw_proof_v3: 9,
      prepare_withdraw_attestation_v3: 12,
      prepare_withdraw_payload_v3: 17,
      withdraw_step2a_eunoma_verify_v3: 9,
      withdraw_step2b_invoke_framework_v3: 15,
    });
  });

  it("every entry key is a valid WithdrawV2CallArgs field (encodeV3EntryArgs does not throw)", () => {
    const args = fixtureCallArgs();
    for (const entry of WITHDRAW_V3_ENTRIES) {
      const encoded = encodeV3EntryArgs(entry, args);
      expect(encoded.length).toBe(entry.keys.length);
    }
  });
});

describe("createWithdrawV3Submitter — drives the 5 v3 txs", () => {
  it("submits all 5 entries in order, same profile, --simulate default, returns 5 tx hashes", async () => {
    const { fn, calls } = buildMultiMockSpawn();
    const submitter = createWithdrawV3Submitter("0xabc", "relayer-lowpriv", { spawnAptos: fn });
    const result = await submitter(fixtureCallArgs());

    expect(calls.length).toBe(5);
    expect(result.accepted).toBe(true);
    expect(result.simulated).toBe(true);
    expect(result.txHashes.length).toBe(5);

    calls.forEach((call, i) => {
      const fnIdx = call.args.indexOf("--function-id");
      expect(call.args[fnIdx + 1]).toBe(`0xabc::eunoma_bridge::${EXPECTED_ORDER[i]}`);
      // Consistent-submitter invariant: ALL 5 use the same dedicated relayer profile
      // (compose_pending_key namespaces step2a/step2b by submitter).
      const profIdx = call.args.indexOf("--profile");
      expect(call.args[profIdx + 1]).toBe("relayer-lowpriv");
      expect(call.args).toContain("--simulate");
      // The positional args after --args match the entry's mapped subset exactly.
      const argsIdx = call.args.indexOf("--args");
      const positional = call.args.slice(argsIdx + 1);
      expect(positional).toEqual(encodeV3EntryArgs(WITHDRAW_V3_ENTRIES[i], fixtureCallArgs()));
    });
  });

  it("omits --simulate when submit=true (env gate satisfied)", async () => {
    const { fn, calls } = buildMultiMockSpawn();
    const submitter = createWithdrawV3Submitter("0xabc", "relayer-lowpriv", {
      submit: true,
      env: { RELAYER_SUBMIT_ENABLED: "1" },
      spawnAptos: fn,
    });
    const result = await submitter(fixtureCallArgs());
    expect(result.simulated).toBe(false);
    for (const call of calls) expect(call.args).not.toContain("--simulate");
  });

  it("submit=true without RELAYER_SUBMIT_ENABLED=1 throws at construction", () => {
    expect(() =>
      createWithdrawV3Submitter("0xabc", "relayer-lowpriv", { submit: true, env: {} }),
    ).toThrow(/RELAYER_SUBMIT_ENABLED=1/);
  });

  it("rejects an invalid bridgePackage", () => {
    expect(() => createWithdrawV3Submitter("", "p")).toThrow();
    expect(() => createWithdrawV3Submitter("nothex", "p")).toThrow();
  });

  it("aborts the sequence on a failing tx (step 3) and never leaks stderr into the error", async () => {
    const { fn, calls } = buildMultiMockSpawn({
      exitCodes: [0, 0, 1], // 3rd tx (payload) fails
      stderr: "Error: insufficient gas at admin@0xff WALLET_PATH=/home/op/wallet.json",
    });
    const buffered: string[] = [];
    const submitter = createWithdrawV3Submitter("0xabc", "relayer-lowpriv", {
      spawnAptos: fn,
      stderrSink: { write: (c: string) => buffered.push(c) },
    });
    await expect(submitter(fixtureCallArgs())).rejects.toBeInstanceOf(RelayerSubmitterError);
    // Stopped after the 3rd (failing) tx — step2a/step2b never submitted.
    expect(calls.length).toBe(3);
    // stderr logged locally, NOT in the thrown error.
    const sinkText = buffered.join("");
    expect(sinkText).toContain("insufficient gas");
    try {
      await createWithdrawV3Submitter("0xabc", "relayer-lowpriv", {
        spawnAptos: buildMultiMockSpawn({ exitCodes: [0, 0, 1], stderr: "secret-stderr" }).fn,
        stderrSink: { write: () => {} },
      })(fixtureCallArgs());
    } catch (err) {
      expect((err as RelayerSubmitterError).message).not.toContain("secret-stderr");
      expect((err as RelayerSubmitterError).message).not.toContain("WALLET_PATH");
    }
  });
});

import { describe, expect, it } from "vitest";
import { type WithdrawV2CallArgs } from "@eunoma/deop-protocol";
import { RelayerSubmitterError, type SpawnAptosFn } from "../src/server.js";
import {
  WITHDRAW_V3_ENTRIES,
  createWithdrawV3Submitter,
  encodeV3EntryArgs,
} from "../src/withdraw_v3_submitter.js";

/** Same deterministic fixture as aptos_cli_submitter.test.ts. */
function fixtureCallArgs(opts: { partial?: boolean } = {}): WithdrawV2CallArgs {
  const hex32 = (seed: number): string =>
    Array.from({ length: 32 }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");
  const hexN = (n: number, seed: number): string =>
    Array.from({ length: n }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");
  const changeCommitment = opts.partial ? hex32(0x18) : "00".repeat(32);
  return {
    assetAddr: hex32(0x01),
    root: hex32(0x10),
    nullifierHash: hex32(0x11),
    recipient: hex32(0x12),
    recipientHash: hex32(0x13),
    amountTag: hex32(0x14),
    caPayloadHash: hex32(0x15),
    requestHash: hex32(0x16),
    aspRoot: hex32(0x17),
    stateTreeDepth: "4",
    aspTreeDepth: "3",
    changeCommitment,
    amountPDigest: hex32(0x19),
    amountPOld: Array.from({ length: 4 }, (_, i) => hex32(0x1a + i)),
    amountPRem: Array.from({ length: 4 }, (_, i) => (opts.partial ? hex32(0x1e + i) : "00".repeat(32))),
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

function buildScriptedMockSpawn(
  outputs: Array<{ exitCode?: number | null; stdout?: string; stderr?: string }>,
): {
  fn: SpawnAptosFn;
  calls: Array<{ command: string; args: string[] }>;
} {
  const calls: Array<{ command: string; args: string[] }> = [];
  const fn: SpawnAptosFn = (command, args) => {
    const idx = calls.length;
    calls.push({ command, args });
    const out = outputs[idx] ?? {};
    const exitCode = out.exitCode ?? 0;
    async function* stdoutGen() {
      if (out.stdout) yield out.stdout;
    }
    async function* stderrGen() {
      if (out.stderr) yield out.stderr;
    }
    return { stdout: stdoutGen(), stderr: stderrGen(), done: Promise.resolve(exitCode) };
  };
  return { fn, calls };
}

const EXPECTED_ORDER = [
  "prepare_withdraw_proof_v4",
  "prepare_withdraw_attestation_v3",
  "prepare_withdraw_payload_v3",
  "prepare_withdraw_conservation_v4",
  "withdraw_step2a_eunoma_verify_v3",
  "withdraw_step2b_invoke_framework_v3",
];

const expectedExecutedEntries = (args: WithdrawV2CallArgs) =>
  WITHDRAW_V3_ENTRIES.filter((entry) => !(entry.skip?.(args) ?? false));

describe("WITHDRAW_V3_ENTRIES — field mapping", () => {
  it("has the 6 entries in submission order with the expected arg counts", () => {
    expect(WITHDRAW_V3_ENTRIES.map((e) => e.fn)).toEqual(EXPECTED_ORDER);
    // Arg counts match the ACTUAL Move signatures (leading &signer excluded),
    // read positionally from eunoma_bridge.move — NOT a hand-maintained map.
    // V4 (CP5 RC1): asset_addr is the +1 routing key on the 4 registry-resolving
    // entries that take it as an explicit positional (proof/attestation/payload/
    // step2a: each +1). V4 (CP2 CP1): change_commitment public[12] is an
    // additional +1 positional on the 2 entries whose Move signature carries it
    // (prepare_withdraw_proof_v4 → 14, withdraw_step2a_eunoma_verify_v3 → 11);
    // prepare_withdraw_attestation_v3 (no proof) and prepare_withdraw_payload_v3
    // (no withdraw publics) do NOT take change_commitment.
    // withdraw_step2b_invoke_framework_v3 takes NO asset_addr / change_commitment
    // positional — it re-resolves the registry row + change_commitment from the
    // finalization row stored by step2a — so its shape is unchanged at 15.
    const counts = Object.fromEntries(WITHDRAW_V3_ENTRIES.map((e) => [e.fn, e.keys.length]));
    expect(counts).toEqual({
      prepare_withdraw_proof_v4: 14,
      prepare_withdraw_attestation_v3: 13,
      prepare_withdraw_payload_v3: 18,
      prepare_withdraw_conservation_v4: 6,
      withdraw_step2a_eunoma_verify_v3: 11,
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
    const args = fixtureCallArgs();
    const executed = expectedExecutedEntries(args);
    const result = await submitter(args);

    expect(calls.length).toBe(5);
    expect(result.accepted).toBe(true);
    expect(result.simulated).toBe(true);
    expect(result.txHashes.length).toBe(5);

    calls.forEach((call, i) => {
      const fnIdx = call.args.indexOf("--function-id");
      expect(call.args[fnIdx + 1]).toBe(`0xabc::eunoma_bridge::${executed[i].fn}`);
      // Consistent-submitter invariant: ALL 5 use the same dedicated relayer profile
      // (compose_pending_key namespaces step2a/step2b by submitter).
      const profIdx = call.args.indexOf("--profile");
      expect(call.args[profIdx + 1]).toBe("relayer-lowpriv");
      expect(call.args).toContain("--simulate");
      // The positional args after --args match the entry's mapped subset exactly.
      const argsIdx = call.args.indexOf("--args");
      const positional = call.args.slice(argsIdx + 1);
      expect(positional).toEqual(encodeV3EntryArgs(executed[i], args));
    });
  });

  it("runs the conservation tx for partial withdraws", async () => {
    const { fn, calls } = buildMultiMockSpawn();
    const submitter = createWithdrawV3Submitter("0xabc", "relayer-lowpriv", { spawnAptos: fn });
    const args = fixtureCallArgs({ partial: true });
    const executed = expectedExecutedEntries(args);
    const result = await submitter(args);

    expect(calls.length).toBe(6);
    expect(result.txHashes.length).toBe(6);
    expect(executed.map((entry) => entry.fn)).toEqual(EXPECTED_ORDER);
    const fns = calls.map((call) => {
      const fnIdx = call.args.indexOf("--function-id");
      return call.args[fnIdx + 1];
    });
    expect(fns).toContain("0xabc::eunoma_bridge::prepare_withdraw_conservation_v4");
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

  it("logs non-zero stdout locally with long hex redacted", async () => {
    const longHex = `0x${"ab".repeat(96)}`;
    const { fn } = buildScriptedMockSpawn([
      {
        exitCode: 1,
        stdout: `Simulation failed with status Move abort: E_PENDING_WITHDRAW_PROOF ${longHex}`,
      },
    ]);
    const buffered: string[] = [];
    const submitter = createWithdrawV3Submitter("0xabc", "relayer-lowpriv", {
      spawnAptos: fn,
      stderrSink: { write: (c: string) => buffered.push(c) },
    });
    await expect(submitter(fixtureCallArgs())).rejects.toBeInstanceOf(RelayerSubmitterError);
    const sinkText = buffered.join("");
    expect(sinkText).toContain("E_PENDING_WITHDRAW_PROOF");
    expect(sinkText).toContain("0x<redacted:192hex>");
    expect(sinkText).not.toContain(longHex);
  });

  it("retries Aptos fullnode rate-limit output when CLI exits 0 without a tx hash", async () => {
    const success = (idx: number) => ({
      stdout: JSON.stringify({ Result: { transaction_hash: `0x${idx.toString(16).padStart(64, "0")}` } }),
    });
    const { fn, calls } = buildScriptedMockSpawn([
      success(0),
      success(1),
      success(2),
      {
        stdout: JSON.stringify({
          Error:
            "API error: Unknown error Per anonymous IP rate limit exceeded. Limit: 40000 compute units per 300 seconds window.",
        }),
      },
      success(3),
      success(4),
      success(5),
      success(6),
    ]);
    const buffered: string[] = [];
    const submitter = createWithdrawV3Submitter("0xabc", "relayer-lowpriv", {
      submit: true,
      env: { RELAYER_SUBMIT_ENABLED: "1" },
      spawnAptos: fn,
      retryAttempts: 2,
      retryDelayMs: 0,
      stderrSink: { write: (c: string) => buffered.push(c) },
    });
    const result = await submitter(fixtureCallArgs({ partial: true }));

    expect(result.txHashes.length).toBe(6);
    expect(calls.length).toBe(7);
    const fns = calls.map((call) => call.args[call.args.indexOf("--function-id") + 1]);
    expect(fns[3]).toBe("0xabc::eunoma_bridge::prepare_withdraw_conservation_v4");
    expect(fns[4]).toBe("0xabc::eunoma_bridge::prepare_withdraw_conservation_v4");
    expect(buffered.join("")).toContain("retryable Aptos CLI transport failure");
  });

  it("defaults to a retry window long enough for the Aptos anonymous rate-limit window", async () => {
    const success = (idx: number) => ({
      stdout: JSON.stringify({ Result: { transaction_hash: `0x${idx.toString(16).padStart(64, "0")}` } }),
    });
    const rateLimit = {
      stdout: JSON.stringify({
        Error:
          "API error: Unknown error Per anonymous IP rate limit exceeded. Limit: 40000 compute units per 300 seconds window.",
      }),
    };
    const { fn, calls } = buildScriptedMockSpawn([
      ...Array.from({ length: 11 }, () => rateLimit),
      success(0),
      success(1),
      success(2),
      success(3),
      success(4),
      success(5),
    ]);
    const buffered: string[] = [];
    const submitter = createWithdrawV3Submitter("0xabc", "relayer-lowpriv", {
      submit: true,
      env: { RELAYER_SUBMIT_ENABLED: "1", RELAYER_APTOS_CLI_RETRY_DELAY_MS: "0" },
      spawnAptos: fn,
      stderrSink: { write: (c: string) => buffered.push(c) },
    });
    const result = await submitter(fixtureCallArgs({ partial: true }));

    expect(result.txHashes.length).toBe(6);
    expect(calls.length).toBe(17);
    expect(buffered.join("")).toContain("attempt 11/12");
  });

  it("recovers already-prepared payload state when a prior CLI call committed without a tx hash", async () => {
    const success = (idx: number) => ({
      stdout: JSON.stringify({ Result: { transaction_hash: `0x${idx.toString(16).padStart(64, "0")}` } }),
    });
    const { fn, calls } = buildScriptedMockSpawn([
      success(0),
      success(1),
      {
        stdout: JSON.stringify({
          Error:
            "API error: Unknown error Transaction committed on chain, but failed execution: Move abort in 0xabc::eunoma_bridge: E_PENDING_WITHDRAW_PAYLOAD(0x1b): ",
        }),
      },
      success(3),
      success(4),
      success(5),
    ]);
    const buffered: string[] = [];
    const done: Array<{ step: number; fn: string; txHash: string }> = [];
    const submitter = createWithdrawV3Submitter("0xabc", "relayer-lowpriv", {
      submit: true,
      env: { RELAYER_SUBMIT_ENABLED: "1" },
      spawnAptos: fn,
      stderrSink: { write: (c: string) => buffered.push(c) },
    });

    const result = await submitter(fixtureCallArgs({ partial: true }), {
      onStepDone: (step, entryFn, txHash) => done.push({ step, fn: entryFn, txHash }),
    });

    expect(calls.length).toBe(6);
    expect(result.txHashes).toEqual([
      "0x" + "0".repeat(64),
      "0x" + "1".padStart(64, "0"),
      "recovered:prepare_withdraw_payload_v3:step2",
      "0x" + "3".padStart(64, "0"),
      "0x" + "4".padStart(64, "0"),
      "0x" + "5".padStart(64, "0"),
    ]);
    expect(result.txHashes.at(-1)).toMatch(/^0x[0-9a-f]{64}$/);
    expect(done[2]).toEqual({
      step: 2,
      fn: "prepare_withdraw_payload_v3",
      txHash: "recovered:prepare_withdraw_payload_v3:step2",
    });
    expect(buffered.join("")).toContain("recovered already-prepared on-chain state");
  });

  it("surfaces already-spent nullifiers as terminal errors without retrying", async () => {
    const { fn, calls } = buildScriptedMockSpawn([
      {
        stdout: JSON.stringify({
          Error:
            "API error: Unknown error Transaction committed on chain, but failed execution: " +
            "Move abort in 0xabc::eunoma_bridge: E_NULLIFIER_ALREADY_SPENT(0x13): ",
        }),
      },
    ]);
    const buffered: string[] = [];
    const submitter = createWithdrawV3Submitter("0xabc", "relayer-lowpriv", {
      submit: true,
      env: { RELAYER_SUBMIT_ENABLED: "1" },
      spawnAptos: fn,
      retryAttempts: 3,
      retryDelayMs: 0,
      stderrSink: { write: (c: string) => buffered.push(c) },
    });

    await expect(submitter(fixtureCallArgs())).rejects.toMatchObject({
      code: "nullifier_already_spent",
      message: expect.stringContaining("E_NULLIFIER_ALREADY_SPENT"),
    });
    expect(calls.length).toBe(1);
    expect(buffered.join("")).toContain("terminal Move abort E_NULLIFIER_ALREADY_SPENT");
  });

  it("resumes after journal-completed split withdraw steps without replaying them", async () => {
    const { fn, calls } = buildMultiMockSpawn();
    const submitter = createWithdrawV3Submitter("0xabc", "relayer-lowpriv", {
      submit: true,
      env: { RELAYER_SUBMIT_ENABLED: "1" },
      spawnAptos: fn,
    });

    const result = await submitter(fixtureCallArgs({ partial: true }), {
      completedTxHashes: ["0x" + "a".repeat(64), "0x" + "b".repeat(64)],
      resumeAfterStep: 1,
    });

    expect(result.txHashes).toEqual([
      "0x" + "a".repeat(64),
      "0x" + "b".repeat(64),
      "0x" + "0".repeat(64),
      "0x" + "1".padStart(64, "0"),
      "0x" + "2".padStart(64, "0"),
      "0x" + "3".padStart(64, "0"),
    ]);
    expect(calls.length).toBe(4);
    const fns = calls.map((call) => call.args[call.args.indexOf("--function-id") + 1]);
    expect(fns).toEqual([
      "0xabc::eunoma_bridge::prepare_withdraw_payload_v3",
      "0xabc::eunoma_bridge::prepare_withdraw_conservation_v4",
      "0xabc::eunoma_bridge::withdraw_step2a_eunoma_verify_v3",
      "0xabc::eunoma_bridge::withdraw_step2b_invoke_framework_v3",
    ]);
  });
});

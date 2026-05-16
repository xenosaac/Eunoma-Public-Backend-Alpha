import { describe, expect, it } from "vitest";
import {
  WITHDRAW_V2_CALL_ARGS_ORDER,
  type WithdrawV2CallArgs,
} from "@eunoma/deop-protocol";
import {
  RelayerSubmitterError,
  createAptosCliSubmitter,
  encodeCallArgs,
  type SpawnAptosFn,
} from "../src/server.js";

/**
 * Deterministic 27-field WithdrawV2CallArgs. Mirrors the fixture used by
 * server.test.ts but typed (and slightly trimmed) so the CLI args are
 * inspectable in test assertions.
 */
function fixtureCallArgs(): WithdrawV2CallArgs {
  const hex32 = (seed: number): string =>
    Array.from({ length: 32 }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join(
      "",
    );
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

/**
 * Build a mock spawnAptos that captures the argv vector and emits a canned
 * stdout fixture. Resolves the done promise with the provided exit code.
 */
function buildMockSpawn(opts: {
  stdout?: string;
  stderr?: string;
  exitCode?: number | null;
  captureArgs: { command?: string; args?: string[] };
}): SpawnAptosFn {
  return (command, args) => {
    opts.captureArgs.command = command;
    opts.captureArgs.args = args;
    async function* stdoutGen() {
      if (opts.stdout) yield opts.stdout;
    }
    async function* stderrGen() {
      if (opts.stderr) yield opts.stderr;
    }
    return {
      stdout: stdoutGen(),
      stderr: stderrGen(),
      done: Promise.resolve(opts.exitCode ?? 0),
    };
  };
}

const APTOS_CLI_STDOUT_FIXTURE = JSON.stringify(
  {
    Result: {
      transaction_hash: "0x" + "ab".repeat(32),
      gas_used: 1234,
      gas_unit_price: 100,
      sender: "0x" + "12".repeat(32),
      success: true,
      version: 999999,
      vm_status: "Executed successfully",
    },
  },
  null,
  2,
);

describe("createAptosCliSubmitter — input validation", () => {
  it("rejects an empty bridgePackage", () => {
    expect(() => createAptosCliSubmitter("", undefined)).toThrow();
  });
  it("rejects a bridgePackage missing 0x prefix", () => {
    expect(() => createAptosCliSubmitter("abc123", undefined)).toThrow();
  });
});

describe("createAptosCliSubmitter — argv encoding", () => {
  it("emits --simulate by default and does NOT emit --simulate when submit=true", async () => {
    const capture: { command?: string; args?: string[] } = {};
    const submitter = createAptosCliSubmitter(
      "0xabc",
      "admin",
      {
        spawnAptos: buildMockSpawn({
          stdout: APTOS_CLI_STDOUT_FIXTURE,
          captureArgs: capture,
          exitCode: 0,
        }),
      },
    );
    await submitter(fixtureCallArgs());
    expect(capture.args).toContain("--simulate");

    const captureSubmit: { command?: string; args?: string[] } = {};
    const submitterReal = createAptosCliSubmitter(
      "0xabc",
      "admin",
      {
        submit: true,
        spawnAptos: buildMockSpawn({
          stdout: APTOS_CLI_STDOUT_FIXTURE,
          captureArgs: captureSubmit,
          exitCode: 0,
        }),
      },
    );
    await submitterReal(fixtureCallArgs());
    expect(captureSubmit.args).not.toContain("--simulate");
  });

  it("emits the canonical --function-id pointing at withdraw_to_recipient_v2", async () => {
    const capture: { command?: string; args?: string[] } = {};
    const submitter = createAptosCliSubmitter(
      "0xabc",
      undefined,
      {
        spawnAptos: buildMockSpawn({
          stdout: APTOS_CLI_STDOUT_FIXTURE,
          captureArgs: capture,
          exitCode: 0,
        }),
      },
    );
    await submitter(fixtureCallArgs());
    const fnIndex = capture.args!.indexOf("--function-id");
    expect(fnIndex).toBeGreaterThanOrEqual(0);
    expect(capture.args![fnIndex + 1]).toBe(
      "0xabc::eunoma_bridge::withdraw_to_recipient_v2",
    );
  });

  it("attaches --profile when adminProfile is set and omits it otherwise", async () => {
    const cap1: { command?: string; args?: string[] } = {};
    await createAptosCliSubmitter("0xabc", "admin-profile", {
      spawnAptos: buildMockSpawn({
        stdout: APTOS_CLI_STDOUT_FIXTURE,
        captureArgs: cap1,
        exitCode: 0,
      }),
    })(fixtureCallArgs());
    const profIdx = cap1.args!.indexOf("--profile");
    expect(profIdx).toBeGreaterThanOrEqual(0);
    expect(cap1.args![profIdx + 1]).toBe("admin-profile");

    const cap2: { command?: string; args?: string[] } = {};
    await createAptosCliSubmitter("0xabc", undefined, {
      spawnAptos: buildMockSpawn({
        stdout: APTOS_CLI_STDOUT_FIXTURE,
        captureArgs: cap2,
        exitCode: 0,
      }),
    })(fixtureCallArgs());
    expect(cap2.args).not.toContain("--profile");
  });

  it("emits the 27 positional args after --args in canonical Move order", async () => {
    const capture: { command?: string; args?: string[] } = {};
    const submitter = createAptosCliSubmitter("0xabc", undefined, {
      spawnAptos: buildMockSpawn({
        stdout: APTOS_CLI_STDOUT_FIXTURE,
        captureArgs: capture,
        exitCode: 0,
      }),
    });
    const args = fixtureCallArgs();
    await submitter(args);

    const argsIdx = capture.args!.indexOf("--args");
    expect(argsIdx).toBeGreaterThanOrEqual(0);
    const positional = capture.args!.slice(argsIdx + 1);
    expect(positional.length).toBe(27);

    // Recompute the expected positional vector from the canonical Move-order
    // manifest. If the encoder or the manifest drift, this catches it.
    const expected = encodeCallArgs(args);
    expect(positional).toEqual(expected);
    expect(expected.length).toBe(WITHDRAW_V2_CALL_ARGS_ORDER.length);

    // Smoke that each positional arg carries the expected aptos-cli type
    // prefix (u64:, hex:, u8:). The order is locked, so we can predict the
    // prefixes positionally.
    expect(positional[0]).toMatch(/^hex:0x/); // root
    expect(positional[7]).toMatch(/^u64:/); // vaultSequence
    expect(positional[9]).toMatch(/^u64:/); // expirySecs
    expect(positional[11]).toMatch(/^u8:/); // fallbackBitmap
    expect(positional[21]).toMatch(/^hex:\[/); // amountRVolunAuds (vector form)
  });
});

describe("createAptosCliSubmitter — stdout parsing", () => {
  it("returns the parsed tx hash and simulated=true by default", async () => {
    const expectedHash = "0x" + "ab".repeat(32);
    const submitter = createAptosCliSubmitter(
      "0xabc",
      undefined,
      {
        spawnAptos: buildMockSpawn({
          stdout: APTOS_CLI_STDOUT_FIXTURE,
          captureArgs: {},
          exitCode: 0,
        }),
      },
    );
    const result = await submitter(fixtureCallArgs());
    expect(result.accepted).toBe(true);
    expect(result.txHash).toBe(expectedHash);
    expect(result.simulated).toBe(true);
  });

  it("returns simulated=false when submit=true", async () => {
    const submitter = createAptosCliSubmitter(
      "0xabc",
      "admin",
      {
        submit: true,
        spawnAptos: buildMockSpawn({
          stdout: APTOS_CLI_STDOUT_FIXTURE,
          captureArgs: {},
          exitCode: 0,
        }),
      },
    );
    const result = await submitter(fixtureCallArgs());
    expect(result.simulated).toBe(false);
  });

  it("cli_submitter_stderr_not_in_http_response_body", async () => {
    // Killer test for the codex P2 finding: raw subprocess stderr must NEVER
    // appear in the thrown error message. Operators read their own logs to
    // see the underlying CLI failure; over-the-wire callers see only an
    // opaque `aptos_cli_error` code with a generic message.
    const stderrPayload =
      "Error: insufficient gas\nbacktrace: 0xdeadbeef at admin@0xff...\nWALLET_PATH=/home/op/wallet.json";
    const buffered: string[] = [];
    const submitter = createAptosCliSubmitter(
      "0xabc",
      undefined,
      {
        spawnAptos: buildMockSpawn({
          stdout: "",
          stderr: stderrPayload,
          captureArgs: {},
          exitCode: 1,
        }),
        stderrSink: { write: (chunk: string) => buffered.push(chunk) },
      },
    );
    try {
      await submitter(fixtureCallArgs());
      throw new Error("expected RelayerSubmitterError");
    } catch (err) {
      expect(err).toBeInstanceOf(RelayerSubmitterError);
      const submitErr = err as RelayerSubmitterError;
      expect(submitErr.code).toBe("aptos_cli_error");
      // Generic message — no stderr text leaks.
      expect(submitErr.message).toBe(
        "Aptos CLI invocation failed; check relayer logs for details.",
      );
      expect(submitErr.message).not.toContain("insufficient gas");
      expect(submitErr.message).not.toContain("backtrace");
      expect(submitErr.message).not.toContain("WALLET_PATH");
      expect(submitErr.message).not.toContain("0xdeadbeef");
    }
    // The stderr SHOULD have been logged locally to the injected sink.
    const sinkText = buffered.join("");
    expect(sinkText).toContain("insufficient gas");
    expect(sinkText).toContain("backtrace");
  });

  it("throws when the aptos CLI stdout is missing transaction_hash", async () => {
    const submitter = createAptosCliSubmitter(
      "0xabc",
      undefined,
      {
        spawnAptos: buildMockSpawn({
          stdout: '{"Result": {"foo": "bar"}}',
          captureArgs: {},
          exitCode: 0,
        }),
      },
    );
    await expect(submitter(fixtureCallArgs())).rejects.toThrow(/transaction_hash/);
  });
});

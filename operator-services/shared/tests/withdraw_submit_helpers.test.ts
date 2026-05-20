import { describe, expect, it } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  assembleWithdrawV2CallArgs,
  isNotImplementedPhasePassthrough,
  loadMpccaFinalizeTranscript,
  mpccaFinalizeTranscriptPath,
  waitForTx,
  WithdrawSubmitAssemblyError,
  type FinalizeTranscript,
  type FinalizeWithdrawV2CallArgsFields,
} from "../src/index.js";

const HEX32 = (seed: number): string =>
  Array.from({ length: 32 }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");
const HEXN = (n: number, seed: number): string =>
  Array.from({ length: n }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");

function validCallArgsFields(): FinalizeWithdrawV2CallArgsFields {
  return {
    root: HEX32(0x10),
    nullifierHash: HEX32(0x11),
    recipient: HEX32(0x12),
    recipientHash: HEX32(0x13),
    amountTag: HEX32(0x14),
    caPayloadHash: HEX32(0x15),
    requestHash: HEX32(0x16),
    vaultSequence: "42",
    expirySecs: "1800000000",
    withdrawProof: HEXN(192, 0x20),
    groupSignature: HEXN(64, 0x30),
    fallbackBitmap: 0,
    fallbackSignatures: [],
    newBalanceP: Array.from({ length: 8 }, (_, i) => HEX32(0x40 + i)),
    newBalanceR: Array.from({ length: 8 }, (_, i) => HEX32(0x50 + i)),
    newBalanceREffAud: [],
    amountP: Array.from({ length: 4 }, (_, i) => HEX32(0x60 + i)),
    amountRSender: Array.from({ length: 4 }, (_, i) => HEX32(0x70 + i)),
    amountRRecip: Array.from({ length: 4 }, (_, i) => HEX32(0x80 + i)),
    amountREffAud: [],
    ekVolunAuds: [],
    amountRVolunAuds: [],
    zkrpNewBalance: HEXN(672, 0x90),
    zkrpAmount: HEXN(672, 0xa0),
    sigmaProtoComm: Array.from({ length: 30 }, (_, i) => HEX32(0xb0 + i)),
    sigmaProtoResp: Array.from({ length: 25 }, (_, i) => HEX32(0xc0 + i)),
    memo: "",
  };
}

describe("mpccaFinalizeTranscriptPath — canonical layout", () => {
  it("builds <stateRoot>/coordinator/mpcca_withdraw/<dkgEpoch>__<requestId>__finalize.json", () => {
    const p = mpccaFinalizeTranscriptPath("/tmp/root", "1", "req-001");
    expect(p).toBe("/tmp/root/coordinator/mpcca_withdraw/1__req-001__finalize.json");
  });
});

describe("loadMpccaFinalizeTranscript — disk loader", () => {
  it("returns null when the transcript file is absent", async () => {
    const stateRoot = await mkdtemp(join(tmpdir(), "eunoma-finalize-noent-"));
    const result = await loadMpccaFinalizeTranscript(stateRoot, "1", "req-missing");
    expect(result).toBeNull();
  });

  it("loads a stub finalize transcript (notImplementedPhase only)", async () => {
    const stateRoot = await mkdtemp(join(tmpdir(), "eunoma-finalize-stub-"));
    const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
    await mkdir(dir, { recursive: true });
    const path = join(dir, "1__req-stub__finalize.json");
    await writeFile(
      path,
      JSON.stringify({
        scheme: "mpcca_withdraw_v2_finalize",
        dkgEpoch: "1",
        requestId: "req-stub",
        notImplementedPhase: "mpcca_withdraw_v2_finalize_aggregate_pending_milestone4",
      }),
    );
    const result = await loadMpccaFinalizeTranscript(stateRoot, "1", "req-stub");
    expect(result).toBeDefined();
    expect(result!.notImplementedPhase).toBe(
      "mpcca_withdraw_v2_finalize_aggregate_pending_milestone4",
    );
    expect(result!.withdrawV2CallArgsFields).toBeUndefined();
  });

  // Codex M5b P2 #3: the loader accepts an optional attestationConfig block that
  // scopes the deployment context the finalize aggregator used. None of these fields
  // enter WithdrawV2CallArgs; they ride into the submit artifact for the audit trail.
  it("loads_finalize_transcript_with_attestationConfig", async () => {
    const stateRoot = await mkdtemp(join(tmpdir(), "eunoma-finalize-attest-"));
    const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
    await mkdir(dir, { recursive: true });
    const path = join(dir, "1__req-attest__finalize.json");
    const attestationConfig = {
      chainId: 2,
      bridge: "ab".repeat(32),
      vault: "cd".repeat(32),
      assetType: "ef".repeat(32),
      operatorSetVersion: "1",
      rosterHash: "10".repeat(32),
      frostGroupPubkey: "20".repeat(32),
      circuitVersionsHash: "30".repeat(32),
    };
    await writeFile(
      path,
      JSON.stringify({
        scheme: "mpcca_withdraw_v2_finalize",
        dkgEpoch: "1",
        requestId: "req-attest",
        notImplementedPhase: "stub",
        attestationConfig,
      }),
    );
    const result = await loadMpccaFinalizeTranscript(stateRoot, "1", "req-attest");
    expect(result).toBeDefined();
    expect(result!.attestationConfig).toEqual(attestationConfig);
  });

  it("rejects_finalize_transcript_with_malformed_attestationConfig_chainId", async () => {
    const stateRoot = await mkdtemp(join(tmpdir(), "eunoma-finalize-attest-bad-"));
    const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
    await mkdir(dir, { recursive: true });
    const path = join(dir, "1__req-bad-attest__finalize.json");
    await writeFile(
      path,
      JSON.stringify({
        scheme: "mpcca_withdraw_v2_finalize",
        dkgEpoch: "1",
        requestId: "req-bad-attest",
        notImplementedPhase: "stub",
        attestationConfig: {
          chainId: "not-an-int",
          bridge: "ab".repeat(32),
          vault: "cd".repeat(32),
          assetType: "ef".repeat(32),
          operatorSetVersion: "1",
          rosterHash: "10".repeat(32),
          frostGroupPubkey: "20".repeat(32),
          circuitVersionsHash: "30".repeat(32),
        },
      }),
    );
    await expect(
      loadMpccaFinalizeTranscript(stateRoot, "1", "req-bad-attest"),
    ).rejects.toThrowError(/attestationConfig\.chainId must be a non-negative integer/);
  });

  it("loads a complete finalize transcript (withdrawV2CallArgsFields populated)", async () => {
    const stateRoot = await mkdtemp(join(tmpdir(), "eunoma-finalize-real-"));
    const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
    await mkdir(dir, { recursive: true });
    const path = join(dir, "1__req-real__finalize.json");
    const fields = validCallArgsFields();
    await writeFile(
      path,
      JSON.stringify({
        scheme: "mpcca_withdraw_v2_finalize",
        dkgEpoch: "1",
        requestId: "req-real",
        withdrawV2CallArgsFields: fields,
      }),
    );
    const result = await loadMpccaFinalizeTranscript(stateRoot, "1", "req-real");
    expect(result).toBeDefined();
    expect(result!.notImplementedPhase).toBeUndefined();
    expect(result!.withdrawV2CallArgsFields).toBeDefined();
    expect(result!.withdrawV2CallArgsFields!.root).toBe(fields.root);
  });

  // KILLER (Codex M5b P1 #2): the loader rejects a transcript whose embedded
  // (dkgEpoch, requestId) does not match the request tuple passed in. Previously
  // a misfiled transcript would pass shape checks and be assembled/submitted
  // under the caller's tuple, breaking auditability.
  it("rejects_transcript_whose_embedded_identity_differs_from_request_tuple", async () => {
    const stateRoot = await mkdtemp(join(tmpdir(), "eunoma-finalize-stale-id-"));
    const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
    await mkdir(dir, { recursive: true });
    // Misfile a transcript embedded with (epoch=2, requestId=req-A) under the
    // filename for (epoch=1, requestId=req-B).
    const misfiledPath = join(dir, "1__req-B__finalize.json");
    await writeFile(
      misfiledPath,
      JSON.stringify({
        scheme: "mpcca_withdraw_v2_finalize",
        dkgEpoch: "2",
        requestId: "req-A",
        notImplementedPhase: "stub",
      }),
    );
    await expect(
      loadMpccaFinalizeTranscript(stateRoot, "1", "req-B"),
    ).rejects.toMatchObject({
      code: "mpcca_finalize_transcript_identity_mismatch",
      message: expect.stringMatching(/does not match the request tuple/),
    });
  });

  it("rejects a transcript with wrong scheme", async () => {
    const stateRoot = await mkdtemp(join(tmpdir(), "eunoma-finalize-badscheme-"));
    const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
    await mkdir(dir, { recursive: true });
    const path = join(dir, "1__req-bad__finalize.json");
    await writeFile(
      path,
      JSON.stringify({
        scheme: "wrong_scheme",
        dkgEpoch: "1",
        requestId: "req-bad",
      }),
    );
    await expect(
      loadMpccaFinalizeTranscript(stateRoot, "1", "req-bad"),
    ).rejects.toThrowError(/scheme must be "mpcca_withdraw_v2_finalize"/);
  });

  it("rejects a transcript that's not valid JSON", async () => {
    const stateRoot = await mkdtemp(join(tmpdir(), "eunoma-finalize-badjson-"));
    const dir = join(stateRoot, "coordinator", "mpcca_withdraw");
    await mkdir(dir, { recursive: true });
    const path = join(dir, "1__req-badjson__finalize.json");
    await writeFile(path, "{not json");
    await expect(
      loadMpccaFinalizeTranscript(stateRoot, "1", "req-badjson"),
    ).rejects.toThrowError(/not valid JSON/);
  });
});

describe("assembleWithdrawV2CallArgs — NotImplemented passthrough vs full assembly", () => {
  // KILLER for M5b: the M3a stub case — finalize transcript with `notImplementedPhase`
  // set must produce the passthrough WITHOUT throwing, so the route can surface 501.
  it("returns { notImplementedPhase } when finalize is the M3a stub", () => {
    const finalize: FinalizeTranscript = {
      scheme: "mpcca_withdraw_v2_finalize",
      dkgEpoch: "1",
      requestId: "req-stub",
      notImplementedPhase: "mpcca_withdraw_v2_finalize_aggregate_pending_milestone4",
    };
    const result = assembleWithdrawV2CallArgs(finalize);
    expect(isNotImplementedPhasePassthrough(result)).toBe(true);
    if (isNotImplementedPhasePassthrough(result)) {
      expect(result.notImplementedPhase).toBe(
        "mpcca_withdraw_v2_finalize_aggregate_pending_milestone4",
      );
    }
  });

  it("assembles a 27-field WithdrawV2CallArgs from a complete finalize transcript", () => {
    const finalize: FinalizeTranscript = {
      scheme: "mpcca_withdraw_v2_finalize",
      dkgEpoch: "1",
      requestId: "req-real",
      withdrawV2CallArgsFields: validCallArgsFields(),
    };
    const result = assembleWithdrawV2CallArgs(finalize);
    expect(isNotImplementedPhasePassthrough(result)).toBe(false);
    if (!isNotImplementedPhasePassthrough(result)) {
      // 27-field projection — assert ALL keys are present.
      const keys = Object.keys(result);
      expect(keys).toContain("root");
      expect(keys).toContain("nullifierHash");
      expect(keys).toContain("recipient");
      expect(keys).toContain("recipientHash");
      expect(keys).toContain("amountTag");
      expect(keys).toContain("caPayloadHash");
      expect(keys).toContain("requestHash");
      expect(keys).toContain("vaultSequence");
      expect(keys).toContain("withdrawProof");
      expect(keys).toContain("expirySecs");
      expect(keys).toContain("groupSignature");
      expect(keys).toContain("fallbackBitmap");
      expect(keys).toContain("fallbackSignatures");
      expect(keys).toContain("newBalanceP");
      expect(keys).toContain("newBalanceR");
      expect(keys).toContain("newBalanceREffAud");
      expect(keys).toContain("amountP");
      expect(keys).toContain("amountRSender");
      expect(keys).toContain("amountRRecip");
      expect(keys).toContain("amountREffAud");
      expect(keys).toContain("ekVolunAuds");
      expect(keys).toContain("amountRVolunAuds");
      expect(keys).toContain("zkrpNewBalance");
      expect(keys).toContain("zkrpAmount");
      expect(keys).toContain("sigmaProtoComm");
      expect(keys).toContain("sigmaProtoResp");
      expect(keys).toContain("memo");
      expect(keys.length).toBe(27);
    }
  });

  it("rejects a finalize transcript with BOTH notImplementedPhase AND fields populated", () => {
    expect(() =>
      assembleWithdrawV2CallArgs({
        scheme: "mpcca_withdraw_v2_finalize",
        dkgEpoch: "1",
        requestId: "req-bad",
        notImplementedPhase: "stub",
        withdrawV2CallArgsFields: validCallArgsFields(),
      }),
    ).toThrowError(/mutually exclusive/);
  });

  it("rejects a finalize transcript with NEITHER set", () => {
    expect(() =>
      assembleWithdrawV2CallArgs({
        scheme: "mpcca_withdraw_v2_finalize",
        dkgEpoch: "1",
        requestId: "req-empty",
      }),
    ).toThrowError(/exactly one must be present/);
  });

  // KILLER (Codex M5b P1 #1): the assembler MUST enforce the M5a/M5b no-auditor invariant
  // before the relayer is ever called. Exercises each of the four auditor vectors
  // independently so a single-field regression fails the test.
  it("assembler_rejects_nonempty_auditor_fields_with_stable_code", () => {
    const cases: Array<[string, Partial<FinalizeWithdrawV2CallArgsFields>]> = [
      ["newBalanceREffAud", { newBalanceREffAud: ["ff".repeat(32)] }],
      ["amountREffAud", { amountREffAud: ["ff".repeat(32)] }],
      ["ekVolunAuds", { ekVolunAuds: ["ff".repeat(32)] }],
      ["amountRVolunAuds", { amountRVolunAuds: [["ff".repeat(32)]] }],
    ];
    for (const [label, overrides] of cases) {
      const fields: FinalizeWithdrawV2CallArgsFields = {
        ...validCallArgsFields(),
        ...overrides,
      };
      try {
        assembleWithdrawV2CallArgs({
          scheme: "mpcca_withdraw_v2_finalize",
          dkgEpoch: "1",
          requestId: "req-auditor",
          withdrawV2CallArgsFields: fields,
        });
        throw new Error(`expected rejection for ${label}`);
      } catch (err) {
        expect(err, label).toBeInstanceOf(WithdrawSubmitAssemblyError);
        expect((err as WithdrawSubmitAssemblyError).code, label).toBe(
          "auditor_branch_not_supported_in_milestone_5b",
        );
        expect((err as WithdrawSubmitAssemblyError).message, label).toMatch(
          /Eunoma is no-auditor today/,
        );
      }
    }
  });

  it("rejects a finalize transcript with mis-shaped root", () => {
    const fields = validCallArgsFields();
    fields.root = "ab".repeat(16); // wrong byte length
    expect(() =>
      assembleWithdrawV2CallArgs({
        scheme: "mpcca_withdraw_v2_finalize",
        dkgEpoch: "1",
        requestId: "req-x",
        withdrawV2CallArgsFields: fields,
      }),
    ).toThrowError(/root must be 32-byte hex/);
  });

  it("rejects a finalize transcript with a non-decimal vaultSequence", () => {
    const fields = validCallArgsFields();
    fields.vaultSequence = "abc";
    expect(() =>
      assembleWithdrawV2CallArgs({
        scheme: "mpcca_withdraw_v2_finalize",
        dkgEpoch: "1",
        requestId: "req-x",
        withdrawV2CallArgsFields: fields,
      }),
    ).toThrowError(/vaultSequence must be a decimal string/);
  });
});

describe("waitForTx — chain confirmation polling", () => {
  it("returns confirmed=true, success=true when chain returns a successful tx", async () => {
    let calls = 0;
    const fetchImpl: typeof fetch = async (_url) => {
      calls += 1;
      const body = JSON.stringify({
        success: true,
        vm_status: "Executed successfully",
      });
      return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
    };
    const result = await waitForTx("http://127.0.0.1:8080", "0xabc", {
      timeoutMs: 1000,
      pollIntervalMs: 10,
      fetchImpl,
    });
    expect(result.confirmed).toBe(true);
    expect(result.success).toBe(true);
    expect(result.vmStatus).toBe("Executed successfully");
    expect(calls).toBe(1);
  });

  it("returns confirmed=true, success=false on a failed tx", async () => {
    const fetchImpl: typeof fetch = async () =>
      new Response(JSON.stringify({ success: false, vm_status: "MOVE_ABORT" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    const result = await waitForTx("http://127.0.0.1:8080", "0xabc", {
      timeoutMs: 200,
      pollIntervalMs: 10,
      fetchImpl,
    });
    expect(result.confirmed).toBe(true);
    expect(result.success).toBe(false);
    expect(result.vmStatus).toBe("MOVE_ABORT");
  });

  it("polls through 'pending_transaction' responses until success", async () => {
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls += 1;
      if (calls < 3) {
        return new Response(JSON.stringify({ type: "pending_transaction" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ success: true, vm_status: "ok" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
    const result = await waitForTx("http://127.0.0.1:8080", "0xabc", {
      timeoutMs: 2000,
      pollIntervalMs: 5,
      fetchImpl,
    });
    expect(result.confirmed).toBe(true);
    expect(result.success).toBe(true);
    expect(calls).toBeGreaterThanOrEqual(3);
  });

  it("returns confirmed=false when the deadline elapses with the tx still pending", async () => {
    const fetchImpl: typeof fetch = async () =>
      new Response(JSON.stringify({ type: "pending_transaction" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    const result = await waitForTx("http://127.0.0.1:8080", "0xabc", {
      timeoutMs: 50,
      pollIntervalMs: 10,
      fetchImpl,
    });
    expect(result.confirmed).toBe(false);
  });

  it("treats 404 as 'not found yet' and polls", async () => {
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls += 1;
      if (calls < 2) {
        return new Response("not found", { status: 404 });
      }
      return new Response(JSON.stringify({ success: true, vm_status: "ok" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
    const result = await waitForTx("http://127.0.0.1:8080", "0xabc", {
      timeoutMs: 1000,
      pollIntervalMs: 5,
      fetchImpl,
    });
    expect(result.confirmed).toBe(true);
    expect(result.success).toBe(true);
  });

  it("throws on non-404 HTTP errors", async () => {
    const fetchImpl: typeof fetch = async () =>
      new Response("bad gateway", { status: 502 });
    await expect(
      waitForTx("http://127.0.0.1:8080", "0xabc", {
        timeoutMs: 200,
        pollIntervalMs: 10,
        fetchImpl,
      }),
    ).rejects.toThrowError(/poll .* -> 502/);
  });

  it("rejects malformed txHash before contacting the network", async () => {
    let called = false;
    const fetchImpl: typeof fetch = async () => {
      called = true;
      return new Response("{}", { status: 200 });
    };
    await expect(
      waitForTx("http://127.0.0.1:8080", "not-a-tx-hash", { fetchImpl }),
    ).rejects.toThrowError(/txHash must be 0x-prefixed hex/);
    expect(called).toBe(false);
  });
});

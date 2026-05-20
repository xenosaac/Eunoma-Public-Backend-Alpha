import { describe, expect, it } from "vitest";
import {
  EUNOMA_MPCCA_WITHDRAW_SUBMIT_V1,
  ForbiddenPlaintextFieldError,
  MpccaWithdrawSubmitError,
  parseMpccaWithdrawSubmitRequest,
  parseMpccaWithdrawSubmitResponse,
} from "../src/index.js";

const HEX32 = "ab".repeat(32);

describe("mpcca_withdraw_submit — domain constant", () => {
  it("EUNOMA_MPCCA_WITHDRAW_SUBMIT_V1 is the canonical string", () => {
    // Locked-in domain string: if a future refactor changes this, the persisted
    // submit-transcript artifact hash will silently change → the test catches it.
    expect(EUNOMA_MPCCA_WITHDRAW_SUBMIT_V1).toBe("EUNOMA_MPCCA_WITHDRAW_SUBMIT_V1");
  });
});

describe("parseMpccaWithdrawSubmitRequest — happy path + shape validation", () => {
  it("accepts minimal valid request", () => {
    const parsed = parseMpccaWithdrawSubmitRequest({
      dkgEpoch: "1",
      requestId: "withdraw-req-001",
    });
    expect(parsed).toEqual({
      dkgEpoch: "1",
      requestId: "withdraw-req-001",
    });
  });

  it("accepts request with relayerOverrides", () => {
    const parsed = parseMpccaWithdrawSubmitRequest({
      dkgEpoch: "5",
      requestId: "withdraw-req-002",
      relayerOverrides: {
        relayerUrl: "http://127.0.0.1:4300",
        relayerBearerToken: "tok-1",
      },
    });
    expect(parsed.relayerOverrides).toEqual({
      relayerUrl: "http://127.0.0.1:4300",
      relayerBearerToken: "tok-1",
    });
  });

  it("rejects non-decimal dkgEpoch", () => {
    expect(() =>
      parseMpccaWithdrawSubmitRequest({ dkgEpoch: "abc", requestId: "x" }),
    ).toThrowError(/dkgEpoch must be a non-empty decimal string/);
  });

  it("rejects empty requestId", () => {
    expect(() => parseMpccaWithdrawSubmitRequest({ dkgEpoch: "1", requestId: "" })).toThrowError(
      /requestId must be a non-empty string/,
    );
  });

  it("rejects non-object body", () => {
    expect(() => parseMpccaWithdrawSubmitRequest(42)).toThrowError(/body must be an object/);
    expect(() => parseMpccaWithdrawSubmitRequest([])).toThrowError(/body must be an object/);
  });

  it("rejects relayerOverrides with malformed URL", () => {
    expect(() =>
      parseMpccaWithdrawSubmitRequest({
        dkgEpoch: "1",
        requestId: "x",
        relayerOverrides: { relayerUrl: "not a url" },
      }),
    ).toThrowError(/relayerOverrides.relayerUrl must be a valid URL/);
  });
});

describe("parseMpccaWithdrawSubmitRequest — forbidden-plaintext-field guard", () => {
  // KILLER: the parser runs the recursive forbidden-field guard FIRST, BEFORE any shape
  // validation. Even if `amount` is nested under `relayerOverrides`, the gate trips.
  it("rejects top-level amount field", () => {
    let caught: unknown;
    try {
      parseMpccaWithdrawSubmitRequest({
        dkgEpoch: "1",
        requestId: "x",
        amount: "1000",
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ForbiddenPlaintextFieldError);
    expect((caught as ForbiddenPlaintextFieldError).path).toBe("amount");
  });

  it("rejects nested secret_share field", () => {
    let caught: unknown;
    try {
      parseMpccaWithdrawSubmitRequest({
        dkgEpoch: "1",
        requestId: "x",
        relayerOverrides: { secret_share: "deadbeef" },
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ForbiddenPlaintextFieldError);
    expect((caught as ForbiddenPlaintextFieldError).path).toBe("relayerOverrides.secret_share");
  });

  it("rejects nested vault_dk field", () => {
    let caught: unknown;
    try {
      parseMpccaWithdrawSubmitRequest({
        dkgEpoch: "1",
        requestId: "x",
        vault_dk: HEX32,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ForbiddenPlaintextFieldError);
  });
});

describe("parseMpccaWithdrawSubmitResponse — round-trip + shape", () => {
  function validResponseBody(): Record<string, unknown> {
    return {
      accepted: true,
      requestId: "withdraw-req-001",
      dkgEpoch: "1",
      txHash: "0x" + "aa".repeat(32),
      simulated: true,
      transcriptHash: HEX32,
      transcriptPath: "/tmp/state/coordinator/mpcca_withdraw_submit/1__withdraw-req-001.json",
      completed: true,
    };
  }

  it("round-trips a successful submit response", () => {
    const body = validResponseBody();
    const parsed = parseMpccaWithdrawSubmitResponse(body);
    expect(parsed.accepted).toBe(true);
    expect(parsed.simulated).toBe(true);
    expect(parsed.completed).toBe(true);
    expect(parsed.txHash).toBe(body.txHash);
    // Hex normalised (lowercase, no 0x prefix).
    expect(parsed.transcriptHash).toBe(HEX32);
  });

  it("round-trips a NotImplemented stub response (no txHash, completed=false)", () => {
    const parsed = parseMpccaWithdrawSubmitResponse({
      accepted: false,
      requestId: "withdraw-req-002",
      dkgEpoch: "1",
      simulated: true,
      transcriptHash: HEX32,
      transcriptPath: "/tmp/state/coordinator/mpcca_withdraw_submit/1__withdraw-req-002.json",
      completed: false,
      notImplementedPhase: "mpcca_withdraw_v2_finalize_pending_milestone4",
    });
    expect(parsed.completed).toBe(false);
    expect(parsed.notImplementedPhase).toBe("mpcca_withdraw_v2_finalize_pending_milestone4");
    expect(parsed.txHash).toBeUndefined();
  });

  it("rejects missing transcriptHash", () => {
    const body = { ...validResponseBody() };
    delete body.transcriptHash;
    expect(() => parseMpccaWithdrawSubmitResponse(body)).toThrowError(
      /transcriptHash must be a non-empty hex string/,
    );
  });

  it("rejects transcriptHash with wrong byte length", () => {
    expect(() =>
      parseMpccaWithdrawSubmitResponse({
        ...validResponseBody(),
        transcriptHash: "ab".repeat(16), // 16 bytes, not 32
      }),
    ).toThrowError(/transcriptHash must be 32-byte hex/);
  });

  it("rejects non-boolean accepted", () => {
    expect(() =>
      parseMpccaWithdrawSubmitResponse({ ...validResponseBody(), accepted: "yes" }),
    ).toThrowError(/accepted must be a boolean/);
  });

  it("rejects forbidden plaintext field in response", () => {
    // Defense-in-depth: even on the response side, forbidden plaintext fields are rejected.
    let caught: unknown;
    try {
      parseMpccaWithdrawSubmitResponse({ ...validResponseBody(), nullifier: "deadbeef" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ForbiddenPlaintextFieldError);
  });
});

describe("MpccaWithdrawSubmitError — error-code surface", () => {
  it("captures the code on the error instance", () => {
    const err = new MpccaWithdrawSubmitError(
      "mpcca_finalize_transcript_not_found",
      "no transcript on disk",
    );
    expect(err.code).toBe("mpcca_finalize_transcript_not_found");
    expect(err.message).toBe("no transcript on disk");
    expect(err.name).toBe("MpccaWithdrawSubmitError");
  });
});

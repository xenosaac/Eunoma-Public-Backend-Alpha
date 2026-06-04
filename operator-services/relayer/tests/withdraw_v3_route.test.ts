import { describe, expect, it } from "vitest";
import {
  RelayerSubmitterError,
  type WithdrawV3SubmitterFn,
  buildRelayerServer,
} from "../src/server.js";
import { VaultSequencer } from "../src/vault_sequencer.js";
import { FileSubmitJournal } from "../src/submit_journal.js";
import type { GasGuard } from "../src/gas_guard.js";

function validWithdrawV2Body(): Record<string, unknown> {
  const hex32 = (seed: number): string =>
    Array.from({ length: 32 }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");
  const hexN = (n: number, seed: number): string =>
    Array.from({ length: n }, (_, i) => ((i + seed) & 0xff).toString(16).padStart(2, "0")).join("");
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
    changeCommitment: hex32(0x18),
    amountPDigest: hex32(0x19),
    amountPOld: Array.from({ length: 4 }, (_, i) => hex32(0x1a + i)),
    amountPRem: Array.from({ length: 4 }, (_, i) => hex32(0x1e + i)),
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

/** A submitter that exercises the 5-step journal hooks then returns 5 hashes. */
const fiveStepSubmitter = (onCalled?: () => void): WithdrawV3SubmitterFn => {
  return async (_args, hooks) => {
    onCalled?.();
    const txHashes: string[] = [];
    for (let i = 0; i < 5; i++) {
      hooks?.onStepStart?.(i, `fn${i}`);
      txHashes.push(`0x${i.toString(16).padStart(64, "0")}`);
      hooks?.onStepDone?.(i, `fn${i}`, txHashes[i]);
    }
    return { accepted: true, simulated: true, txHashes };
  };
};

const allowGuard: GasGuard = { check: async () => ({ allow: true, gasUnitPrice: 100n }) };
const openGuard: GasGuard = {
  check: async () => ({ allow: false, reason: "gas_price_circuit_breaker_open", gasUnitPrice: 999n }),
};

describe("relayer /v3/relayer/submit/withdraw", () => {
  it("returns 501 when no v3 submitter is configured", async () => {
    const server = buildRelayerServer({});
    const res = await server.inject({
      method: "POST",
      url: "/v3/relayer/submit/withdraw",
      payload: validWithdrawV2Body(),
    });
    expect(res.statusCode).toBe(501);
  });

  it("refuses with self_submit (200) when the gas breaker is open, WITHOUT calling the submitter", async () => {
    let called = false;
    const server = buildRelayerServer({
      withdrawV3Submitter: fiveStepSubmitter(() => {
        called = true;
      }),
      gasGuard: openGuard,
    });
    const res = await server.inject({
      method: "POST",
      url: "/v3/relayer/submit/withdraw",
      payload: validWithdrawV2Body(),
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ action: "self_submit", reason: "gas_price_circuit_breaker_open" });
    expect(called).toBe(false); // step2a must NOT land when we bail to self-submit
  });

  it("submits via the sequencer and records all 5 steps in the journal on success", async () => {
    let called = false;
    const journal = new FileSubmitJournal({ now: () => 1 });
    const server = buildRelayerServer({
      withdrawV3Submitter: fiveStepSubmitter(() => {
        called = true;
      }),
      gasGuard: allowGuard,
      sequencer: new VaultSequencer(),
      journal,
    });
    const body = validWithdrawV2Body();
    const res = await server.inject({
      method: "POST",
      url: "/v3/relayer/submit/withdraw",
      payload: body,
    });
    expect(res.statusCode).toBe(202);
    const json = res.json();
    expect(json.accepted).toBe(true);
    expect(json.txHashes.length).toBe(5);
    expect(called).toBe(true);
    // Journal recorded per-step completion keyed by request_hash.
    expect(journal.lastCompletedStep(body.requestHash as string)).toBe(4);
  });

  it("passes consecutive completed journal steps to the submitter for resume", async () => {
    const body = validWithdrawV2Body();
    const journal = new FileSubmitJournal({ now: () => 1 });
    journal.recordIntent(body.requestHash as string, 0);
    journal.recordCompleted(body.requestHash as string, 0, "0x" + "a".repeat(64));
    journal.recordIntent(body.requestHash as string, 1);
    journal.recordCompleted(body.requestHash as string, 1, "0x" + "b".repeat(64));
    journal.recordIntent(body.requestHash as string, 3);
    journal.recordCompleted(body.requestHash as string, 3, "0x" + "d".repeat(64));

    let observed:
      | {
          completedTxHashes?: string[];
          resumeAfterStep?: number;
        }
      | undefined;
    const server = buildRelayerServer({
      gasGuard: allowGuard,
      journal,
      withdrawV3Submitter: async (_args, hooks) => {
        observed = {
          completedTxHashes: hooks?.completedTxHashes,
          resumeAfterStep: hooks?.resumeAfterStep,
        };
        hooks?.onStepStart?.(2, "fn2");
        hooks?.onStepDone?.(2, "fn2", "0x" + "c".repeat(64));
        return {
          accepted: true,
          simulated: false,
          txHashes: [...(hooks?.completedTxHashes ?? []), "0x" + "c".repeat(64)],
        };
      },
    });

    const res = await server.inject({
      method: "POST",
      url: "/v3/relayer/submit/withdraw",
      payload: body,
    });

    expect(res.statusCode).toBe(202);
    expect(observed).toEqual({
      completedTxHashes: ["0x" + "a".repeat(64), "0x" + "b".repeat(64)],
      resumeAfterStep: 1,
    });
    expect(journal.lastCompletedStep(body.requestHash as string)).toBe(3);
  });

  it("rejects a forbidden plaintext field with 400", async () => {
    const server = buildRelayerServer({ withdrawV3Submitter: fiveStepSubmitter() });
    const body = validWithdrawV2Body();
    body.amount = "1000";
    const res = await server.inject({
      method: "POST",
      url: "/v3/relayer/submit/withdraw",
      payload: body,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("forbidden_plaintext_field");
  });

  it("surfaces a RelayerSubmitterError as 502 submit_failed (no stderr leak)", async () => {
    const server = buildRelayerServer({
      gasGuard: allowGuard,
      withdrawV3Submitter: async () => {
        throw new RelayerSubmitterError("aptos_cli_error", "generic; check logs");
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v3/relayer/submit/withdraw",
      payload: validWithdrawV2Body(),
    });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("submit_failed");
    expect(res.json().code).toBe("aptos_cli_error");
  });

  it("surfaces already-spent nullifiers as terminal 409 submit failures", async () => {
    const server = buildRelayerServer({
      gasGuard: allowGuard,
      withdrawV3Submitter: async () => {
        throw new RelayerSubmitterError(
          "nullifier_already_spent",
          "prepare_withdraw_proof_v4 failed because the note was already spent (E_NULLIFIER_ALREADY_SPENT)"
        );
      },
    });
    const res = await server.inject({
      method: "POST",
      url: "/v3/relayer/submit/withdraw",
      payload: validWithdrawV2Body(),
    });
    expect(res.statusCode).toBe(409);
    const body = res.json();
    expect(body.error).toBe("submit_failed");
    expect(body.code).toBe("nullifier_already_spent");
  });
});

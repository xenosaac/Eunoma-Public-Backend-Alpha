import { describe, expect, it } from "vitest";
import { buildRelayerServer } from "../src/index.js";

describe("relayer", () => {
  it("rejects forbidden plaintext fields", async () => {
    const server = buildRelayerServer();
    const res = await server.inject({
      method: "POST",
      url: "/v2/relayer/submit",
      payload: { requestId: "r", secret: "bad" },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("forbidden_plaintext_field");
  });

  it("passes valid submit payload to configured submitter", async () => {
    const server = buildRelayerServer({
      submitter: async (body) => ({
        accepted: true,
        requestId: body.requestId,
        txHash: "aa".repeat(32),
      }),
    });
    const res = await server.inject({
      method: "POST",
      url: "/v2/relayer/submit",
      payload: {
        requestId: "r",
        signedTransactionBcs: "00",
        attestationHash: "11".repeat(32),
        caPayloadHash: "22".repeat(32),
      },
    });
    expect(res.statusCode).toBe(202);
    expect(res.json().txHash).toBe("aa".repeat(32));
  });
});

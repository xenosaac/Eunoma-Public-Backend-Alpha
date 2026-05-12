// Partner operator Fastify server (HANDOFF Section 6.3).
//
// Endpoints:
//   POST /v1/cosign/deposit — verify + sign attestation message
//   GET  /v1/health
//   GET  /v1/operator-info

import Fastify, { FastifyInstance } from "fastify";
import { bearerAuthHook, keccak256, rateLimitHook } from "@eunoma/shared";
import { PartnerOperatorConfig } from "./config.js";
import {
  CoSignRequestBody,
  verifyCoSignRequest,
} from "./verify/cosign_request.js";
import {
  WithdrawCoSignRequestBody,
  WithdrawCoSignVerifyHooks,
  verifyWithdrawCoSignRequest,
} from "./verify/withdraw_cosign_request.js";

export interface PartnerServerHooks {
  /// CP4 — withdraw cosign verifier hooks (chain reader / Groth16 verifier).
  withdrawVerify?: WithdrawCoSignVerifyHooks;
}

export function buildPartnerServer(
  cfg: PartnerOperatorConfig,
  hooks: PartnerServerHooks = {},
): FastifyInstance {
  const fastify = Fastify({ logger: false });

  fastify.addHook(
    "onRequest",
    bearerAuthHook({
      expectedToken: cfg.bearer_token,
      exemptPaths: ["/v1/health"],
    }),
  );
  fastify.addHook(
    "onRequest",
    rateLimitHook({
      maxPerWindow: cfg.rate_limit_max_per_window,
      windowMs: cfg.rate_limit_window_ms,
      paths: ["/v1/cosign/deposit", "/v1/cosign/withdraw"],
    }),
  );

  fastify.get("/v1/health", async () => ({ ok: true, slot: cfg.slot }));

  fastify.get("/v1/operator-info", async () => ({
    slot: cfg.slot,
    operator_set_version: cfg.operator_set_version.toString(),
    threshold: cfg.threshold.toString(),
    pubkey_hex: Buffer.from(cfg.signer.publicKey()).toString("hex"),
  }));

  fastify.post("/v1/cosign/deposit", async (req, reply) => {
    const body = req.body as CoSignRequestBody;
    if (!body || typeof body !== "object") {
      return reply.code(400).send({ error: "missing_body" });
    }

    const now_secs = Math.floor(Date.now() / 1000);
    const result = await verifyCoSignRequest(cfg, body, now_secs);
    if (!result.ok || !result.msg_bytes) {
      return reply.code(400).send({
        error: "cosign_rejected",
        reason: result.reason ?? "unknown",
      });
    }

    const sig = await cfg.signer.sign(result.msg_bytes);
    const msg_hash = keccak256(result.msg_bytes);

    return reply.code(200).send({
      slot: cfg.slot,
      signature_hex: Buffer.from(sig).toString("hex"),
      pubkey_hex: Buffer.from(cfg.signer.publicKey()).toString("hex"),
      message_bytes_hash_hex: Buffer.from(msg_hash).toString("hex"),
    });
  });

  fastify.post("/v1/cosign/withdraw", async (req, reply) => {
    const body = req.body as WithdrawCoSignRequestBody;
    if (!body || typeof body !== "object") {
      return reply.code(400).send({ error: "missing_body" });
    }
    const now_secs = Math.floor(Date.now() / 1000);
    const result = await verifyWithdrawCoSignRequest(
      cfg,
      body,
      now_secs,
      hooks.withdrawVerify ?? {},
    );
    if (!result.ok || !result.msg_bytes) {
      return reply.code(400).send({
        error: "cosign_rejected",
        reason: result.reason ?? "unknown",
      });
    }
    const sig = await cfg.signer.sign(result.msg_bytes);
    const msg_hash = keccak256(result.msg_bytes);
    return reply.code(200).send({
      slot: cfg.slot,
      signature_hex: Buffer.from(sig).toString("hex"),
      pubkey_hex: Buffer.from(cfg.signer.publicKey()).toString("hex"),
      message_bytes_hash_hex: Buffer.from(msg_hash).toString("hex"),
    });
  });

  return fastify;
}

// Start function for production use.
export async function startPartnerServer(
  cfg: PartnerOperatorConfig,
  hooks: PartnerServerHooks = {},
): Promise<{
  server: FastifyInstance;
  url: string;
}> {
  const server = buildPartnerServer(cfg, hooks);
  const address = await server.listen({ port: cfg.port, host: "127.0.0.1" });
  return { server, url: address };
}

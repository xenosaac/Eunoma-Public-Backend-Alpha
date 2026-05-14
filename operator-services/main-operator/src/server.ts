// Main operator Fastify server (HANDOFF Section 6.2).

import Fastify, { FastifyInstance } from "fastify";
import {
  AttestationResult,
  bearerAuthHook,
  buildDepositAttestationMessage,
  hexToBytes,
  InMemoryStore,
  keccak256,
  rateLimitHook,
  Store,
  verifyEd25519,
} from "@eunoma/shared";
import { CoSignRequestBody } from "@eunoma/partner-operator/src/verify/cosign_request.js";
import { MainOperatorConfig } from "./config.js";
import {
  DepositRequestBodyMain,
  verifyDepositRequest,
} from "./verify/deposit_request.js";
import { fanOutCoSignRequests } from "./partner_client.js";
import { registerRecipientRolloverRoute } from "./routes/recipient_rollover.js";
import { registerWithdrawRoutes, type WithdrawRouteHooks } from "./routes/withdraw.js";
import { registerAppConfigRoute, type AppConfigRouteHooks } from "./routes/app_config.js";
import { registerRootRoutes, type RootRouteHooks } from "./routes/root.js";
import { randomUUID } from "node:crypto";

export interface MainServerOptions {
  cfg: MainOperatorConfig;
  store?: Store;
  /// Optional injection of stubs for /v1/withdraw/* (chain reader, CA payload
  /// builder, Groth16 verifier, partner cosign fanout). Default {} — production.
  withdrawRouteHooks?: WithdrawRouteHooks;
  appConfigRouteHooks?: AppConfigRouteHooks;
  rootRouteHooks?: RootRouteHooks;
}

const ALLOWED_CORS_ORIGINS = new Set([
  "https://app.eunoma.xyz",
  "http://localhost:3000",
  "http://localhost:3008",
]);

export function buildMainServer(opts: MainServerOptions): {
  server: FastifyInstance;
  store: Store;
} {
  const cfg = opts.cfg;
  const store: Store = opts.store ?? new InMemoryStore();

  const fastify = Fastify({ logger: false });

  fastify.addHook("onRequest", async (req, reply) => {
    const origin = req.headers.origin;
    if (origin && ALLOWED_CORS_ORIGINS.has(origin)) {
      reply.header("Access-Control-Allow-Origin", origin);
      reply.header("Vary", "Origin");
      reply.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
      reply.header("Access-Control-Allow-Headers", "authorization,content-type");
      reply.header("Access-Control-Max-Age", "600");
    }
    if (req.method === "OPTIONS") {
      reply.code(204).send();
      return reply;
    }
  });

  // W1: bearer-token auth for all non-public routes + rate limit on
  // heavy verification endpoints. Both run as onRequest hooks.
  fastify.addHook(
    "onRequest",
    bearerAuthHook({
      expectedToken: cfg.bearer_token,
      exemptPaths: ["/v1/health", "/v1/app/config", "/v1/root/current"],
    }),
  );
  fastify.addHook(
    "onRequest",
    rateLimitHook({
      maxPerWindow: cfg.rate_limit_max_per_window,
      windowMs: cfg.rate_limit_window_ms,
      paths: ["/v1/deposit/request-attestation"],
    }),
  );

  fastify.get("/v1/health", async () => ({ ok: true, slot: cfg.main_slot }));

  registerAppConfigRoute(fastify, cfg, opts.appConfigRouteHooks ?? {});
  registerRootRoutes(fastify, cfg, opts.rootRouteHooks ?? {});
  registerRecipientRolloverRoute(fastify);
  registerWithdrawRoutes(fastify, store, cfg, opts.withdrawRouteHooks ?? {});

  fastify.get("/v1/operator-set", async () => ({
    operator_set_version: cfg.operator_set_version.toString(),
    threshold: cfg.threshold.toString(),
    main_index: cfg.main_slot,
    pubkeys_hex: cfg.partner_pubkeys.map((b) => Buffer.from(b).toString("hex")),
    partner_urls: cfg.partner_urls,
  }));

  fastify.get("/v1/vault/state", async () => ({
    vault_addr: Buffer.from(cfg.vault_addr).toString("hex"),
    asset_type: Buffer.from(cfg.asset_type).toString("hex"),
    chain_id: cfg.chain_id,
    pool_id: cfg.pool_id.toString(),
  }));

  fastify.post("/v1/deposit/request-attestation", async (req, reply) => {
    const body = req.body as DepositRequestBodyMain;
    if (!body || typeof body !== "object") {
      return reply.code(400).send({ error: "missing_body" });
    }

    const now_secs = Math.floor(Date.now() / 1000);
    let verification;
    try {
      verification = await verifyDepositRequest(cfg, body, now_secs);
    } catch {
      return reply.code(400).send({
        error: "deposit_request_rejected",
        reason: "malformed_payload",
      });
    }
    if (!verification.ok || !verification.ca_payload_hash) {
      return reply.code(400).send({
        error: "deposit_request_rejected",
        reason: verification.reason ?? "unknown",
      });
    }

    // Build the canonical attestation message.
    const commitment = hexToBytes(body.commitment);
    const amount_tag = hexToBytes(body.amount_tag);
    const deposit_nonce = hexToBytes(body.deposit_nonce);
    const expiry = BigInt(body.expiry_secs);
    const ca_payload_hash = verification.ca_payload_hash;

    const { msg_bytes } = buildDepositAttestationMessage({
      chain_id: cfg.chain_id,
      pool_id: cfg.pool_id,
      operator_set_version: cfg.operator_set_version,
      threshold: cfg.threshold,
      vault_addr: cfg.vault_addr,
      asset_type: cfg.asset_type,
      commitment,
      amount_tag,
      ca_payload_hash,
      deposit_nonce,
      expiry_secs: expiry,
    });

    // Persist deposit request.
    const request_id = randomUUID();
    await store.insertDepositRequest({
      request_id,
      user_addr: body.user_addr,
      vault_addr: Buffer.from(cfg.vault_addr).toString("hex"),
      asset_type: Buffer.from(cfg.asset_type).toString("hex"),
      amount: BigInt(body.amount),
      deposit_blind: hexToBytes(body.deposit_blind),
      amount_tag,
      commitment,
      deposit_binding_proof: new Uint8Array(
        // For audit storage, serialize the snarkjs JSON shape.
        Buffer.from(JSON.stringify(body.deposit_binding_proof_snark)),
      ),
      ca_payload_hash,
      ca_payload_jsonb: body.ca_payload,
      deposit_nonce,
      expiry,
      status: "verified",
      created_at: new Date(),
    });
    await store.insertAuditLog({
      id: randomUUID(),
      request_id,
      event_type: "deposit_request_received",
      payload_jsonb: { user_addr: body.user_addr },
      timestamp: new Date(),
    });

    // Sign main-op attestation slot.
    const main_sig = await cfg.signer.sign(msg_bytes);
    const main_msg_hash = keccak256(msg_bytes);
    await store.insertAttestationSignature({
      id: randomUUID(),
      request_id,
      operator_slot: cfg.main_slot,
      signature_bytes: main_sig,
      message_bytes_hash: main_msg_hash,
      verification_status: "valid",
      created_at: new Date(),
    });

    // Build the co-sign request body and fan out to partners.
    const auth_payload = new Uint8Array(
      Buffer.concat([Buffer.from(request_id, "utf-8"), Buffer.from(msg_bytes)]),
    );
    const main_auth_sig = await cfg.signer.sign(auth_payload);

    const cosignBody: CoSignRequestBody = {
      request_id,
      operator_set_version: cfg.operator_set_version.toString(),
      threshold: cfg.threshold.toString(),
      vault_addr: Buffer.from(cfg.vault_addr).toString("hex"),
      asset_type: Buffer.from(cfg.asset_type).toString("hex"),
      chain_id: cfg.chain_id,
      pool_id: cfg.pool_id.toString(),
      commitment: body.commitment,
      amount_tag: body.amount_tag,
      ca_payload_hash: Buffer.from(ca_payload_hash).toString("hex"),
      deposit_nonce: body.deposit_nonce,
      expiry_secs: body.expiry_secs,

      amount: body.amount,
      deposit_blind: body.deposit_blind,
      ca_payload: body.ca_payload,

      deposit_binding_proof_snark: body.deposit_binding_proof_snark,
      public_inputs: body.public_inputs,

      main_op_signature: Buffer.from(main_auth_sig).toString("hex"),
      test_override_asset_id: body.test_override_asset_id,
      test_override_vault_addr_hash: body.test_override_vault_addr_hash,
    };

    const partner_results = await fanOutCoSignRequests(
      cfg.partner_urls,
      cfg.partner_bearer_tokens,
      cosignBody,
      cfg.partner_request_timeout_ms,
    );

    // Build 7-slot signature vector.
    const sigs: (Uint8Array | null)[] = new Array(7).fill(null);
    sigs[cfg.main_slot] = main_sig;

    for (const r of partner_results) {
      if (
        r.signature_bytes &&
        r.slot >= 0 &&
        r.slot < 7 &&
        r.slot !== cfg.main_slot
      ) {
        // Independent verify of partner sig BEFORE accepting (defense in
        // depth — partner could be malicious).
        const expected_pubkey = cfg.partner_pubkeys[r.slot];
        if (
          expected_pubkey &&
          verifyEd25519(r.signature_bytes, expected_pubkey, msg_bytes)
        ) {
          sigs[r.slot] = r.signature_bytes;
          await store.insertAttestationSignature({
            id: randomUUID(),
            request_id,
            operator_slot: r.slot,
            signature_bytes: r.signature_bytes,
            message_bytes_hash: main_msg_hash,
            verification_status: "valid",
            created_at: new Date(),
          });
        } else {
          await store.insertAuditLog({
            id: randomUUID(),
            request_id,
            event_type: "partner_signature_invalid",
            payload_jsonb: { slot: r.slot },
            timestamp: new Date(),
          });
        }
      } else if (r.error) {
        await store.insertAuditLog({
          id: randomUUID(),
          request_id,
          event_type: "partner_request_failed",
          payload_jsonb: { error: r.error },
          timestamp: new Date(),
        });
      }
    }

    const non_empty_count = sigs.filter((s) => s !== null).length;
    const threshold_met = BigInt(non_empty_count) >= cfg.threshold;

    if (threshold_met) {
      await store.updateDepositRequestStatus(request_id, "complete");
    }

    const result: AttestationResult = {
      request_id,
      status: threshold_met ? "complete" : "in_progress",
      message_bytes_hex: Buffer.from(msg_bytes).toString("hex"),
      signatures: sigs.map((s, i) => ({ slot: i, signature: s })),
      threshold_met,
    };

    return reply.code(200).send({
      ...result,
      signatures: result.signatures.map((s) => ({
        slot: s.slot,
        signature_hex: s.signature
          ? Buffer.from(s.signature).toString("hex")
          : null,
      })),
    });
  });

  fastify.get<{ Params: { request_id: string } }>(
    "/v1/deposit/aggregate/:request_id",
    async (req, reply) => {
      const id = req.params.request_id;
      const row = await store.getDepositRequest(id);
      if (!row) return reply.code(404).send({ error: "not_found" });
      const sigs = await store.getSignaturesForRequest(id);
      return {
        request_id: id,
        status: row.status,
        signatures: sigs.map((s) => ({
          slot: s.operator_slot,
          signature_hex: Buffer.from(s.signature_bytes).toString("hex"),
        })),
      };
    },
  );

  return { server: fastify, store };
}

export async function startMainServer(opts: MainServerOptions): Promise<{
  server: FastifyInstance;
  store: Store;
  url: string;
}> {
  const { server, store } = buildMainServer(opts);
  const url = await server.listen({ port: opts.cfg.port, host: "127.0.0.1" });
  return { server, store, url };
}

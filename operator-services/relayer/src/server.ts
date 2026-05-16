import Fastify, { type FastifyInstance } from "fastify";
import {
  ForbiddenPlaintextFieldError,
  assertNoForbiddenPlaintextFields,
} from "@eunoma/deop-protocol";
import { HttpError, hexToBytes, requireBearer } from "@eunoma/shared";

export interface RelayerSubmitRequest {
  requestId: string;
  signedTransactionBcs: string;
  attestationHash: string;
  caPayloadHash: string;
}

export interface RelayerSubmitResult {
  accepted: true;
  requestId: string;
  txHash: string;
}

export type RelayerSubmitter = (body: RelayerSubmitRequest) => Promise<RelayerSubmitResult>;

export interface RelayerServerOptions {
  bearerToken?: string;
  aptosNodeUrl?: string;
  submitter?: RelayerSubmitter;
}

export function buildRelayerServer(opts: RelayerServerOptions = {}): FastifyInstance {
  const server = Fastify({ logger: false });
  const submitter = opts.submitter ?? (
    opts.aptosNodeUrl ? createAptosRestSubmitter(opts.aptosNodeUrl) : failClosedSubmitter
  );

  server.setErrorHandler((err, _req, reply) => {
    if (err instanceof HttpError) {
      return reply.code(err.statusCode).send({ error: err.code });
    }
    return reply.code(500).send({ error: "internal_error" });
  });

  server.addHook("onRequest", async (req) => {
    if (req.url === "/v2/relayer/health") return;
    requireBearer(req.headers.authorization, opts.bearerToken);
  });

  server.get("/v2/relayer/health", async () => ({ ok: true }));

  server.post("/v2/relayer/submit", async (req, reply) => {
    try {
      const body = parseSubmit(req.body);
      const result = await submitter(body);
      return reply.code(202).send(result);
    } catch (err) {
      if (err instanceof ForbiddenPlaintextFieldError) {
        return reply.code(400).send({ error: "forbidden_plaintext_field", field: err.path });
      }
      return reply.code(400).send({
        error: "invalid_request",
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  });

  return server;
}

function parseSubmit(body: unknown): RelayerSubmitRequest {
  assertNoForbiddenPlaintextFields(body);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("body must be an object");
  }
  const obj = body as Record<string, unknown>;
  return {
    requestId: stringField(obj, "requestId"),
    signedTransactionBcs: hexField(obj, "signedTransactionBcs"),
    attestationHash: hexField(obj, "attestationHash"),
    caPayloadHash: hexField(obj, "caPayloadHash"),
  };
}

async function failClosedSubmitter(): Promise<RelayerSubmitResult> {
  throw new Error("relayer submitter is not configured");
}

export function createAptosRestSubmitter(
  aptosNodeUrl: string,
  fetchImpl: typeof fetch = fetch,
): RelayerSubmitter {
  return async (body) => {
    const submitPath = ["", "v1", "transactions"].join("/");
    const res = await fetchImpl(new URL(submitPath, aptosNodeUrl), {
      method: "POST",
      headers: { "content-type": "application/x.aptos.signed_transaction+bcs" },
      body: Buffer.from(hexToBytes(body.signedTransactionBcs)),
    });
    const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      throw new Error(`aptos submit failed: ${res.status}`);
    }
    const txHash = typeof json.hash === "string" ? json.hash : json.tx_hash;
    if (typeof txHash !== "string" || txHash.length === 0) {
      throw new Error("aptos submit response missing transaction hash");
    }
    return { accepted: true, requestId: body.requestId, txHash };
  };
}

function stringField(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${key} must be a non-empty string`);
  }
  return value;
}

function hexField(obj: Record<string, unknown>, key: string): string {
  const value = stringField(obj, key);
  if (!/^(0x)?[0-9a-fA-F]*$/.test(value) || value.replace(/^0x/i, "").length % 2 !== 0) {
    throw new Error(`${key} must be hex`);
  }
  return value;
}

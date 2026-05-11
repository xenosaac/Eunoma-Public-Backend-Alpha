// POST /v1/recipient/rollover (Phase 4 W5).
//
// After a withdraw_to_recipient on-chain tx, the recipient's CA balance lands
// in `pending`. To make it spendable they must call
// `confidential_asset::rollover_pending_balance` — which requires THEIR signer
// (not the operator's, since the framework abort-checks sender == owner).
//
// This endpoint builds the unsigned SimpleTransaction so the recipient's
// wallet can sign + submit it. The operator never sees the recipient's
// private key.
//
// Request:
//   POST /v1/recipient/rollover
//   { recipient_addr: "0x..." (32 bytes hex),
//     asset_id?:      "0xa" (default APT FA metadata) }
//
// Response:
//   200 { unsigned_tx_hex: "...", sender: "0x...", function_id: "0x1::confidential_asset::rollover_pending_balance" }
//   400 { error: "invalid_recipient_addr" | "invalid_asset_id" }
//   500 { error: "rollover_build_failed", reason: "..." }

import type { FastifyInstance } from "fastify";
import {
  AccountAddress,
  Aptos,
  AptosConfig,
  Network,
} from "@aptos-labs/ts-sdk";
import { ConfidentialAsset } from "@aptos-labs/confidential-asset";

interface RolloverRequestBody {
  recipient_addr: string;
  asset_id?: string;
}

const DEFAULT_ASSET_ID = "0xa";

export function registerRecipientRolloverRoute(fastify: FastifyInstance): void {
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  const ca = new ConfidentialAsset({ config: aptos.config });

  fastify.post("/v1/recipient/rollover", async (req, reply) => {
    const body = req.body as RolloverRequestBody | undefined;
    if (!body || typeof body !== "object") {
      return reply.code(400).send({ error: "missing_body" });
    }
    if (typeof body.recipient_addr !== "string") {
      return reply.code(400).send({ error: "invalid_recipient_addr" });
    }

    let sender: AccountAddress;
    try {
      sender = AccountAddress.from(body.recipient_addr);
    } catch (e: any) {
      return reply.code(400).send({
        error: "invalid_recipient_addr",
        reason: e?.message ?? "unparseable",
      });
    }

    const assetId = body.asset_id ?? DEFAULT_ASSET_ID;
    let tokenAddress: AccountAddress;
    try {
      tokenAddress = AccountAddress.from(assetId);
    } catch (e: any) {
      return reply.code(400).send({
        error: "invalid_asset_id",
        reason: e?.message ?? "unparseable",
      });
    }

    let tx;
    try {
      tx = await ca.transaction.rolloverPendingBalance({
        sender,
        tokenAddress,
      });
    } catch (e: any) {
      return reply.code(500).send({
        error: "rollover_build_failed",
        reason: e?.message ?? "unknown",
      });
    }

    const rawTxnBytes = tx.rawTransaction.bcsToBytes();
    return reply.code(200).send({
      unsigned_tx_hex: Buffer.from(rawTxnBytes).toString("hex"),
      sender: sender.toString(),
      function_id: "0x1::confidential_asset::rollover_pending_balance",
      asset_id: tokenAddress.toString(),
    });
  });
}

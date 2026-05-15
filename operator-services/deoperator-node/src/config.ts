import type { CryptoWorker } from "@eunoma/crypto-worker-client";
import { FailClosedCryptoWorker, HttpCryptoWorkerClient } from "@eunoma/crypto-worker-client";
import {
  assertProductionCaDkgScheme,
  parseCaDkgV2Roster,
  parseFrostDkgV2Roster,
  validateRoster,
  type CaDkgV2Roster,
  type DeoperatorRoster,
  type FrostDkgV2Roster,
} from "@eunoma/deop-protocol";

export interface DeoperatorNodeConfig {
  slot: number;
  nodeId: string;
  host: string;
  port: number;
  bearerToken?: string;
  roster?: DeoperatorRoster;
  caDkgV2Roster?: CaDkgV2Roster;
  frostDkgV2Roster?: FrostDkgV2Roster;
  cryptoWorker: CryptoWorker;
  /** Phase 2: passthrough target URL for the vault_ek derive routes. */
  cryptoWorkerUrl?: string;
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): DeoperatorNodeConfig {
  const rosterJson = env.DEOPERATOR_ROSTER_JSON;
  const roster = rosterJson ? (JSON.parse(rosterJson) as DeoperatorRoster) : undefined;
  const caDkgV2Roster = env.CA_DKG_V2_ROSTER_JSON
    ? parseCaDkgV2Roster(JSON.parse(env.CA_DKG_V2_ROSTER_JSON))
    : undefined;
  const frostDkgV2Roster = env.FROST_DKG_V2_ROSTER_JSON
    ? parseFrostDkgV2Roster(JSON.parse(env.FROST_DKG_V2_ROSTER_JSON))
    : undefined;
  if (!roster && !caDkgV2Roster) {
    throw new Error("DEOPERATOR_ROSTER_JSON or CA_DKG_V2_ROSTER_JSON is required");
  }
  if (roster) {
    if (env.NODE_ENV === "production" || env.EUNOMA_ENV === "production") {
      assertProductionCaDkgScheme(roster);
    } else {
      validateRoster(roster);
    }
  }
  const workerUrl = env.CRYPTO_WORKER_URL;
  return {
    slot: Number.parseInt(env.DEOPERATOR_SLOT ?? "", 10),
    nodeId: env.DEOPERATOR_NODE_ID ?? `node-${env.DEOPERATOR_SLOT ?? "unknown"}`,
    host: env.DEOPERATOR_HOST ?? "127.0.0.1",
    port: Number.parseInt(env.DEOPERATOR_PORT ?? "4100", 10),
    bearerToken: env.DEOPERATOR_BEARER_TOKEN,
    roster,
    caDkgV2Roster,
    frostDkgV2Roster,
    cryptoWorker: workerUrl ? new HttpCryptoWorkerClient(workerUrl) : new FailClosedCryptoWorker(),
    cryptoWorkerUrl: workerUrl,
  };
}

// IPFS publisher for the ASP full approved-set (public, transparent — owner: ASP data should be
// public). Real pin via Pinata (default) or web3.storage; a local content-addressed fallback for
// dev runs without creds (clearly marked non-IPFS so it's never mistaken for a real pin).
import { keccak_256 } from "@noble/hashes/sha3";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

export class PinataPublisher {
  constructor({ jwt, fetchImpl } = {}) {
    if (!jwt) throw new Error("PinataPublisher: jwt required (PINATA_JWT)");
    this.jwt = jwt;
    this.fetch = fetchImpl ?? globalThis.fetch;
    this.kind = "pinata";
  }
  async publish(data, name = "eunoma-asp-set") {
    const res = await this.fetch("https://api.pinata.cloud/pinning/pinJSONToIPFS", {
      method: "POST",
      headers: { Authorization: `Bearer ${this.jwt}`, "Content-Type": "application/json" },
      body: JSON.stringify({ pinataContent: data, pinataMetadata: { name } }),
    });
    if (!res.ok) throw new Error(`pinata pin ${res.status}: ${await res.text().catch(() => "")}`);
    const body = await res.json();
    if (!body?.IpfsHash) throw new Error("pinata: no IpfsHash in response");
    return { cid: body.IpfsHash, source: this.kind };
  }
}

export class Web3StoragePublisher {
  constructor({ token, fetchImpl } = {}) {
    if (!token) throw new Error("Web3StoragePublisher: token required (WEB3_STORAGE_TOKEN)");
    this.token = token;
    this.fetch = fetchImpl ?? globalThis.fetch;
    this.kind = "web3.storage";
  }
  async publish(data, name = "eunoma-asp-set") {
    const res = await this.fetch("https://api.web3.storage/upload", {
      method: "POST",
      headers: { Authorization: `Bearer ${this.token}`, "X-NAME": name, "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`web3.storage upload ${res.status}: ${await res.text().catch(() => "")}`);
    const body = await res.json();
    if (!body?.cid) throw new Error("web3.storage: no cid in response");
    return { cid: body.cid, source: this.kind };
  }
}

// Dev fallback: writes the set locally + returns a content-hash pseudo-CID prefixed "local-" so it
// is NEVER confused with a real IPFS pin. Use only when no PINATA_JWT / WEB3_STORAGE_TOKEN is set.
export class LocalDevPublisher {
  constructor({ dir } = {}) {
    this.dir = dir || resolve(process.cwd(), ".agent-local", "asp-sets");
    this.kind = "local-dev-fallback";
  }
  async publish(data, name = "eunoma-asp-set") {
    mkdirSync(this.dir, { recursive: true });
    const json = JSON.stringify(data);
    const cid = "local-" + Buffer.from(keccak_256(new TextEncoder().encode(json))).toString("hex").slice(0, 46);
    writeFileSync(resolve(this.dir, `${cid}.json`), json);
    return { cid, source: this.kind };
  }
}

export function makeIpfsPublisher(env = process.env) {
  if (env.PINATA_JWT) return new PinataPublisher({ jwt: env.PINATA_JWT });
  if (env.WEB3_STORAGE_TOKEN) return new Web3StoragePublisher({ token: env.WEB3_STORAGE_TOKEN });
  process.stderr.write(
    "[ipfs] WARNING: no PINATA_JWT / WEB3_STORAGE_TOKEN — using LOCAL DEV fallback (NOT a real IPFS pin). " +
      "Set PINATA_JWT for a real public pin.\n",
  );
  return new LocalDevPublisher({});
}

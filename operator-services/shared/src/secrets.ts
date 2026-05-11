// Secret loading from environment variables.
//
// Phase 4 W3: all private keys live in process env (.env in dev, secret manager
// in prod). The legacy .vault-ek.json / .recipient-ek.json / .user-ek.json /
// .operator-keys.json files are migrated once via scripts/migrate_json_secrets_to_env.ts
// and then deleted from disk.

const HEX_RE = /^0x[0-9a-fA-F]+$/;

export function loadSecretHex(envName: string, expectedByteLen?: number): string {
  const v = process.env[envName];
  if (!v) {
    throw new Error(
      `secret ${envName} not set; copy from .env.example and run migrate_json_secrets_to_env.ts if upgrading from JSON-based config`,
    );
  }
  if (!HEX_RE.test(v)) {
    throw new Error(`${envName} must be a 0x-prefixed hex string`);
  }
  if (expectedByteLen !== undefined) {
    const hexLen = v.length - 2;
    if (hexLen !== expectedByteLen * 2) {
      throw new Error(
        `${envName} must be ${expectedByteLen} bytes (${expectedByteLen * 2} hex chars), got ${hexLen}`,
      );
    }
  }
  return v;
}

export interface OperatorKey {
  slot: number;
  role: string;
  private_key: string;
  public_key: string;
  address: string;
}

export function loadOperatorKeys(): OperatorKey[] {
  const b64 = process.env.OPERATOR_KEYS_JSON_B64;
  if (!b64) {
    throw new Error(
      "OPERATOR_KEYS_JSON_B64 not set; run scripts/migrate_json_secrets_to_env.ts to convert .operator-keys.json",
    );
  }
  const decoded = Buffer.from(b64, "base64").toString("utf-8");
  const keys = JSON.parse(decoded) as OperatorKey[];
  if (!Array.isArray(keys) || keys.length !== 7) {
    throw new Error(`OPERATOR_KEYS_JSON_B64 must decode to an array of 7 operator keys, got ${Array.isArray(keys) ? keys.length : typeof keys}`);
  }
  for (const k of keys) {
    if (typeof k.slot !== "number" || typeof k.private_key !== "string" || typeof k.public_key !== "string") {
      throw new Error(`OPERATOR_KEYS_JSON_B64 entry malformed at slot ${k.slot}`);
    }
  }
  return keys;
}

export function loadOperatorKeyForSlot(slot: number): OperatorKey {
  const all = loadOperatorKeys();
  const k = all.find((x) => x.slot === slot);
  if (!k) throw new Error(`operator key for slot ${slot} not found in OPERATOR_KEYS_JSON_B64`);
  return k;
}

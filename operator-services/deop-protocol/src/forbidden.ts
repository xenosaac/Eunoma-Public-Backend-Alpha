export class ForbiddenPlaintextFieldError extends Error {
  constructor(readonly path: string) {
    super(`forbidden plaintext field: ${path}`);
    this.name = "ForbiddenPlaintextFieldError";
  }
}

const FORBIDDEN_FIELD_NAMES = new Set([
  "amount",
  "amountoctas",
  "amount_octas",
  "blind",
  "balancechunks",
  "balance_chunks",
  "depositblind",
  "withdrawblind",
  "plaintext",
  "plaintextamount",
  "plaintext_amount",
  "plaintextbalance",
  "plaintext_balance",
  "notesecret",
  "note_secret",
  "secret",
  "secretshare",
  "secret_share",
  "vaultdk",
  "vault_dk",
  "vaultdecryptionkey",
  "vault_decryption_key",
  "decryptionkey",
  "decryption_key",
  "fulldk",
  "full_dk",
  "nullifier",
  "nullifiersecret",
  "nullifier_secret",
  "nullifiershare",
  "nullifier_share",
  "rawnullifier",
  "raw_nullifier",
  "dkinv",
  "dkinverse",
  "invshare",
  "inverseshare",
  "dkshare",
  "dk_share",
  "cadkshare",
  "ca_dk_share",
  "shamirshare",
  "shamir_share",
]);

export function assertNoForbiddenPlaintextFields(value: unknown): void {
  visit(value, "$");
}

function visit(value: unknown, path: string): void {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      visit(value[i], `${path}[${i}]`);
    }
    return;
  }
  if (!value || typeof value !== "object") return;

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const normalized = key.replace(/[-_]/g, "").toLowerCase();
    if (FORBIDDEN_FIELD_NAMES.has(normalized) || FORBIDDEN_FIELD_NAMES.has(key.toLowerCase())) {
      throw new ForbiddenPlaintextFieldError(path === "$" ? key : `${path}.${key}`);
    }
    visit(child, path === "$" ? key : `${path}.${key}`);
  }
}

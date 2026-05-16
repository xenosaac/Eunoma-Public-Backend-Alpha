// TS equivalents of `scripts/_lib/format_aptos_args.mjs` for callers that work
// in TS-land (relayer, deop-protocol tests). Output strings are byte-compatible
// with `aptos move run --args`:
//
//   u64Arg(42n)                 -> "u64:42"
//   hexArg("0x1234")            -> "hex:0x1234"
//   hexVectorArg(["0x12"])      -> "hex:[0x12]"
//   hexVector3Arg([["0x12"]])   -> "hex:[[0x12]]"
//
// Aptos CLI accepts vector<vector<u8>> as the comma-separated bracketed form
// `hex:[0x..,0x..]`. For the depth-3 case (vector<vector<vector<u8>>>) the
// outer brackets nest twice — `hex:[[0x..,0x..],[0x..]]` — which is what the
// `amount_r_volun_auds` field of `withdraw_to_recipient_v2` requires. The
// depth-3 helper is new vs the .mjs lib; that lib only goes to depth 2 because
// no V1 call needed depth-3 args.

export type HexInput = string;

/**
 * Format a u64 argument. Accepts `bigint` or a decimal string.
 *
 * Note that the .mjs lib only accepts strings; the TS variant also accepts
 * bigints because callers in TS-land often hold values as `bigint` and the
 * .toString() round-trip is verbose.
 */
export function u64Arg(value: bigint | string): string {
  if (typeof value === "bigint") {
    if (value < 0n) {
      throw new Error(`u64 arg must be non-negative: ${value}`);
    }
    if (value > 18446744073709551615n) {
      throw new Error(`u64 arg overflows u64: ${value}`);
    }
    return `u64:${value.toString(10)}`;
  }
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`u64 arg must be a decimal string: ${value}`);
  }
  if (BigInt(value) > 18446744073709551615n) {
    throw new Error(`u64 arg overflows u64: ${value}`);
  }
  return `u64:${value}`;
}

/**
 * Format a single hex argument as `hex:0x<bytes>`. Accepts with or without an
 * existing `0x` prefix; normalizes the casing to lowercase to match the .mjs
 * helper exactly.
 */
export function hexArg(value: HexInput): string {
  const clean = normalizeHex(value);
  return `hex:0x${clean}`;
}

/**
 * Format a `vector<vector<u8>>` argument as `hex:[0x..,0x..,..]`.
 *
 * Empty arrays produce the bracket pair only: `hex:[]`. The Aptos CLI accepts
 * this and the Move side decodes it as an empty `vector<vector<u8>>` — which
 * is the legal value for fields like `new_balance_r_eff_aud` when there is no
 * effective auditor.
 */
export function hexVectorArg(values: HexInput[]): string {
  if (!Array.isArray(values)) {
    throw new Error(`hex vector arg requires an array, got ${typeof values}`);
  }
  const items = values.map((v, idx) => {
    try {
      return `0x${normalizeHex(v)}`;
    } catch (err) {
      throw new Error(
        `hex vector entry [${idx}] invalid: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  });
  return `hex:[${items.join(",")}]`;
}

/**
 * Format a `vector<vector<vector<u8>>>` argument as
 * `hex:[[0x..,0x..],[0x..],..]`. Used for `amount_r_volun_auds` — the only
 * depth-3 vector field in `withdraw_to_recipient_v2`.
 *
 * Each inner array is a per-auditor ciphertext vector. The outer array iterates
 * over voluntary auditors. Empty outer arrays produce `hex:[]`; outer arrays
 * with empty inner arrays produce `hex:[[]]`.
 */
export function hexVector3Arg(values: HexInput[][]): string {
  if (!Array.isArray(values)) {
    throw new Error(`hex vector3 arg requires an array, got ${typeof values}`);
  }
  const outer = values.map((inner, outerIdx) => {
    if (!Array.isArray(inner)) {
      throw new Error(`hex vector3 entry [${outerIdx}] must be an array, got ${typeof inner}`);
    }
    const innerItems = inner.map((v, innerIdx) => {
      try {
        return `0x${normalizeHex(v)}`;
      } catch (err) {
        throw new Error(
          `hex vector3 entry [${outerIdx}][${innerIdx}] invalid: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    });
    return `[${innerItems.join(",")}]`;
  });
  return `hex:[${outer.join(",")}]`;
}

function normalizeHex(value: HexInput): string {
  if (typeof value !== "string") {
    throw new Error(`hex must be a string, got ${typeof value}`);
  }
  const clean = value.replace(/^0x/i, "").toLowerCase();
  if (clean.length % 2 !== 0) {
    throw new Error(`hex must have even number of nibbles: ${value}`);
  }
  if (!/^[0-9a-f]*$/.test(clean)) {
    throw new Error(`hex contains non-hex characters: ${value}`);
  }
  return clean;
}

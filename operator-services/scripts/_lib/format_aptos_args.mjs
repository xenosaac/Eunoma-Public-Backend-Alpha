// Format helpers for `aptos move run --args` invocations.
// Tested against Aptos CLI 3.5+. Pinned via the script header.

export function u64Arg(value) {
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) {
    throw new Error(`u64 arg must be decimal string: ${value}`);
  }
  return `u64:${value}`;
}

export function hexArg(value) {
  const clean = String(value).replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error(`hex arg invalid: ${value}`);
  }
  return `hex:0x${clean}`;
}

export function hexVectorArg(values) {
  if (!Array.isArray(values)) {
    throw new Error(`hex vector arg requires an array, got ${typeof values}`);
  }
  const items = values.map((v) => {
    const clean = String(v).replace(/^0x/i, "").toLowerCase();
    if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
      throw new Error(`hex vector entry invalid: ${v}`);
    }
    return `0x${clean}`;
  });
  // Aptos CLI accepts vector<vector<u8>> as: "hex:[0x..,0x..,..]"
  return `hex:[${items.join(",")}]`;
}

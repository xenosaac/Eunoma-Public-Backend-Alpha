// Helper for Aptos /v1/view queries. Used by the testnet rotation script to
// read on-chain DeoperatorConfigV2 state before submitting a rotation tx.

export async function aptosView(nodeUrl, functionId, typeArgs, args) {
  const url = new URL("/v1/view", nodeUrl).toString();
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      function: functionId,
      type_arguments: typeArgs ?? [],
      arguments: args ?? [],
    }),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`aptos /v1/view ${functionId} -> ${res.status}: ${text}`);
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`aptos /v1/view ${functionId} returned non-JSON: ${text}`);
  }
}

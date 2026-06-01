#!/usr/bin/env bash
# R7-OPS-1 helper: query Aptos Indexer GraphQL for all deposit txs ever sent
# to the bridge package, resolve versions to tx hashes via REST, output
# comma-separated hash list on stdout. Used by refresh_known_root_cycle.sh
# to feed local_build_commitment_tree.mjs --tx-hashes.
#
# Why: events v1 GraphQL table is deprecated (Sep 2025). account_transactions
# table is the supported replacement. We filter by entry function name to find
# every deposit_step2b_invoke_framework + deposit_with_commitment_v2 call ever
# sent to the bridge package. This is only a retry/backfill feed; the route-ready
# wrapper persists concrete observe_deposit tx hashes and the tree builder only
# appends the next contiguous current-vault deposit counts.
#
# Output: comma-separated hex tx hashes (e.g., 0x123...,0x456...). Empty string
# if no txs found (caller should treat as no-op).
set -euo pipefail

BRIDGE=${EUNOMA_BRIDGE_PACKAGE_ADDRESS:-0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1}
APTOS_NODE_URL=${APTOS_TESTNET_NODE_URL:-https://api.testnet.aptoslabs.com/v1}
LIMIT=${EUNOMA_TX_FETCH_LIMIT:-500}

# Step 1: GraphQL — list all account_transactions for bridge package addr,
# filter to deposit_step2b/deposit_with_commitment_v2 entry funs, get versions.
VERSIONS=$(curl -sS -X POST "${APTOS_NODE_URL%/v1}/v1/graphql" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":\"query { account_transactions(where: {account_address: {_eq: \\\"${BRIDGE}\\\"}}, order_by: {transaction_version: desc}, limit: ${LIMIT}) { transaction_version user_transaction { entry_function_id_str } }}\"}" \
  | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if 'errors' in d:
        print('GRAPHQL_ERROR:', d['errors'][0].get('message','?')[:200], file=sys.stderr)
        sys.exit(2)
    txs = d.get('data', {}).get('account_transactions', [])
    versions = []
    for t in txs:
        u = t.get('user_transaction', {}) or {}
        fn = (u.get('entry_function_id_str') or '').lower()
        if 'deposit_step2b_invoke_framework' in fn or 'deposit_with_commitment_v2' in fn:
            versions.append(str(t['transaction_version']))
    # Print one per line for shell consumption
    for v in versions:
        print(v)
except Exception as e:
    print(f'PARSE_ERROR: {e}', file=sys.stderr)
    sys.exit(2)
")

if [ -z "$VERSIONS" ]; then
  echo "" # No deposits found; caller no-ops
  exit 0
fi

# Step 2: For each version, REST GET /transactions/by_version/{V} to get hash.
# Iterate, build comma-separated list. Skip txs that fail lookup (best-effort).
HASHES=""
for V in $VERSIONS; do
  H=$(curl -sS --max-time 10 "${APTOS_NODE_URL%/v1}/v1/transactions/by_version/$V" 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('hash',''))" 2>/dev/null || true)
  if [ -n "$H" ] && [ "${H:0:2}" = "0x" ]; then
    if [ -z "$HASHES" ]; then HASHES="$H"; else HASHES="$HASHES,$H"; fi
  fi
done

echo "$HASHES"

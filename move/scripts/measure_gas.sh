#!/usr/bin/env bash
# Phase D.0 — sim-session gas measurement for eunoma bench wrappers.
#
# Usage:   ./scripts/measure_gas.sh <bench_function_name>
# Example: ./scripts/measure_gas.sh bench_noop
#          ./scripts/measure_gas.sh bench_multi_sig_4of7
#
# Output: a single JSON line on stdout, e.g.
#   {"function":"bench_noop","gas_units":4,"raw_output":"…"}
#
# Method:
#   1. `aptos move sim init` — ephemeral local simulation session.
#   2. `aptos move sim fund` — give the derived address enough APT to pay for
#      both `publish` and the bench `run`.
#   3. `aptos move publish --session` from `bench/` — transitively publishes
#      eunoma_bench + eunoma_bridge + eunoma_pool to the derived address. All
#      three named addresses (eunoma, eunoma_pool, eunoma_bench) are bound to
#      DERIVED_ADDR via --named-addresses CLI override (mvp-backend's Move.toml
#      uses "_" unpinned addresses).
#   4. `aptos move run --session` invokes the bench entry function.
#   5. Parse `gas_used` from the JSON output and emit our own JSON line.
#
# Determinism: gas_used is bit-identical across reruns within the same session
# AND across fresh-session runs (verified during Phase D.0 smoke test).
#
# Per-invocation isolation: SESSION_DIR defaults to /tmp/eunoma_gas_session;
# parallel agents MUST override via `EUNOMA_GAS_SESSION_DIR` env var to avoid
# cross-contamination (Round 5 / Phase D.1 lesson).
#
# Idempotence: reuses SESSION_DIR if it exists and has a .published marker;
# set `FORCE_REINIT=1` to force re-init + republish.
#
# Exit code: 0 on success, non-zero on failure (with error JSON on stderr).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOVE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BENCH_DIR="$MOVE_ROOT/bench"

if [[ -z "${1:-}" ]]; then
    echo "usage: $0 <bench_function_name>" >&2
    exit 2
fi
FN="$1"

# Sim-session sender material is local-only. Keep it out of git history; callers
# that need bit-identical gas runs should export the same values in their shell.
PRIVATE_KEY="${EUNOMA_GAS_PRIVATE_KEY:?EUNOMA_GAS_PRIVATE_KEY env var required}"
DERIVED_ADDR="${EUNOMA_GAS_DERIVED_ADDR:?EUNOMA_GAS_DERIVED_ADDR env var required}"
GAS_UNIT_PRICE=100

SESSION_DIR="${EUNOMA_GAS_SESSION_DIR:-/tmp/eunoma_gas_session}"
INIT_MARKER="$SESSION_DIR/.published"

publish_one() {
    local pkg_dir="$1"
    local label="$2"
    (
        cd "$pkg_dir" && \
        aptos move publish \
            --session "$SESSION_DIR" \
            --sender-account "$DERIVED_ADDR" \
            --private-key "$PRIVATE_KEY" \
            --gas-unit-price "$GAS_UNIT_PRICE" \
            --named-addresses "eunoma=${DERIVED_ADDR},eunoma_pool=${DERIVED_ADDR},eunoma_bench=${DERIVED_ADDR}" \
            --skip-fetch-latest-git-deps \
            --included-artifacts none \
            --override-size-check \
            --assume-yes 2>&1 | tail -3
    )
    echo "  [published $label]"
}

setup_session() {
    rm -rf "$SESSION_DIR"
    aptos move sim init --path "$SESSION_DIR" >/dev/null
    aptos move sim fund --session "$SESSION_DIR" --account "$DERIVED_ADDR" \
        --amount 1000000000000 >/dev/null

    # Publish in dependency order: deps before consumers.
    # All three packages bind eunoma/eunoma_pool/eunoma_bench to DERIVED_ADDR.
    # --override-size-check because eunoma_bridge alone is ~25KB; bench is tiny.
    publish_one "$MOVE_ROOT/poseidon_local" "eunoma_pool"
    publish_one "$MOVE_ROOT"               "eunoma_bridge"
    publish_one "$BENCH_DIR"               "eunoma_bench"
    touch "$INIT_MARKER"
}

# (Re)publish if session is missing or any source changed.
need_setup=0
if [[ "${FORCE_REINIT:-0}" == "1" ]]; then
    need_setup=1
elif [[ ! -f "$INIT_MARKER" ]]; then
    need_setup=1
else
    # If any tracked source is newer than the marker, republish.
    newest_src=$(find "$MOVE_ROOT/sources" "$MOVE_ROOT/poseidon_local/sources" \
        "$BENCH_DIR/sources" "$MOVE_ROOT/Move.toml" "$MOVE_ROOT/poseidon_local/Move.toml" \
        "$BENCH_DIR/Move.toml" -type f -newer "$INIT_MARKER" 2>/dev/null | head -1 || true)
    if [[ -n "$newest_src" ]]; then
        need_setup=1
    fi
fi

if [[ "$need_setup" == "1" ]]; then
    setup_session >&2
fi

# Run the bench entry function in the sim session. Capture full JSON output.
RAW=$(
    cd "$BENCH_DIR" && \
    aptos move run \
        --session "$SESSION_DIR" \
        --sender-account "$DERIVED_ADDR" \
        --private-key "$PRIVATE_KEY" \
        --gas-unit-price "$GAS_UNIT_PRICE" \
        --function-id "${DERIVED_ADDR}::bench_eunoma::${FN}" \
        --assume-yes 2>&1
)

# Parse gas_used (line like "gas_used": 4,).
GAS=$(printf '%s\n' "$RAW" | sed -n 's/.*"gas_used": *\([0-9][0-9]*\).*/\1/p' | head -1)
if [[ -z "$GAS" ]]; then
    RAW_JSON=$(printf '%s' "$RAW" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
    printf '{"function":"%s","gas_units":null,"error":"could not parse gas_used","raw_output":%s}\n' "$FN" "$RAW_JSON" >&2
    exit 1
fi

# Sanity-check: success:true must appear in raw output.
if ! printf '%s\n' "$RAW" | grep -q '"success": *true'; then
    RAW_JSON=$(printf '%s' "$RAW" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
    printf '{"function":"%s","gas_units":%s,"error":"tx did not report success:true","raw_output":%s}\n' "$FN" "$GAS" "$RAW_JSON" >&2
    exit 1
fi

RAW_JSON=$(printf '%s' "$RAW" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
printf '{"function":"%s","gas_units":%s,"raw_output":%s}\n' "$FN" "$GAS" "$RAW_JSON"

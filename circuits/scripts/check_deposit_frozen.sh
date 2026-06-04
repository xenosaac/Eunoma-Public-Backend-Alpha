#!/usr/bin/env bash
# Invariant guard: deposit FROZEN within V4 but UNFROZEN at V3->V4 stable-label cutover (D6).
#
# The V3 deposit circuit was byte-frozen against a CP0 oracle. At the D6 V3->V4 stable-label
# cutover the deposit_binding circuit is INTENTIONALLY re-cut (BindSecretWithLabel folds the
# stable label into the commitment preimage), so the V3 oracle no longer matches and is RETIRED
# to .deposit_v3_retired_baseline.sha256 (kept for clean-replace provenance, NOT enforced).
#
# Within V4, deposit is frozen again: once the Setup stage records the V4 baseline (after the
# final deposit compile) into .deposit_v4_baseline.sha256, this gate enforces byte-identity in the
# CP1 + CP2 gates. Until then it is a no-op pass (the v4 baseline does not exist yet — by design).
set -euo pipefail
cd "$(dirname "$0")/.."

V4_BASELINE=.deposit_v4_baseline.sha256
V3_RETIRED=.deposit_v3_retired_baseline.sha256

if [ -f "$V4_BASELINE" ]; then
  shasum -a 256 -c "$V4_BASELINE"
  echo "deposit circuit FROZEN within V4: OK (byte-identical to V4 baseline oracle)"
  exit 0
fi

# V4 baseline not yet recorded (pre-Setup). The V3 oracle is retired and MUST NOT be enforced
# against the re-cut V4 deposit artifacts (it would spuriously fail post-cutover).
if [ -f "$V3_RETIRED" ]; then
  echo "deposit UNFROZEN at V3->V4 cutover (D6): V4 baseline not yet recorded (Setup records it" \
       "after the final deposit compile). V3 oracle retained at $V3_RETIRED for provenance only."
  exit 0
fi

echo "ERROR: neither $V4_BASELINE nor $V3_RETIRED present (deposit provenance lost)" >&2
exit 1

#!/usr/bin/env bash
# Invariant guard: the deposit circuit is FROZEN (label≡commitment ⇒ commitment structure
# unchanged; no in-circuit Merkle ⇒ LeanIMT migration doesn't touch it). Asserts the deposit
# artifacts are byte-identical to the CP0 baseline oracle. Run in CP1 + CP2 gates.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -f .deposit_frozen_baseline.sha256 ]; then
  echo "ERROR: .deposit_frozen_baseline.sha256 missing (CP0 oracle not recorded)" >&2
  exit 1
fi
shasum -a 256 -c .deposit_frozen_baseline.sha256
echo "deposit circuit FROZEN: OK (byte-identical to CP0 oracle)"

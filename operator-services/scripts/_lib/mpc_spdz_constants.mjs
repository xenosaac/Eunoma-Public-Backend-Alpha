// Shared constants for MP-SPDZ scripts (bootstrap, check, future runners).
// Keep these byte-identical with crypto-worker-rust constants — see
// crypto-worker-rust/src/lib.rs (Ed25519 scalar field) and the H_RISTRETTO_HEX
// at the crate root.

export const ED25519_SCALAR_MODULUS =
  "7237005577332262213973186563042994240857116359379907606001950938285454250989";

export const MP_SPDZ_COMMIT_DEFAULT = "7bf16a74e10bb07850b762797e603a8eca8785c2";

export const VAULT_EK_INVERSION_PROGRAM = "vault_ek_inversion_v1";

export const DEOPERATOR_COUNT = 7;
export const DEOPERATOR_THRESHOLD = 5;

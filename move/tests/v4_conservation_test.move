#[test_only]
/// V4 B-prime aggregate-Pedersen amount-conservation (CP2 MB-4, multi-asset design §6 B-prime /
/// §6.4). Drives the REAL assert_amount_conservation_v4 via test_only_assert_amount_conservation_v4.
/// The check pins the spent note's aggregate P_old to the Groth16-bound amount_p_digest (public[8])
/// via the Compose8 recompute, then asserts the carry-free integer-conservation equality on the
/// aggregated Ristretto points: point_equals(P_old, P_wd + P_rem).
///
/// SOUNDNESS-CRITICAL: aggregate_pedersen_amount_point decompresses each 32B chunk via
/// ristretto255::new_point_from_bytes (VALIDATES canonical encoding; option::extract aborts on a
/// non-canonical point) — NOT point_decompress (which would trust + mis-bind malformed bytes). A
/// tampered/non-canonical chunk therefore BRICKS the spend rather than mis-binding it.
///
/// Covered:
///   (pos) full-spend instance (A_rem = 0): old == wd; rem = encrypted-zero (identity = 32 zeros);
///         P_old == P_wd + identity == P_wd; digest pinned to Compose8(amount_p_old) -> passes.
///   (neg, bad split) a NON-identity remainder so P_old != P_wd + P_rem -> abort E_AMOUNT_CONSERVATION (43).
///   (neg, digest mismatch) the digest is computed over the WRONG chunks, so the P_old pin fails
///         -> abort E_AMOUNT_CONSERVATION (43).
///   (neg, tampered/non-canonical chunk) a non-canonical 32B chunk -> new_point_from_bytes returns
///         none -> option::extract aborts (the use-new_point_from_bytes-not-point_decompress property).
module eunoma::v4_conservation_test {
    use std::vector;
    use eunoma::eunoma_bridge;

    const E_AMOUNT_CONSERVATION: u64 = 43;

    // Canonical Ristretto255 basepoint G (a valid, canonical 32B compressed point).
    fun g_bytes(): vector<u8> { x"e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76" }
    // The Ristretto255 identity point compresses to 32 zero bytes (canonical encoding of 0).
    fun identity_bytes(): vector<u8> { x"0000000000000000000000000000000000000000000000000000000000000000" }
    // A non-canonical 32B encoding (all 0xff is NOT a valid Ristretto point).
    fun non_canonical_bytes(): vector<u8> { x"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" }

    // amount_p = the CA framework's 4 × 32B compressed-Ristretto amount chunks.
    fun four_of(p: vector<u8>): vector<vector<u8>> {
        let v = vector::empty<vector<u8>>();
        vector::push_back(&mut v, copy p);
        vector::push_back(&mut v, copy p);
        vector::push_back(&mut v, copy p);
        vector::push_back(&mut v, p);
        v
    }

    // (pos) conservation HOLDS for the full-spend instance (zero remainder).
    #[test]
    fun test_conservation_holds_full_spend() {
        let amount_p_old = four_of(g_bytes());
        let amount_p_wd = four_of(g_bytes());
        let amount_p_rem = four_of(identity_bytes());
        let digest = eunoma_bridge::test_only_compute_amount_p_digest(four_of(g_bytes()));
        eunoma_bridge::test_only_assert_amount_conservation_v4(
            amount_p_old, amount_p_wd, amount_p_rem, digest,
        );
        // Sanity: the abort const is the CP2-allocated 43.
        assert!(eunoma_bridge::e_amount_conservation() == 43, 300);
    }

    // (neg, bad split) a NON-identity remainder breaks the equality -> abort.
    #[test]
    #[expected_failure(abort_code = E_AMOUNT_CONSERVATION, location = eunoma::eunoma_bridge)]
    fun test_conservation_bad_split_aborts() {
        let amount_p_old = four_of(g_bytes());
        let amount_p_wd = four_of(g_bytes());
        // NON-zero remainder: P_old = G != 2G = P_wd + P_rem.
        let amount_p_rem = four_of(g_bytes());
        let digest = eunoma_bridge::test_only_compute_amount_p_digest(four_of(g_bytes()));
        eunoma_bridge::test_only_assert_amount_conservation_v4(
            amount_p_old, amount_p_wd, amount_p_rem, digest,
        );
    }

    // (neg, digest mismatch) the digest is pinned to the WRONG chunks -> P_old pin fails -> abort.
    #[test]
    #[expected_failure(abort_code = E_AMOUNT_CONSERVATION, location = eunoma::eunoma_bridge)]
    fun test_conservation_digest_mismatch_aborts() {
        let amount_p_old = four_of(g_bytes());
        let amount_p_wd = four_of(g_bytes());
        let amount_p_rem = four_of(identity_bytes());
        // Digest computed over identity chunks, NOT over amount_p_old.
        let wrong_digest = eunoma_bridge::test_only_compute_amount_p_digest(four_of(identity_bytes()));
        eunoma_bridge::test_only_assert_amount_conservation_v4(
            amount_p_old, amount_p_wd, amount_p_rem, wrong_digest,
        );
    }

    // (neg, tampered chunk) a tampered/non-canonical 32B chunk -> the VALIDATING decompression
    // (new_point_from_bytes, NOT point_decompress) returns none -> option::extract aborts. This pins
    // the soundness-critical "use new_point_from_bytes" property: malformed bytes brick the spend.
    #[test]
    #[expected_failure]
    fun test_conservation_tampered_chunk_aborts() {
        let amount_p_old = four_of(g_bytes());
        let amount_p_wd = four_of(g_bytes());
        // Tamper one leg's chunks to a non-canonical encoding.
        let amount_p_rem = four_of(non_canonical_bytes());
        let digest = eunoma_bridge::test_only_compute_amount_p_digest(four_of(g_bytes()));
        eunoma_bridge::test_only_assert_amount_conservation_v4(
            amount_p_old, amount_p_wd, amount_p_rem, digest,
        );
    }
}

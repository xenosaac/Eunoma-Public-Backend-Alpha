#[test_only]
/// CP2 MB-4 / MB-5 / MB-6 unit tests.
///
/// MB-4 (B-prime aggregate-Pedersen conservation): drives the REAL assert_amount_conservation_v4
///   via the test_only_assert_amount_conservation_v4 shim.
///   - positive (full-spend instance: A_rem = 0): amount_p_old == amount_p_wd and amount_p_rem is
///     the encrypted-zero (Ristretto identity = 32 zero bytes) chunks, so
///     P_old == P_wd + identity == P_wd. With amount_p_digest pinned to Compose8(amount_p_old).
///   - negative (bad split): amount_p_rem is a NON-identity point, so P_old != P_wd + P_rem ->
///     aborts E_AMOUNT_CONSERVATION (43).
///   - negative (P_old / digest mismatch): a wrong amount_p_digest -> aborts E_AMOUNT_CONSERVATION.
///   - negative (non-canonical chunk bytes): a non-canonical 32B point -> aborts (new_point_from_bytes
///     VALIDATES; option::extract on none aborts).
///
/// MB-5 (change-leaf event + sentinel): the EMPTY change_commitment sentinel = 32 LE zero bytes ->
///   has_change_commitment(EMPTY) == false (full withdraw, no ChangeNoteAppendedV4); a non-zero
///   commitment -> true (partial withdraw, emits the change leaf).
///
/// The full conservation / change-event / emergency-exit flows with real CA witnesses + 5-of-7
/// FROST are E2E (testnet), exercised later; these unit tests pin the on-chain primitives.
module eunoma::v4_mb456_test {
    use std::vector;
    use eunoma::eunoma_bridge;

    const E_AMOUNT_CONSERVATION: u64 = 43;

    // The canonical Ristretto255 basepoint G in compressed form (a valid, canonical 32B point).
    fun g_bytes(): vector<u8> { x"e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76" }

    // The Ristretto255 identity point compresses to 32 zero bytes (canonical encoding of 0).
    fun identity_bytes(): vector<u8> { x"0000000000000000000000000000000000000000000000000000000000000000" }

    // A non-canonical 32B encoding (all 0xff is NOT a valid Ristretto point) — new_point_from_bytes
    // returns none, so option::extract aborts.
    fun non_canonical_bytes(): vector<u8> { x"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" }

    // amount_p = 4 chunks (the CA framework TRANSFER_AMOUNT_CHUNK_COUNT), each a 32B compressed
    // Ristretto point. four_of(p) builds [p, p, p, p].
    fun four_of(p: vector<u8>): vector<vector<u8>> {
        let v = vector::empty<vector<u8>>();
        vector::push_back(&mut v, copy p);
        vector::push_back(&mut v, copy p);
        vector::push_back(&mut v, copy p);
        vector::push_back(&mut v, p);
        v
    }

    // Positive: full-spend conservation instance (A_rem = 0). old == wd; rem = encrypted-zero
    // (identity points). P_old == P_wd + identity, so point_equals holds. amount_p_digest is pinned
    // to Compose8(amount_p_old).
    #[test]
    fun test_conservation_full_spend_zero_remainder_passes() {
        let amount_p_old = four_of(g_bytes());
        let amount_p_wd = four_of(g_bytes());
        let amount_p_rem = four_of(identity_bytes());
        let digest = eunoma_bridge::test_only_compute_amount_p_digest(four_of(g_bytes()));
        eunoma_bridge::test_only_assert_amount_conservation_v4(
            amount_p_old, amount_p_wd, amount_p_rem, digest,
        );
    }

    // Negative: bad split — the remainder is a NON-identity point, so P_old != P_wd + P_rem.
    #[test]
    #[expected_failure(abort_code = E_AMOUNT_CONSERVATION, location = eunoma::eunoma_bridge)]
    fun test_conservation_bad_split_aborts() {
        let amount_p_old = four_of(g_bytes());
        let amount_p_wd = four_of(g_bytes());
        let amount_p_rem = four_of(g_bytes()); // NON-zero remainder; P_old = G != 2G = P_wd + P_rem
        let digest = eunoma_bridge::test_only_compute_amount_p_digest(four_of(g_bytes()));
        eunoma_bridge::test_only_assert_amount_conservation_v4(
            amount_p_old, amount_p_wd, amount_p_rem, digest,
        );
    }

    // Negative: P_old is pinned to the WRONG amount_p_digest (not Compose8(amount_p_old)).
    #[test]
    #[expected_failure(abort_code = E_AMOUNT_CONSERVATION, location = eunoma::eunoma_bridge)]
    fun test_conservation_digest_mismatch_aborts() {
        let amount_p_old = four_of(g_bytes());
        let amount_p_wd = four_of(g_bytes());
        let amount_p_rem = four_of(identity_bytes());
        // digest computed over the identity chunks, NOT over amount_p_old -> the P_old pin fails.
        let wrong_digest = eunoma_bridge::test_only_compute_amount_p_digest(four_of(identity_bytes()));
        eunoma_bridge::test_only_assert_amount_conservation_v4(
            amount_p_old, amount_p_wd, amount_p_rem, wrong_digest,
        );
    }

    // Negative: a non-canonical 32B chunk in amount_p_rem -> VALIDATING decompression aborts
    // (new_point_from_bytes returns none; option::extract aborts). This is the soundness-critical
    // "use new_point_from_bytes NOT point_decompress" property: malformed bytes brick the spend.
    #[test]
    #[expected_failure]
    fun test_conservation_non_canonical_chunk_aborts() {
        let amount_p_old = four_of(g_bytes());
        let amount_p_wd = four_of(g_bytes());
        let amount_p_rem = four_of(non_canonical_bytes());
        let digest = eunoma_bridge::test_only_compute_amount_p_digest(four_of(g_bytes()));
        eunoma_bridge::test_only_assert_amount_conservation_v4(
            amount_p_old, amount_p_wd, amount_p_rem, digest,
        );
    }

    // MB-5: the EMPTY sentinel (32 LE zero bytes) is has_change == false (full withdraw -> no
    // ChangeNoteAppendedV4); a non-zero commitment is has_change == true (partial -> emit change).
    #[test]
    fun test_has_change_commitment_sentinel() {
        let empty = eunoma_bridge::test_only_change_commitment_empty();
        assert!(vector::length(&empty) == 32, 100);
        assert!(!eunoma_bridge::test_only_has_change_commitment(copy empty), 101);
        let non_empty = x"abababababababababababababababababababababababababababababababab";
        assert!(eunoma_bridge::test_only_has_change_commitment(non_empty), 102);
    }
}

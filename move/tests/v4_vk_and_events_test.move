#[test_only]
/// V4 verification-key shapes + partial-withdraw change-leaf event/counter wiring (CP1 + CP2 MB-5).
/// Pins the on-chain VK IC lengths, the CANONICAL 6-public withdraw order ending in
/// change_commitment, the has_change gating of ChangeNoteAppendedV4, and the GLOBAL
/// next_leaf_index monotonicity. The full Groth16 verify + the real event emit are E2E (testnet);
/// these pin the structural invariants the clean-replace cutover depends on.
///
/// Covered:
///   (a) WITHDRAW_VK_IC_LENGTH == 7 (const) AND publish_withdraw_proof_vk_v4 stores exactly 7 IC
///       elements (6 publics + 1 const term).
///   (b) the CANONICAL 6-public withdraw vector has change_commitment at index [5].
///   (c) DEPOSIT_VK_IC_LENGTH == 6 (const) AND publish_deposit_binding_vk_v4 stores exactly 6 IC
///       elements (5 publics + 1 const term) — the deposit circuit is FROZEN under V4.
///   (d) ChangeNoteAppendedV4 is emitted ONLY when has_change == 1: the EMPTY sentinel (32 LE zero
///       bytes) -> has_change == false (full withdraw, NO change leaf); a non-zero commitment ->
///       has_change == true (partial withdraw, emit the change leaf).
///   (e) the GLOBAL next_leaf_index is strictly monotonic across asset-agnostic appends (deposits +
///       change leaves share one counter).
module eunoma::v4_vk_and_events_test {
    use std::vector;
    use eunoma::eunoma_bridge;

    // 64-byte G1 / 128-byte G2 length-correct placeholders. The publish entries' assert_g1/assert_g2
    // only check LENGTH (not curve membership), so these exercise the real publish + the IC-length
    // assertion (mirrors ragequit_access_control_test convention).
    fun g1_bytes(): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < 64) { vector::push_back(&mut v, 0x11); i = i + 1; };
        v
    }
    fun g2_bytes(): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < 128) { vector::push_back(&mut v, 0x22); i = i + 1; };
        v
    }
    fun fr32(b: u8): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut v, b); i = i + 1; };
        v
    }

    // (a) WITHDRAW_VK_IC_LENGTH == 7 AND publish_withdraw_proof_vk_v4 stores exactly 7 IC elements.
    #[test(admin = @eunoma)]
    fun test_withdraw_vk_ic_length_7(admin: &signer) {
        assert!(eunoma_bridge::withdraw_vk_ic_length() == 7, 400);
        eunoma_bridge::publish_withdraw_proof_vk_v4(
            admin,
            g1_bytes(), g2_bytes(), g2_bytes(), g2_bytes(), // alpha_g1, beta/gamma/delta_g2
            g1_bytes(), g1_bytes(), // ic_0..ic_1
            g1_bytes(), g1_bytes(), g1_bytes(), g1_bytes(), g1_bytes(), g1_bytes(), g1_bytes(),
            g1_bytes(), // ic_2..ic_9, compatibility args; only ic_0..ic_6 are stored
            g1_bytes(), g1_bytes(), g1_bytes(), g1_bytes(), // compatibility args ic_10..ic_13
        );
        assert!(eunoma_bridge::test_only_withdraw_vk_ic_len() == 7, 401);
    }

    // (b) the CANONICAL 6-public withdraw vector has change_commitment at index [5].
    #[test]
    fun test_withdraw_publics_change_commitment_at_index_5() {
        let change_commitment = fr32(0x0C);
        let (len, idx5) = eunoma_bridge::test_only_withdraw_publics_index5(
            fr32(0x01), // [0] root
            fr32(0x02), // [1] nullifier_hash
            fr32(0x03), // [2] asset_id
            fr32(0x04), // [3] recipient_hash
            fr32(0x05), // [4] amount_tag
            fr32(0x06), // [5] ca_payload_hash
            fr32(0x07), // [6] request_hash
            42,         // [7] vault_sequence
            fr32(0x08), // [8] amount_p_digest
            fr32(0x09), // [9] asp_root
            10,         // [10] state_tree_depth
            11,         // [11] asp_tree_depth
            change_commitment, // [12] change_commitment
        );
        assert!(len == 6, 410);
        assert!(idx5 == fr32(0x0C), 411);
    }

    // (c) DEPOSIT_VK_IC_LENGTH == 6 AND publish_deposit_binding_vk_v4 stores exactly 6 IC elements.
    #[test(admin = @eunoma)]
    fun test_deposit_vk_ic_length_6(admin: &signer) {
        assert!(eunoma_bridge::deposit_vk_ic_length() == 6, 420);
        eunoma_bridge::publish_deposit_binding_vk_v4(
            admin,
            g1_bytes(), g2_bytes(), g2_bytes(), g2_bytes(), // alpha_g1, beta/gamma/delta_g2
            g1_bytes(), g1_bytes(), g1_bytes(), g1_bytes(), g1_bytes(), g1_bytes(), // ic_0..ic_5
        );
        assert!(eunoma_bridge::test_only_deposit_vk_ic_len() == 6, 421);
    }

    // (d) ChangeNoteAppendedV4 only on has_change == 1: EMPTY sentinel -> false; non-zero -> true.
    #[test]
    fun test_change_event_only_on_has_change() {
        let empty = eunoma_bridge::test_only_change_commitment_empty();
        assert!(vector::length(&empty) == 32, 430);
        // Full withdraw: EMPTY (32 LE zero bytes) -> has_change == false -> NO ChangeNoteAppendedV4.
        assert!(!eunoma_bridge::test_only_has_change_commitment(copy empty), 431);
        // Partial withdraw: a non-zero Compose5 commitment -> has_change == true -> emit change leaf.
        let non_empty = fr32(0xAB);
        assert!(eunoma_bridge::test_only_has_change_commitment(non_empty), 432);
    }

    // (e) the GLOBAL next_leaf_index is strictly monotonic across asset-agnostic appends.
    #[test(admin = @eunoma)]
    fun test_next_leaf_index_monotonic(admin: &signer) {
        eunoma_bridge::test_only_seed_v4_core_and_registry(admin, b"v4_seed_vk_e");
        assert!(eunoma_bridge::test_only_next_leaf_index() == 0, 440);
        // Each append (a deposit finalization OR a partial-withdraw change leaf) post-increments the
        // SAME global counter.
        let i1 = eunoma_bridge::test_only_bump_next_leaf_index();
        assert!(i1 == 1, 441);
        let i2 = eunoma_bridge::test_only_bump_next_leaf_index();
        assert!(i2 == 2, 442);
        let i3 = eunoma_bridge::test_only_bump_next_leaf_index();
        assert!(i3 == 3, 443);
        // Strictly increasing, no reset.
        assert!(i1 < i2 && i2 < i3, 444);
        assert!(eunoma_bridge::test_only_next_leaf_index() == 3, 445);
    }
}

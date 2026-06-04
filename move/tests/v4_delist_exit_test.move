#[test_only]
/// V4 de-list emergency exit (CP2 MB-6, dormant-lifecycle-VERIFIED §3 + §8 release-gate "De-list
/// exit"). THE ONE BROKEN ITEM: if Aptos governance DE-LISTS an active CA asset, the normal bridge
/// withdraw (withdraw_step2b -> confidential_transfer_raw) AND ragequit both brick the framework
/// E_ASSET_TYPE_DISALLOWED (confidential_asset.move:622, error::invalid_argument) — total fund
/// freeze. THE FIX (additive, 5-of-7, no redesign): emergency_exit_to_raw_v4 settles via the
/// framework withdraw_to_raw primitive (which checks only is_emergency_paused + is_safe_for_
/// confidentiality, NOT the allow-list) to exit to PLAIN FA, authorized by the SAME 5-of-7 FROST
/// attestation with the recipient PINNED in the signed message.
///
/// The full "de-list -> normal withdraw bricks E_ASSET_TYPE_DISALLOWED, emergency-exit
/// withdraw_to_raw succeeds to plain FA" round-trip is E2E (it needs the CA GlobalConfig +
/// AssetConfig, whose init is public(friend) to aptos_framework only, plus a real 5-of-7 FROST
/// witness + a real withdraw_to_raw sigma/range proof). These unit tests pin the on-chain structural
/// invariants the emergency path is built on:
///   (a) 5-of-7 is a HARD invariant — THRESHOLD_V2 == 5 (no override path); the emergency exit
///       authorizes via the SAME assert_deop_attestation_v2 -> cfg.threshold gate.
///   (b) the emergency-exit DORMANT gate: a never-CA-registered (DORMANT) asset has nothing to
///       drain -> emergency_exit aborts E_ASSET_NOT_ACTIVE (40); ACTIVE and PAUSED are allowed
///       (emergency drain is exactly when winding an asset down).
///   (c) recipient is PINNED: recipient + amount are SIGNED fields of the emergency attestation, so
///       two different recipients produce DIFFERENT signed bytes — a low-priv relayer cannot
///       redirect funds without a fresh 5-of-7 signature.
///   (d) domain separation: DOMAIN_EMERGENCY_EXIT_V4 != DOMAIN_WITHDRAW_V2 — an emergency-exit
///       signature can never be replayed as a normal-withdraw attestation (and vice-versa).
///   (e) E_NOT_DELISTED (44) is wired — the emergency path is ONLY for a de-listed asset; while CA
///       is live the normal withdraw / ragequit paths must be used (the assert is E2E since it reads
///       the framework GlobalConfig, but the const wiring is pinned here).
module eunoma::v4_delist_exit_test {
    use aptos_framework::fungible_asset;
    use aptos_framework::object;
    use eunoma::eunoma_bridge;

    fun vault_addr_hash(): vector<u8> { x"5151515151515151515151515151515151515151515151515151515151515151" }
    fun roster_hash(): vector<u8> { x"7777777777777777777777777777777777777777777777777777777777777777" }
    fun frost_pk(): vector<u8> { x"8888888888888888888888888888888888888888888888888888888888888888" }

    fun setup_one_dormant(admin: &signer, creator: &signer, seed: vector<u8>): address {
        eunoma_bridge::test_only_seed_v4_core_and_registry(admin, seed);
        let (_m, _t, _b, _mm, asset) = fungible_asset::create_fungible_asset(creator);
        let addr = object::object_address(&asset);
        eunoma_bridge::register_asset_metadata_v4(admin, addr, vault_addr_hash(), 8);
        addr
    }

    // (a) 5-of-7 HARD invariant: THRESHOLD_V2 == 5 (the emergency exit authorizes through the same
    // threshold gate; there is no override path).
    #[test]
    fun test_emergency_exit_requires_5_of_7() {
        assert!(eunoma_bridge::threshold_v2() == 5, 500);
    }

    // (b) DORMANT asset -> emergency_exit aborts E_ASSET_NOT_ACTIVE (40) (nothing to drain).
    #[test(admin = @eunoma, creator = @0xA1)]
    #[expected_failure(abort_code = 40, location = eunoma::eunoma_bridge)]
    fun test_emergency_exit_on_dormant_aborts(
        admin: &signer,
        creator: &signer,
    ) {
        let addr = setup_one_dormant(admin, creator, b"v4_seed_delist_b");
        // DORMANT -> the emergency DORMANT gate aborts.
        eunoma_bridge::test_only_assert_emergency_exit_not_dormant(addr);
    }

    // (b') ACTIVE and PAUSED assets pass the emergency DORMANT gate (emergency drain is allowed when
    // winding an asset down, including while PAUSED).
    #[test(admin = @eunoma, creator = @0xA1)]
    fun test_emergency_exit_allowed_on_active_and_paused(
        admin: &signer,
        creator: &signer,
    ) {
        let addr = setup_one_dormant(admin, creator, b"v4_seed_delist_b2");
        eunoma_bridge::test_only_set_asset_status(addr, eunoma_bridge::asset_status_active());
        eunoma_bridge::test_only_assert_emergency_exit_not_dormant(addr); // ACTIVE -> passes
        eunoma_bridge::test_only_set_asset_status(addr, eunoma_bridge::asset_status_paused());
        eunoma_bridge::test_only_assert_emergency_exit_not_dormant(addr); // PAUSED -> passes
    }

    // (c) recipient PINNED: the emergency attestation binds recipient + amount, so a different
    // recipient (or amount) yields different signed bytes -> a relayer cannot redirect funds.
    #[test(good = @0x600D, evil = @0xEED1)]
    fun test_recipient_pinned_in_signed_message(good: &signer, evil: &signer) {
        let good_recipient = std::signer::address_of(good);
        let evil_recipient = std::signer::address_of(evil);
        let asset_type_addr = @0xA55E7;

        let msg_good = eunoma_bridge::test_only_serialize_emergency_exit_msg(
            eunoma_bridge::domain_emergency_exit_v4(),
            2, @eunoma, @0x7A017, asset_type_addr, 1, 1,
            roster_hash(), frost_pk(), good_recipient, 1000, 9999999999,
        );
        let msg_evil = eunoma_bridge::test_only_serialize_emergency_exit_msg(
            eunoma_bridge::domain_emergency_exit_v4(),
            2, @eunoma, @0x7A017, asset_type_addr, 1, 1,
            roster_hash(), frost_pk(), evil_recipient, 1000, 9999999999,
        );
        // Redirecting the recipient changes the FROST-signed bytes -> the existing 5-of-7 sig no
        // longer verifies (relayer cannot redirect without a fresh signature).
        assert!(msg_good != msg_evil, 510);

        // Changing the amount also changes the signed bytes (amount is pinned too).
        let msg_amount = eunoma_bridge::test_only_serialize_emergency_exit_msg(
            eunoma_bridge::domain_emergency_exit_v4(),
            2, @eunoma, @0x7A017, asset_type_addr, 1, 1,
            roster_hash(), frost_pk(), good_recipient, 2000, 9999999999,
        );
        assert!(msg_good != msg_amount, 511);
    }

    // (d) domain separation: an emergency-exit signature can never be replayed as a normal-withdraw
    // attestation — DOMAIN_EMERGENCY_EXIT_V4 != DOMAIN_WITHDRAW_V2, so even identical field values
    // produce different signed-message prefixes.
    #[test]
    fun test_emergency_exit_domain_separated_from_withdraw() {
        let d_emergency = eunoma_bridge::domain_emergency_exit_v4();
        let d_withdraw = eunoma_bridge::domain_withdraw_v2();
        assert!(d_emergency != d_withdraw, 520);

        let asset_type_addr = @0xA55E7;
        let recipient = @0x600D;
        // The emergency serializer over the EMERGENCY domain vs the WITHDRAW domain differ in the
        // domain prefix -> distinct signed bytes (cross-domain replay impossible).
        let msg_with_emergency_domain = eunoma_bridge::test_only_serialize_emergency_exit_msg(
            d_emergency, 2, @eunoma, @0x7A017, asset_type_addr, 1, 1,
            roster_hash(), frost_pk(), recipient, 1000, 9999999999,
        );
        let msg_with_withdraw_domain = eunoma_bridge::test_only_serialize_emergency_exit_msg(
            d_withdraw, 2, @eunoma, @0x7A017, asset_type_addr, 1, 1,
            roster_hash(), frost_pk(), recipient, 1000, 9999999999,
        );
        assert!(msg_with_emergency_domain != msg_with_withdraw_domain, 521);
    }

    // (e) E_NOT_DELISTED (44) is wired — the emergency path is ONLY for a de-listed asset (the
    // is_confidentiality_enabled==false gate is E2E; the const wiring is pinned here).
    #[test]
    fun test_e_not_delisted_const_wired() {
        assert!(eunoma_bridge::e_not_delisted() == 44, 530);
    }
}

#[test_only]
/// (CP6 ragequit) Tests for the transparent original-path exit added in the ASP tree design
/// (asp-tree-design.md §8). Covers the access-control + structure invariants (the full
/// proof + confidential_transfer_raw flow is E2E, exercised on testnet later):
///   (a) ragequit by the ORIGINAL depositor resolves successfully (the REAL deposit_sender lookup
///       returns the recorded original deposit address).
///   (b) ragequit by a NON-original signer aborts E_NOT_ORIGINAL_DEPOSITOR (39) — the laundering
///       escape ("deposit -> ragequit to a clean address") is blocked on-chain.
///   (b') ragequit for an unknown commitment (never deposited) aborts E_NOT_ORIGINAL_DEPOSITOR.
///   (c) publish_ragequit_proof_vk stores exactly RAGEQUIT_VK_IC_LENGTH = 5 IC elements; the
///       length assertion / const are wired correctly.
///
/// Setup note: the production `ragequit` entry runs assert_initialized() (a full BridgeVault +
/// DeoperatorConfigV2 bootstrap) then the CA transfer machinery — both are E2E concerns. These
/// unit tests instead use the #[test_only] seeder eunoma_bridge::test_only_seed_deposit_sender to
/// plant DepositSenderMap{commitment -> sender} directly at @eunoma, then drive the REAL
/// access-control path (resolve_ragequit_original_sender, the exact deposit_sender lookup +
/// E_NOT_ORIGINAL_DEPOSITOR assertions step (b)/(c) of the production entry run) via the
/// test_only_resolve_ragequit_original_sender wrapper. test (c) drives the REAL
/// publish_ragequit_proof_vk entry.
module eunoma::ragequit_access_control_test {
    use std::signer;
    use std::vector;
    use eunoma::eunoma_bridge;

    // 32-byte commitment placeholders (ragequit takes a 32B Fr commitment).
    fun commitment_a(): vector<u8> { x"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0" }
    fun unknown_commitment(): vector<u8> { x"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" }

    // 64-byte (G1_UNCOMPRESSED_BYTES) and 128-byte (G2_UNCOMPRESSED_BYTES) placeholders.
    // publish_ragequit_proof_vk's assert_g1/assert_g2 only check LENGTH (not curve membership),
    // so length-correct byte vectors exercise the real publish + the RAGEQUIT_VK_IC_LENGTH check.
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

    // (a) original depositor resolves successfully via the REAL deposit_sender lookup.
    #[test(admin = @eunoma, depositor = @0xD0)]
    fun test_original_depositor_resolves(
        admin: &signer,
        depositor: &signer,
    ) {
        let depositor_addr = signer::address_of(depositor);
        eunoma_bridge::test_only_seed_deposit_sender(admin, commitment_a(), depositor_addr);

        let resolved = eunoma_bridge::test_only_resolve_ragequit_original_sender(
            depositor_addr,
            commitment_a(),
        );
        assert!(resolved == depositor_addr, 100);
        // Sanity: the abort const is the CP6-allocated 39.
        assert!(eunoma_bridge::e_not_original_depositor() == 39, 101);
    }

    // (b) a NON-original signer is rejected with E_NOT_ORIGINAL_DEPOSITOR (39).
    #[test(admin = @eunoma, depositor = @0xD0, attacker = @0xBAD)]
    #[expected_failure(abort_code = 39, location = eunoma::eunoma_bridge)]
    fun test_non_original_signer_aborts(
        admin: &signer,
        depositor: &signer,
        attacker: &signer,
    ) {
        eunoma_bridge::test_only_seed_deposit_sender(
            admin, commitment_a(), signer::address_of(depositor),
        );
        // The attacker is NOT the recorded original depositor for commitment_a -> abort.
        let _ = eunoma_bridge::test_only_resolve_ragequit_original_sender(
            signer::address_of(attacker),
            commitment_a(),
        );
    }

    // (b') an unknown commitment (never deposited) aborts E_NOT_ORIGINAL_DEPOSITOR (39).
    #[test(admin = @eunoma, depositor = @0xD0)]
    #[expected_failure(abort_code = 39, location = eunoma::eunoma_bridge)]
    fun test_unknown_commitment_aborts(
        admin: &signer,
        depositor: &signer,
    ) {
        // Seed a DIFFERENT commitment so DepositSenderMap exists but lacks unknown_commitment().
        eunoma_bridge::test_only_seed_deposit_sender(
            admin, commitment_a(), signer::address_of(depositor),
        );
        let _ = eunoma_bridge::test_only_resolve_ragequit_original_sender(
            signer::address_of(depositor),
            unknown_commitment(),
        );
    }

    // (c) publish_ragequit_proof_vk stores exactly RAGEQUIT_VK_IC_LENGTH = 5 IC elements.
    #[test(admin = @eunoma)]
    fun test_publish_ragequit_vk_ic_length(
        admin: &signer,
    ) {
        eunoma_bridge::publish_ragequit_proof_vk(
            admin,
            g1_bytes(), // alpha_g1
            g2_bytes(), // beta_g2
            g2_bytes(), // gamma_g2
            g2_bytes(), // delta_g2
            g1_bytes(), // ic_0
            g1_bytes(), // ic_1
            g1_bytes(), // ic_2
            g1_bytes(), // ic_3
            g1_bytes(), // ic_4
        );
        // The const wired into the publish length assertion is 5 (4 publics + const term).
        assert!(eunoma_bridge::ragequit_vk_ic_length() == 5, 300);
        // The stored raw VK has exactly 5 IC elements.
        assert!(eunoma_bridge::test_only_ragequit_vk_ic_len() == 5, 301);
    }

    // (c-neg) publishing twice aborts E_ALREADY_INITIALIZED (2) — the publish entry is one-shot.
    #[test(admin = @eunoma)]
    #[expected_failure(abort_code = 2, location = eunoma::eunoma_bridge)]
    fun test_publish_ragequit_vk_twice_aborts(
        admin: &signer,
    ) {
        eunoma_bridge::publish_ragequit_proof_vk(
            admin, g1_bytes(), g2_bytes(), g2_bytes(), g2_bytes(),
            g1_bytes(), g1_bytes(), g1_bytes(), g1_bytes(), g1_bytes(),
        );
        eunoma_bridge::publish_ragequit_proof_vk(
            admin, g1_bytes(), g2_bytes(), g2_bytes(), g2_bytes(),
            g1_bytes(), g1_bytes(), g1_bytes(), g1_bytes(), g1_bytes(),
        );
    }
}

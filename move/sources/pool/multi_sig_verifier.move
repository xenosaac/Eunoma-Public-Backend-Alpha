/// AptosShield Spike — 4-of-7 Ed25519 multi-sig verifier (in-spike copy).
///
/// Module: eunoma::pool_multi_sig_verifier
///
/// Why this exists in the spike (vs depending on ConfidentialAPT):
///   * `eunoma::eunoma_bridge::assert_valid_operator_attestation`
///     and the per-slot `verify_operator_signature` helper (in
///     `ConfidentialAPT/move/sources/confidential_bridge.move:618-685`) are
///     `fun` (private), not `public fun`, and the operator-set storage
///     lives inside the production `VaultConfig` resource. Pulling them
///     across packages would either require modifying ConfidentialAPT
///     (forbidden by spike charter) or duplicating the resource.
///   * The spike charter explicitly permits a "minimal in-spike implementation"
///     when cross-package re-export is not feasible. This module is exactly
///     that: a 1:1 functional copy of the same Ed25519 / threshold logic,
///     using the same Aptos framework primitives, governed by the same
///     trust pin from HANDOFF Section 1.1 (4-of-7 with main-must-sign).
///
/// What this module enforces (one-to-one with HANDOFF Section 1.1):
///   * 7 fixed positional operator slots; empty pubkey == inactive.
///   * `attestation_threshold ≥ 4` valid signatures (configurable, capped at 7).
///   * Main operator slot MUST be among the signers (Section 1.1 + 8.5 #2).
///   * Per-slot `signature_verify_strict` (rejects non-canonical sigs).
///   * Length checks on pubkey (32) + sig (64) BEFORE constructing the
///     framework structs, mirroring LOCAL_CONFIRMATION 8.5 guidance.
///
/// What this module does NOT do (deliberately scoped):
///   * Operator-set rotation, admin rotation, pause — those live in
///     `confidential_bridge` for production. The spike has a single static
///     `OperatorSet` initialized once and read-only thereafter.
///   * Domain separator binding into the message — the caller
///     (`batch_root_update::canonical_message_bytes`) is responsible for
///     prepending the domain.
module eunoma::pool_multi_sig_verifier {
    use std::vector;
    use std::signer;

    use aptos_std::ed25519;

    // ========================================================================
    // Constants
    // ========================================================================

    const MAX_OPERATORS: u64 = 7;
    const SPIKE_THRESHOLD: u64 = 4;
    const ED25519_PUBLIC_KEY_BYTES: u64 = 32;
    const ED25519_SIGNATURE_BYTES: u64 = 64;

    // ========================================================================
    // Error codes  (numbered to NOT collide with pending_queue or batch_root_update)
    // ========================================================================

    const E_NOT_INITIALIZED: u64 = 100;
    const E_ALREADY_INITIALIZED: u64 = 101;
    const E_NOT_ADMIN: u64 = 102;
    const E_BAD_OPERATOR_SET_LENGTH: u64 = 103;
    const E_BAD_MAIN_OPERATOR_INDEX: u64 = 104;
    const E_BAD_THRESHOLD: u64 = 105;
    const E_SIGNATURE_ARRAY_LENGTH: u64 = 106;
    const E_SIGNATURE_FOR_INACTIVE_OPERATOR: u64 = 107;
    const E_INVALID_OPERATOR_SIGNATURE: u64 = 108;
    const E_TOO_FEW_OPERATOR_SIGNATURES: u64 = 109;
    const E_MAIN_OPERATOR_SIGNATURE_REQUIRED: u64 = 110;

    // ========================================================================
    // Resource
    // ========================================================================

    struct OperatorSet has key {
        operator_pubkeys: vector<vector<u8>>,
        main_operator_index: u64,
        threshold: u64,
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    public entry fun initialize(
        admin: &signer,
        operator_pubkeys: vector<vector<u8>>,
        main_operator_index: u64,
        threshold: u64,
    ) {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(!exists<OperatorSet>(@eunoma), E_ALREADY_INITIALIZED);

        assert_valid_operator_set(&operator_pubkeys, main_operator_index, threshold);

        move_to(admin, OperatorSet {
            operator_pubkeys,
            main_operator_index,
            threshold,
        });
    }

    // ========================================================================
    // Verification — public entry-point that batch_root_update calls
    // ========================================================================

    /// 4-of-7 multi-sig verification (HANDOFF Section 1.1 + Section 2.8).
    /// Param-based form: callers pass operator pubkeys / threshold / main_index
    /// directly so the verifier is callable from any module that holds its own
    /// operator set (the bridge keeps it inside `VaultConfig`; the spike-style
    /// path keeps it in this module's `OperatorSet`).
    ///
    /// Aborts on any failure with the precise error code.
    public fun assert_valid_attestation(
        message_bytes: vector<u8>,
        signatures: vector<vector<u8>>,
        operator_pubkeys: &vector<vector<u8>>,
        threshold: u64,
        main_operator_index: u64,
    ) {
        assert!(
            vector::length(&signatures) == MAX_OPERATORS,
            E_SIGNATURE_ARRAY_LENGTH,
        );
        assert!(
            vector::length(operator_pubkeys) == MAX_OPERATORS,
            E_BAD_OPERATOR_SET_LENGTH,
        );
        assert!(
            threshold >= 1 && threshold <= MAX_OPERATORS,
            E_BAD_THRESHOLD,
        );
        assert!(main_operator_index < MAX_OPERATORS, E_BAD_MAIN_OPERATOR_INDEX);

        let valid_count = 0;
        let main_signed = false;

        let i = 0;
        while (i < MAX_OPERATORS) {
            let sig = vector::borrow(&signatures, i);
            let sig_len = vector::length(sig);

            if (sig_len > 0) {
                // A signature is supplied for slot i. Inlined former
                // `verify_operator_signature` helper: removes per-slot
                // function frame and folds the length-checks against
                // the already-required non-empty-sig branch (P1).
                let pubkey = vector::borrow(operator_pubkeys, i);
                let pk_len = vector::length(pubkey);
                assert!(
                    pk_len > 0,
                    E_SIGNATURE_FOR_INACTIVE_OPERATOR,
                );
                let ok =
                    pk_len == ED25519_PUBLIC_KEY_BYTES
                        && sig_len == ED25519_SIGNATURE_BYTES
                        && ed25519::signature_verify_strict(
                            &ed25519::new_signature_from_bytes(*sig),
                            &ed25519::new_unvalidated_public_key_from_bytes(*pubkey),
                            *&message_bytes,
                        );
                assert!(ok, E_INVALID_OPERATOR_SIGNATURE);

                valid_count = valid_count + 1;
                if (i == main_operator_index) {
                    main_signed = true;
                };
            };
            i = i + 1;
        };

        assert!(valid_count >= threshold, E_TOO_FEW_OPERATOR_SIGNATURES);
        assert!(main_signed, E_MAIN_OPERATOR_SIGNATURE_REQUIRED);
    }

    /// Resource-backed wrapper preserving the original spike-style call surface
    /// (`batch_root_update` and any module that runs against the in-spike
    /// `OperatorSet` resource calls this). Bridge-side callers use the
    /// param-based `assert_valid_attestation` directly.
    public fun assert_valid_attestation_from_resource(
        message_bytes: vector<u8>,
        signatures: vector<vector<u8>>,
    ) acquires OperatorSet {
        assert!(exists<OperatorSet>(@eunoma), E_NOT_INITIALIZED);
        let cfg = borrow_global<OperatorSet>(@eunoma);
        assert_valid_attestation(
            message_bytes,
            signatures,
            &cfg.operator_pubkeys,
            cfg.threshold,
            cfg.main_operator_index,
        );
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    fun assert_valid_operator_set(
        operator_pubkeys: &vector<vector<u8>>,
        main_operator_index: u64,
        threshold: u64,
    ) {
        assert!(
            vector::length(operator_pubkeys) == MAX_OPERATORS,
            E_BAD_OPERATOR_SET_LENGTH,
        );
        assert!(main_operator_index < MAX_OPERATORS, E_BAD_MAIN_OPERATOR_INDEX);

        let main_pk = vector::borrow(operator_pubkeys, main_operator_index);
        assert!(vector::length(main_pk) > 0, E_BAD_MAIN_OPERATOR_INDEX);

        let active = 0;
        let i = 0;
        while (i < MAX_OPERATORS) {
            let pk = vector::borrow(operator_pubkeys, i);
            let len = vector::length(pk);
            assert!(
                len == 0 || len == ED25519_PUBLIC_KEY_BYTES,
                E_BAD_OPERATOR_SET_LENGTH,
            );
            if (len > 0) {
                active = active + 1;
            };
            i = i + 1;
        };
        // SPIKE_THRESHOLD is the policy floor; we still allow callers to set
        // a higher threshold (e.g. 5-of-7) but never lower than the spike pin.
        assert!(threshold >= SPIKE_THRESHOLD, E_BAD_THRESHOLD);
        assert!(threshold <= MAX_OPERATORS, E_BAD_THRESHOLD);
        assert!(threshold <= active, E_BAD_THRESHOLD);
    }

    // ========================================================================
    // Test-only accessors (error code introspection)
    // ========================================================================

    #[test_only]
    public fun e_not_initialized(): u64 { E_NOT_INITIALIZED }
    #[test_only]
    public fun e_already_initialized(): u64 { E_ALREADY_INITIALIZED }
    #[test_only]
    public fun e_not_admin(): u64 { E_NOT_ADMIN }
    #[test_only]
    public fun e_bad_operator_set_length(): u64 { E_BAD_OPERATOR_SET_LENGTH }
    #[test_only]
    public fun e_bad_main_operator_index(): u64 { E_BAD_MAIN_OPERATOR_INDEX }
    #[test_only]
    public fun e_bad_threshold(): u64 { E_BAD_THRESHOLD }
    #[test_only]
    public fun e_signature_array_length(): u64 { E_SIGNATURE_ARRAY_LENGTH }
    #[test_only]
    public fun e_signature_for_inactive_operator(): u64 { E_SIGNATURE_FOR_INACTIVE_OPERATOR }
    #[test_only]
    public fun e_invalid_operator_signature(): u64 { E_INVALID_OPERATOR_SIGNATURE }
    #[test_only]
    public fun e_too_few_operator_signatures(): u64 { E_TOO_FEW_OPERATOR_SIGNATURES }
    #[test_only]
    public fun e_main_operator_signature_required(): u64 { E_MAIN_OPERATOR_SIGNATURE_REQUIRED }

    #[test_only]
    public fun max_operators(): u64 { MAX_OPERATORS }
    #[test_only]
    public fun spike_threshold(): u64 { SPIKE_THRESHOLD }
}

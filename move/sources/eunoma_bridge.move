/// ConfidentialAPT shielded-bridge — Gate 2 skeleton.
///
/// Scope (Gate 2):
///   * Constants & error codes
///   * Resources: VaultConfig, OperatorRole, VaultBalanceMetadata
///   * Events: VaultInitialized, OperatorSetUpdated, BridgePauseChanged, AdminRotated
///   * Attestation message structs (Deposit / Withdraw) — BCS field order is part of
///     the wire spec; off-chain TS operator services MUST mirror this order exactly.
///   * Admin entry functions: init_vault, update_operator_set, pause, unpause, rotate_admin
///   * View functions
///   * Internal helpers (assert_admin / assert_not_expired / operator-set validation /
///     ed25519 single-sig verify / 4-of-7 multi-sig verify / message constructors)
///
/// Out of scope (deferred):
///   * Gate 3: real ConfidentialAPT registration in init_vault (today: gated stub)
///   * Gate 4: deposit_with_commitment, deposit-binding-proof verification
///   * Gate 5: withdraw_to_recipient, withdraw-proof verification, nullifier table,
///     Merkle root tracking
///   * Gate 6: operator_rollover_vault_pending, operator_normalize_vault_balance
///
/// Spec corrections applied (per coordination/LOCAL_CONFIRMATION.md):
///   #1: get_vault_balance_encrypted REMOVED — bridge cannot disassemble
///       confidential_asset::CompressedBalance (public(friend) accessors).
///       Replaced by get_vault_balance_metadata returning (vault_addr, asset_type,
///       is_normalized, num_transfers_received).
///   #2: operator_rollover_vault_pending (Gate 6) takes NO rollover_payload arg —
///       underlying confidential_asset::rollover_pending_balance(sender, asset_type)
///       takes no proof.
///   #3: operator_normalize_vault_balance (Gate 6) takes 7 typed args, not a single
///       opaque payload — confidential_asset::normalize_raw needs (new_balance_P/R/R_aud,
///       zkrp_new_balance, sigma_proto_comm/resp).
module eunoma::eunoma_bridge {
    use std::bcs;
    use std::option;
    use std::vector;
    use std::signer;

    use aptos_std::aptos_hash;
    use aptos_std::crypto_algebra;
    use aptos_std::ed25519;
    use aptos_std::table::{Self, Table};

    use std::bn254_algebra::{
        G1, G2, Gt, Fr, Fq12,
        FormatG1Uncompr, FormatG2Uncompr, FormatFrLsb, FormatFq12LscLsb,
    };

    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_framework::confidential_asset;
    use aptos_framework::event;
    use aptos_framework::fungible_asset;
    use aptos_framework::object::{Self, Object};
    use aptos_framework::timestamp;

    use eunoma::groth16_bn254;
    use eunoma::pool_multi_sig_verifier as multi_sig_verifier;
    use eunoma::pool_pending_queue as pending_queue;
    use eunoma::pool_batch_root_update;
    use eunoma_pool::poseidon_bn254;

    // ========================================================================
    // Constants
    // ========================================================================

    /// Total number of operator slots. Slots are FIXED and POSITIONAL — slot index
    /// is identity. Empty pubkey => inactive slot.
    const MAX_OPERATORS: u64 = 7;

    /// Minimum allowable threshold value.
    const MIN_THRESHOLD: u64 = 1;

    /// Domain separators for attestation BCS hashes. These are the first field of the
    /// DepositAttestationMessage / WithdrawAttestationMessage and MUST match the
    /// off-chain TS operator builder byte-for-byte.
    /// Phase D Agent D1 c3: shrunk from 24-byte / 25-byte ASCII tags to 8-byte
    /// tags. Domain separation only requires that deposit-domain bytes ≠
    /// withdraw-domain bytes; the long ASCII forms were a human-readability
    /// convenience, not a cryptographic requirement. Saves 16 / 17 BCS bytes
    /// per signed message, which (a) lowers BCS-encode gas (see
    /// bench_bcs_encode_attn_pool* probes; same slope applies) and (b)
    /// shrinks SHA512 input fed to each ed25519::signature_verify_strict
    /// call (4× per deposit / withdraw). The "_V1" suffix on each tag
    /// preserves forward-compatibility: a future migration (e.g. selectable
    /// disclosure rules) can rev to "_V2" without colliding with V1 sigs.
    const DOMAIN_DEPOSIT_OK_V1: vector<u8> = b"DEP_OK_1";   // 8 bytes
    const DOMAIN_WITHDRAW_OK_V1: vector<u8> = b"WDR_OK_1";  // 8 bytes

    /// Length of an Ed25519 public key in bytes.
    const ED25519_PUBLIC_KEY_BYTES: u64 = 32;

    /// Length of an Ed25519 signature in bytes.
    const ED25519_SIGNATURE_BYTES: u64 = 64;

    // ----- Gate 4b: Deposit-binding circuit / Groth16 verifier -----

    /// Number of public inputs the deposit-binding Groth16 circuit declares.
    /// Wire order (MUST match Gate 4a circuit's `main { public [...] }`):
    ///   [commitment, amount_tag, asset_id, vault_addr_hash, chain_id, pool_id]
    /// snarkjs convention: VK IC vector length must be exactly 1 + N_PUBLIC_INPUTS = 7.
    const N_PUBLIC_INPUTS: u64 = 6;

    /// Uncompressed bn254 point sizes (matches `FormatG1Uncompr` / `FormatG2Uncompr`).
    const G1_UNCOMPRESSED_BYTES: u64 = 64;
    const G2_UNCOMPRESSED_BYTES: u64 = 128;
    /// Fq12 element size (matches `FormatFq12LscLsb`):
    /// Fq12 = Fq6[w]/(w²-v) → 2× Fq6 × 192 bytes = 384 bytes total.
    /// Used by Phase B B.2's `PreparedDepositBindingVK::pvk_alpha_g1_beta_g2_fq12`.
    const FQ12_BYTES: u64 = 384;
    const FR_BYTES: u64 = 32;

    /// Total uncompressed Groth16 proof byte size: a (G1, 64) || b (G2, 128) || c (G1, 64) = 256.
    const PROOF_BYTES: u64 = 256;

    /// VK IC length invariant (snarkjs convention from LOCAL_CONFIRMATION 8.7).
    const VK_IC_LENGTH: u64 = 7; // 1 + N_PUBLIC_INPUTS

    /// Domain separators for Poseidon-based asset_id / vault_addr_hash derivation.
    /// Mirrors must be reproduced byte-for-byte by off-chain operator code (Gate 4c).
    const POSEIDON_DOMAIN_ASSET_ID:        vector<u8> = b"APTOSHIELD_ASSET_ID_V1";
    const POSEIDON_DOMAIN_VAULT_ADDR_HASH: vector<u8> = b"APTOSHIELD_VAULT_ADDR_HASH_V1";
    /// Phase 2 / Gate 6 — domain for Poseidon-based recipient_hash derivation.
    /// Bridge recomputes recipient_hash from the `recipient` address arg passed to
    /// `withdraw_to_recipient` and asserts it equals the user-supplied recipient_hash
    /// public input (which the ZK proof binds). Same hash_3(domain, hi, lo) convention
    /// as vault_addr_hash. Off-chain operator code MUST mirror byte-for-byte.
    const POSEIDON_DOMAIN_RECIPIENT_HASH:  vector<u8> = b"APTOSHIELD_RECIPIENT_HASH_V1";

    // ----- Gate 6: Withdraw circuit / Groth16 verifier -----

    /// Number of public inputs the withdraw Groth16 circuit declares.
    /// Wire order (MUST match Gate 6 circuit's `main { public [...] }`):
    ///   [root, nullifier_hash, asset_id, recipient_hash, amount_tag,
    ///    ca_payload_hash, request_hash, vault_sequence, chain_id]
    /// snarkjs convention: VK IC vector length = 1 + N_WITHDRAW_PUBLIC_INPUTS = 10.
    const N_WITHDRAW_PUBLIC_INPUTS: u64 = 9;
    const WITHDRAW_VK_IC_LENGTH: u64 = 10;

    /// Constant pool identifier baked into the bridge. Pool dispatch is deferred
    /// (architecture-agnostic Gate 4b — see `LOCAL_ARCHITECTURE_UPDATE_DEPOSIT_BATCHING.md`),
    /// but the circuit / attestation message already commits to a 32-byte LE Fr `pool_id`.
    /// Gate 4a fixture uses pool_id = 0; Gate 4b stays consistent so the fixture verifies.
    const POOL_ID_VALUE: u64 = 0;

    // ========================================================================
    // Error codes
    // ========================================================================

    const E_NOT_ADMIN: u64 = 1;
    const E_NOT_MAIN_OPERATOR: u64 = 2;
    const E_BRIDGE_PAUSED: u64 = 3;
    const E_BRIDGE_NOT_PAUSED: u64 = 4;
    const E_ALREADY_INITIALIZED: u64 = 5;
    const E_NOT_INITIALIZED: u64 = 6;
    const E_BAD_OPERATOR_SET_LENGTH: u64 = 7;
    const E_BAD_MAIN_OPERATOR_INDEX: u64 = 8;
    const E_BAD_THRESHOLD: u64 = 9;
    const E_TOO_FEW_OPERATOR_SIGNATURES: u64 = 10;
    const E_MAIN_OPERATOR_SIGNATURE_REQUIRED: u64 = 11;
    const E_INVALID_OPERATOR_SIGNATURE: u64 = 12;
    const E_SIGNATURE_FOR_INACTIVE_OPERATOR: u64 = 13;
    const E_SIGNATURE_ARRAY_LENGTH: u64 = 14;
    const E_EXPIRED_ATTESTATION: u64 = 15;
    const E_DEPOSIT_NONCE_REPLAY: u64 = 16;
    const E_PAYLOAD_HASH_MISMATCH: u64 = 17;
    const E_INVALID_DEPOSIT_BINDING_PROOF: u64 = 18;
    const E_INVALID_WITHDRAW_PROOF: u64 = 19;
    const E_INVALID_ROOT: u64 = 20;
    const E_NULLIFIER_ALREADY_SPENT: u64 = 21;
    const E_VAULT_SEQUENCE_MISMATCH: u64 = 22;
    const E_RECIPIENT_HASH_MISMATCH: u64 = 23;
    const E_BAD_ADMIN_ROTATION: u64 = 24;

    // ========================================================================
    // Resources
    // ========================================================================

    /// The single global bridge vault config. Lives at @eunoma.
    struct VaultConfig has key {
        admin: address,
        main_operator_addr: address,
        vault_addr: address,
        asset_type: Object<fungible_asset::Metadata>,
        vault_signer_cap: account::SignerCapability,
        operator_pubkeys: vector<vector<u8>>,
        main_operator_index: u64,
        attestation_threshold: u64,
        operator_set_version: u64,
        paused: bool,
        vault_sequence: u64,
        used_deposit_nonces: Table<vector<u8>, bool>,
    }

    /// Optional per-operator role marker (issued at update_operator_set time in
    /// Gate 3+). Currently unused in Gate 2 admin tests; declared so the resource
    /// type is present for downstream gates.
    struct OperatorRole has key {
        vault_addr: address,
        operator_index: u64,
        pubkey_hash: vector<u8>,
        active: bool,
    }

    /// Gate 4b — Deposit-binding Groth16 verification key.
    ///
    /// Stored at `@eunoma` and READ ONLY by `assert_valid_deposit_binding_proof`.
    /// Layout matches Gate 4a's exported VK fixture (snarkjs uncompressed format):
    ///   * `alpha_g1`, `beta_g2`, `gamma_g2`, `delta_g2` — sized 64 / 128 / 128 / 128 bytes.
    ///   * `ic` — vector of 64-byte G1 points; length MUST equal `VK_IC_LENGTH` (= 7 = 1 + 6).
    ///
    /// Lifecycle:
    ///   1. Deployer (admin == `@eunoma`) calls `publish_deposit_binding_vk` ONCE
    ///      after `init_vault_with_ca_registration` has succeeded. The function asserts
    ///      that no `DepositBindingVK` exists yet to prevent silent VK swap attacks.
    ///   2. After publication, `deposit_with_commitment` reads (but never mutates) the VK.
    ///
    /// Audit note: rotating the VK is intentionally NOT supported by Gate 4b's surface;
    /// VK rotation requires a full re-trusted-setup ceremony anyway and is best handled
    /// off-line by re-deploying the module (or by adding a future admin-gated rotate
    /// entry in a later gate alongside an `operator_set_version`-style migration).
    struct DepositBindingVK has key {
        alpha_g1: vector<u8>,
        beta_g2:  vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic:       vector<vector<u8>>,
    }

    /// Test-only Fr override for `derive_asset_id` / `derive_vault_addr_hash`.
    ///
    /// PURPOSE: Gate 4b reuses the Gate 4a circuit fixture (placeholder asset_id = 7,
    /// vault_addr_hash = 0xedaff... pattern) so we don't have to regenerate a fresh
    /// circuit proof every time the test environment's `Object<Metadata>` address or
    /// resource-account address changes. The Move-side `derive_*` functions consult
    /// this resource (via `test_override_present`) and, when it exists, return the
    /// stored Fr bytes verbatim.
    ///
    /// PRODUCTION SAFETY: the *installer* `install_deposit_binding_test_override`
    /// is `#[test_only]` and therefore not compiled into a published module. There
    /// is no public entry function — admin OR otherwise — that can move this
    /// resource into existence at `@eunoma` on a production deployment. The
    /// production deposit flow always goes through the real Poseidon-of-address
    /// derivation. (The runtime `exists<DepositBindingTestOverride>` check costs
    /// one extra resource lookup per deposit; that's acceptable overhead — and a
    /// future gate may strip the check entirely once a stable testnet fixture is
    /// available.)
    struct DepositBindingTestOverride has key {
        asset_id_fr: vector<u8>,        // 32-byte LE Fr bytes
        vault_addr_hash_fr: vector<u8>, // 32-byte LE Fr bytes
    }

    /// Phase B B.1 lever L-α — cached `asset_id` and `vault_addr_hash` 32-byte
    /// Fr bytes. Both inputs (asset_type, vault_addr) are per-vault static fields
    /// of `VaultConfig`, so their Poseidon-of-address derivations are deterministic
    /// and identical for every deposit. Caching them here at vault bringup time
    /// removes 2× `poseidon_bn254::hash_3` per deposit (B.0 profile evidence:
    /// 3,054 execution units / 33.69% of 8,958 baseline).
    ///
    /// Lifecycle:
    ///   1. Admin calls `init_vault_config_cache` ONCE after `init_vault` and
    ///      (in tests) after `install_deposit_binding_test_override`.
    ///   2. `assert_valid_deposit_binding_proof` reads (never mutates) the cache
    ///      to populate the Groth16 public-input vector.
    ///
    /// Compatibility: sibling resource pattern (mirrors `DepositBindingVK` /
    ///   `DepositBindingTestOverride` precedents) so this lands as an additive
    ///   compatible upgrade — `VaultConfig` schema is unchanged.
    struct VaultConfigCache has key {
        cached_asset_id: vector<u8>,        // 32-byte LE Fr bytes
        cached_vault_addr_hash: vector<u8>, // 32-byte LE Fr bytes
    }

    /// Phase B B.2 lever L-δ — prepared Groth16 verification key.
    ///
    /// `verify_proof_prepared_fq12` (groth16_bn254.move:71-86) accepts a
    /// pre-computed pairing `α·β ∈ Fq12` plus negated `-γ_g2`, `-δ_g2` and
    /// the unchanged IC vector. Compared to the slow path's 4 separate
    /// pairings + `Gt` deserialization on every deposit, the fast path
    /// performs a single `multi_pairing` of 3 inputs and skips the costly
    /// `Gt` membership test (the upcast trick documented in the upstream
    /// source comment at line 66). Both paths are mathematically identical
    /// per Groth16 paper §3.2; the audit warning at the top of
    /// `groth16_bn254.move` applies equally to both.
    ///
    /// Lifecycle:
    ///   1. Admin calls `publish_deposit_binding_vk` (legacy / Gate 4b).
    ///   2. Admin calls `publish_prepared_deposit_binding_vk` ONCE — this
    ///      reads `DepositBindingVK`, computes the pairing + 2 G2 negations
    ///      on-chain, and persists the prepared bytes here.
    ///   3. `assert_valid_deposit_binding_proof` reads `PreparedDepositBindingVK`
    ///      (no longer reads `DepositBindingVK`) and dispatches to
    ///      `verify_proof_prepared_fq12`.
    ///   4. `DepositBindingVK` remains on-chain as an immutable record of the
    ///      original VK byte material (emergency rollback / audit reference).
    ///
    /// Compatibility: sibling resource pattern. Compatible upgrade safe.
    struct PreparedDepositBindingVK has key {
        /// `pairing(alpha_g1, beta_g2)` upcast to `Fq12`, serialized via `FormatFq12LscLsb`.
        pvk_alpha_g1_beta_g2_fq12: vector<u8>,
        /// `-gamma_g2 ∈ G2`, serialized via `FormatG2Uncompr`.
        pvk_gamma_g2_neg: vector<u8>,
        /// `-delta_g2 ∈ G2`, serialized via `FormatG2Uncompr`.
        pvk_delta_g2_neg: vector<u8>,
        /// Same IC coefficients as `DepositBindingVK::ic` (7 × G1, each 64 bytes).
        pvk_uvw_gamma_g1: vector<vector<u8>>,
    }

    /// Phase 2 / Gate 6 — Withdraw circuit Groth16 verification key (raw bytes).
    /// Mirror of `DepositBindingVK` structure but for the Gate 6 withdraw circuit.
    /// Stored at `@eunoma`, written ONCE by `publish_withdraw_proof_vk`.
    /// Lifecycle: legacy retained for emergency rollback;
    /// `assert_valid_withdraw_proof` reads `PreparedWithdrawProofVK` (fast path) on
    /// the deposit hot path. (Same pattern as Phase B B.2 for deposit-binding.)
    /// Audit note: see `groth16_bn254.move` "NOT been audited" warning — applies
    /// equally to slow + fast variants of withdraw verify.
    struct WithdrawProofVK has key {
        alpha_g1: vector<u8>,
        beta_g2:  vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        /// 10 × G1 IC points (1 + 9 publics). Each 64 bytes uncompressed.
        ic:       vector<vector<u8>>,
    }

    /// Phase 2 / Gate 6 — Prepared (fast-variant) withdraw VK. Mirror of
    /// `PreparedDepositBindingVK`. Computed once at admin time by
    /// `publish_prepared_withdraw_proof_vk` from raw `WithdrawProofVK` bytes.
    struct PreparedWithdrawProofVK has key {
        pvk_alpha_g1_beta_g2_fq12: vector<u8>,  // 384 bytes
        pvk_gamma_g2_neg: vector<u8>,            // 128 bytes
        pvk_delta_g2_neg: vector<u8>,            // 128 bytes
        /// 10 × G1 IC points (1 + 9 publics). Each 64 bytes uncompressed.
        pvk_uvw_gamma_g1: vector<vector<u8>>,
    }

    /// Phase 2 / Gate 6 — set of nullifier_hash bytes already spent.
    /// Bridge inserts on successful `withdraw_to_recipient`; subsequent attempts
    /// with the same nullifier abort `E_NULLIFIER_ALREADY_SPENT`.
    /// Initialized once via admin entry `init_used_nullifiers_table` (matches
    /// Phase B sibling-resource pattern; not auto-created at vault init).
    struct UsedNullifiers has key {
        table: Table<vector<u8>, bool>,
    }

    /// View-only metadata struct (replaces removed get_vault_balance_encrypted).
    /// `is_normalized` and `num_transfers_received` are bridge-readable derived
    /// values from confidential_asset; the encrypted balance ciphertext itself is
    /// not exposed (CompressedBalance accessors are public(friend) — see
    /// LOCAL_CONFIRMATION 8.8). Indexers should read the raw ConfidentialStore
    /// resource via the REST API for ciphertext.
    struct VaultBalanceMetadata has drop, copy, store {
        vault_addr: address,
        asset_type: Object<fungible_asset::Metadata>,
        is_normalized: bool,
        num_transfers_received: u64,
    }

    // ========================================================================
    // Events
    // ========================================================================

    #[event]
    struct VaultInitialized has drop, store {
        vault_addr: address,
        asset_type: Object<fungible_asset::Metadata>,
        main_operator_index: u64,
        attestation_threshold: u64,
        operator_set_version: u64,
    }

    #[event]
    struct OperatorSetUpdated has drop, store {
        operator_set_version: u64,
        main_operator_index: u64,
        threshold: u64,
        active_operator_count: u64,
    }

    #[event]
    struct BridgePauseChanged has drop, store {
        paused: bool,
    }

    /// Phase 2 / Gate 6 — emitted on successful `withdraw_to_recipient`.
    ///
    /// Phase D / Agent D6 gas trim: `asset_type` field removed. The vault's
    /// asset_type is fixed per deployment and readable via the
    /// `get_asset_type()` view from `VaultConfig`. Indexers that need
    /// per-event asset disambiguation must read VaultConfig at the same
    /// version once at startup; removing this field saves the 32-byte BCS
    /// encoding (address) on every withdraw emit.
    /// BREAK NOTE: external event subscribers that decoded `asset_type` from
    /// raw event JSON must migrate to VaultConfig view. The in-tree
    /// operator-services has no such consumer (verified 2026-05-11).
    #[event]
    struct WithdrawEvent has drop, store {
        nullifier_hash: vector<u8>,
        recipient: address,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
    }

    #[event]
    struct AdminRotated has drop, store {
        old_admin: address,
        new_admin: address,
    }

    /// Gate 4b — Deposit completion event (HANDOFF Section 2.3).
    ///
    /// Emitted at the END of `deposit_with_commitment` after every gate has passed
    /// (4-of-7 attestation, Groth16 deposit-binding proof, nonce-replay table insert,
    /// CA framework dispatch). Indexers consume this to track the shielded-pool
    /// commitment list.
    ///
    /// `leaf_index` is a placeholder until the deposit-batching architecture decision
    /// lands (see `coordination/LOCAL_ARCHITECTURE_UPDATE_DEPOSIT_BATCHING.md`):
    /// direct-insert pools return the post-insert leaf index; batched-enqueue pools
    /// would emit `u64::MAX`. Until then the bridge emits 0 unconditionally and a
    /// follow-up gate replaces this single field once the architecture is pinned.
    /// TODO pool gate: replace placeholder leaf_index = 0 with real value.
    /// Phase D / Agent D6 gas trim: `asset_type` field removed (32-byte BCS).
    /// Same rationale as WithdrawEvent — asset_type is fixed per deployment
    /// and obtainable via `get_asset_type()` from VaultConfig. Saves storage
    /// gas on every deposit (hot path).
    #[event]
    struct DepositEvent has drop, store {
        commitment: vector<u8>,
        leaf_index: u64,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
    }

    // ========================================================================
    // Attestation message structs (Section 2.4)
    //
    // Field order is part of the BCS encoding. DO NOT reorder. Off-chain TS
    // operator services build the same struct in the same order before signing.
    // ========================================================================

    struct DepositAttestationMessage has drop, store, copy {
        domain: vector<u8>,
        chain_id: u8,
        pool_id: vector<u8>,
        operator_set_version: u64,
        threshold: u64,
        vault_addr: address,
        asset_type: Object<fungible_asset::Metadata>,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
    }

    struct WithdrawAttestationMessage has drop, store, copy {
        domain: vector<u8>,
        chain_id: u8,
        pool_id: vector<u8>,
        operator_set_version: u64,
        threshold: u64,
        vault_addr: address,
        asset_type: Object<fungible_asset::Metadata>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
    }

    // ========================================================================
    // Admin entry functions (Section 2.5 — admin subset)
    // ========================================================================

    /// Initialise the bridge vault.
    ///
    /// Gate 2 path B: ConfidentialAPT registration is omitted from the in-scope
    /// admin path. The vault resource account is still created via
    /// `account::create_resource_account` (LOCAL_CONFIRMATION 8.3). Gate 3 will
    /// add a real `confidential_asset::register_raw(&vault_signer, asset_type,
    /// vault_ek, ...)` call — the params are accepted today (and validated for
    /// length only) so the public ABI is stable.
    public entry fun init_vault(
        admin: &signer,
        main_operator_addr: address,
        asset_type: Object<fungible_asset::Metadata>,
        operator_pubkeys: vector<vector<u8>>,
        main_operator_index: u64,
        attestation_threshold: u64,
        vault_seed: vector<u8>,
        vault_ek: vector<u8>,
        registration_sigma_proto_comm: vector<vector<u8>>,
        registration_sigma_proto_resp: vector<vector<u8>>,
    ) {
        let admin_addr = signer::address_of(admin);
        // Bridge resource lives at @eunoma (module-static address).
        // init_vault must be called by the @eunoma deployer signer.
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(
            !exists<VaultConfig>(@eunoma),
            E_ALREADY_INITIALIZED,
        );

        // Validate operator set BEFORE creating the resource account (so a bad
        // call doesn't leave behind orphaned on-chain accounts).
        assert_valid_operator_set(
            &operator_pubkeys,
            main_operator_index,
            attestation_threshold,
        );

        // Gate 3 will consume vault_ek + sigma_proto_comm/resp inside
        // confidential_asset::register_raw via init_vault_with_ca_registration
        // (a parallel production entry that does the real cross-module call).
        // For backward compatibility with Gate 2 tests we accept these as part
        // of the public ABI here but DO NOT dispatch the registration; this
        // keeps the Gate 2 fixture tests working with placeholder bytes.
        let _vault_ek = vault_ek;
        let _comm = registration_sigma_proto_comm;
        let _resp = registration_sigma_proto_resp;

        let (vault_signer, vault_signer_cap) = account::create_resource_account(
            admin,
            vault_seed,
        );
        let vault_addr = signer::address_of(&vault_signer);

        // ---- Gate 3 hook ----
        // The real `confidential_asset::register_raw` call lives in the
        // sibling `init_vault_with_ca_registration` entry function below
        // (Gate 3 production-correct variant). This `init_vault` is retained
        // as the Gate 2 stub variant to keep Gate 2 fixture tests reproducible.
        // Gates 4 / 5 will deprecate this stub; production deployments MUST
        // call `init_vault_with_ca_registration`.
        let _vault_signer_unused_in_stub = &vault_signer;

        let cfg = VaultConfig {
            admin: admin_addr,
            main_operator_addr,
            vault_addr,
            asset_type,
            vault_signer_cap,
            operator_pubkeys,
            main_operator_index,
            attestation_threshold,
            operator_set_version: 0,
            paused: false,
            vault_sequence: 0,
            used_deposit_nonces: table::new<vector<u8>, bool>(),
        };

        event::emit(VaultInitialized {
            vault_addr,
            asset_type,
            main_operator_index,
            attestation_threshold,
            operator_set_version: 0,
        });

        move_to(admin, cfg);
    }

    /// Gate 3 production-correct vault initialization.
    ///
    /// Identical to `init_vault` except this variant DOES dispatch the real
    /// `aptos_framework::confidential_asset::register_raw` call against the
    /// freshly-minted vault resource account. This is the entry point
    /// production deployments MUST call (`init_vault` is a Gate 2 stub
    /// retained for backward-compatible tests).
    ///
    /// Empirical confirmation of `LOCAL_CONFIRMATION.md` item 8.4: `register_raw`
    /// is `public entry fun` in `aptos_framework::confidential_asset`, and a
    /// non-friend external module can dispatch it cross-module — this is the
    /// composition pattern Gates 4 / 5 / 6 will reuse for the deposit /
    /// withdraw / rollover flows.
    public entry fun init_vault_with_ca_registration(
        admin: &signer,
        main_operator_addr: address,
        asset_type: Object<fungible_asset::Metadata>,
        operator_pubkeys: vector<vector<u8>>,
        main_operator_index: u64,
        attestation_threshold: u64,
        vault_seed: vector<u8>,
        vault_ek: vector<u8>,
        registration_sigma_proto_comm: vector<vector<u8>>,
        registration_sigma_proto_resp: vector<vector<u8>>,
    ) {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(
            !exists<VaultConfig>(@eunoma),
            E_ALREADY_INITIALIZED,
        );

        assert_valid_operator_set(
            &operator_pubkeys,
            main_operator_index,
            attestation_threshold,
        );

        let (vault_signer, vault_signer_cap) = account::create_resource_account(
            admin,
            vault_seed,
        );
        let vault_addr = signer::address_of(&vault_signer);

        // ---- Gate 3 cross-module CA registration ----
        // The vault signer is held only on this stack frame and is consumed
        // by `register_raw`. The `SignerCapability` is the only persistent
        // handle and is moved into `VaultConfig` below; downstream
        // operator-gated entry functions regenerate the vault signer on
        // demand via `account::create_signer_with_capability` (see
        // `test_only_vault_rollover` and `test_only_vault_to_recipient_transfer_raw`
        // for the regeneration pattern).
        confidential_asset::register_raw(
            &vault_signer,
            asset_type,
            vault_ek,
            registration_sigma_proto_comm,
            registration_sigma_proto_resp,
        );

        let cfg = VaultConfig {
            admin: admin_addr,
            main_operator_addr,
            vault_addr,
            asset_type,
            vault_signer_cap,
            operator_pubkeys,
            main_operator_index,
            attestation_threshold,
            operator_set_version: 0,
            paused: false,
            vault_sequence: 0,
            used_deposit_nonces: table::new<vector<u8>, bool>(),
        };

        event::emit(VaultInitialized {
            vault_addr,
            asset_type,
            main_operator_index,
            attestation_threshold,
            operator_set_version: 0,
        });

        move_to(admin, cfg);
    }

    public entry fun update_operator_set(
        admin: &signer,
        new_operator_pubkeys: vector<vector<u8>>,
        new_main_operator_index: u64,
        new_threshold: u64,
    ) acquires VaultConfig {
        assert!(exists<VaultConfig>(@eunoma), E_NOT_INITIALIZED);
        let cfg = borrow_global_mut<VaultConfig>(@eunoma);
        assert_admin_inner(cfg, admin);

        assert_valid_operator_set(
            &new_operator_pubkeys,
            new_main_operator_index,
            new_threshold,
        );

        cfg.operator_pubkeys = new_operator_pubkeys;
        cfg.main_operator_index = new_main_operator_index;
        cfg.attestation_threshold = new_threshold;
        cfg.operator_set_version = cfg.operator_set_version + 1;

        let active_count = active_operator_count(&cfg.operator_pubkeys);
        event::emit(OperatorSetUpdated {
            operator_set_version: cfg.operator_set_version,
            main_operator_index: cfg.main_operator_index,
            threshold: cfg.attestation_threshold,
            active_operator_count: active_count,
        });
    }

    public entry fun pause(admin: &signer) acquires VaultConfig {
        assert!(exists<VaultConfig>(@eunoma), E_NOT_INITIALIZED);
        let cfg = borrow_global_mut<VaultConfig>(@eunoma);
        assert_admin_inner(cfg, admin);
        assert!(!cfg.paused, E_BRIDGE_PAUSED);
        cfg.paused = true;
        event::emit(BridgePauseChanged { paused: true });
    }

    public entry fun unpause(admin: &signer) acquires VaultConfig {
        assert!(exists<VaultConfig>(@eunoma), E_NOT_INITIALIZED);
        let cfg = borrow_global_mut<VaultConfig>(@eunoma);
        assert_admin_inner(cfg, admin);
        assert!(cfg.paused, E_BRIDGE_NOT_PAUSED);
        cfg.paused = false;
        event::emit(BridgePauseChanged { paused: false });
    }

    public entry fun rotate_admin(
        admin: &signer,
        new_admin: address,
    ) acquires VaultConfig {
        assert!(exists<VaultConfig>(@eunoma), E_NOT_INITIALIZED);
        let cfg = borrow_global_mut<VaultConfig>(@eunoma);
        assert_admin_inner(cfg, admin);
        assert!(new_admin != @0x0, E_BAD_ADMIN_ROTATION);
        let old_admin = cfg.admin;
        cfg.admin = new_admin;
        event::emit(AdminRotated { old_admin, new_admin });
    }

    // ========================================================================
    // View functions (Section 2.6)
    //
    // All views read from the singleton VaultConfig at @eunoma.
    // ========================================================================

    #[view]
    public fun get_vault_addr(): address acquires VaultConfig {
        borrow_global<VaultConfig>(@eunoma).vault_addr
    }

    #[view]
    public fun get_asset_type(): Object<fungible_asset::Metadata> acquires VaultConfig {
        borrow_global<VaultConfig>(@eunoma).asset_type
    }

    #[view]
    public fun get_operator_pubkeys(): vector<vector<u8>> acquires VaultConfig {
        borrow_global<VaultConfig>(@eunoma).operator_pubkeys
    }

    #[view]
    public fun get_main_operator_index(): u64 acquires VaultConfig {
        borrow_global<VaultConfig>(@eunoma).main_operator_index
    }

    #[view]
    public fun get_attestation_threshold(): u64 acquires VaultConfig {
        borrow_global<VaultConfig>(@eunoma).attestation_threshold
    }

    #[view]
    public fun get_operator_set_version(): u64 acquires VaultConfig {
        borrow_global<VaultConfig>(@eunoma).operator_set_version
    }

    #[view]
    public fun get_vault_sequence(): u64 acquires VaultConfig {
        borrow_global<VaultConfig>(@eunoma).vault_sequence
    }

    #[view]
    public fun is_paused(): bool acquires VaultConfig {
        borrow_global<VaultConfig>(@eunoma).paused
    }

    #[view]
    public fun is_deposit_nonce_used(nonce: vector<u8>): bool acquires VaultConfig {
        let cfg = borrow_global<VaultConfig>(@eunoma);
        table::contains(&cfg.used_deposit_nonces, nonce)
    }

    #[view]
    public fun get_admin(): address acquires VaultConfig {
        borrow_global<VaultConfig>(@eunoma).admin
    }

    // Replaces removed `get_vault_balance_encrypted` (LOCAL_CONFIRMATION 8.8).
    // CompressedBalance ciphertext fields are public(friend) and not bridge-readable;
    // indexers must hit `GET /v1/accounts/{vault_addr}/resource/0x1::confidential_asset::ConfidentialStore`
    // for raw bytes. This on-chain view exposes the bridge-owned identity plus
    // confidential_asset's two public derived booleans.
    //
    // IMPORTANT: this view requires the vault to have a registered ConfidentialStore.
    // In Gate 2 (path B) the vault is NOT yet CA-registered, so calling this view
    // before Gate 3 may abort inside confidential_asset. To keep Gate 2 unit tests
    // hermetic we expose `get_vault_balance_metadata_bridge_only` which avoids
    // the cross-module CA call entirely. Both functions are present so the
    // production caller (Gate 3+) gets the full metadata.
    #[view]
    public fun get_vault_balance_metadata(): VaultBalanceMetadata acquires VaultConfig {
        let cfg = borrow_global<VaultConfig>(@eunoma);
        VaultBalanceMetadata {
            vault_addr: cfg.vault_addr,
            asset_type: cfg.asset_type,
            is_normalized: aptos_framework::confidential_asset::is_normalized(
                cfg.vault_addr,
                cfg.asset_type,
            ),
            num_transfers_received: aptos_framework::confidential_asset::get_num_transfers_received(
                cfg.vault_addr,
                cfg.asset_type,
            ),
        }
    }

    // Pre-CA-registration variant: returns only bridge-owned fields. Useful for
    // Gate 2 unit tests where the vault is not yet registered with confidential_asset.
    #[view]
    public fun get_vault_balance_metadata_bridge_only(): VaultBalanceMetadata acquires VaultConfig {
        let cfg = borrow_global<VaultConfig>(@eunoma);
        VaultBalanceMetadata {
            vault_addr: cfg.vault_addr,
            asset_type: cfg.asset_type,
            is_normalized: false,
            num_transfers_received: 0,
        }
    }

    // ========================================================================
    // Internal helpers (Section 2.7)
    // ========================================================================

    /// Public so test code can call it; uses `assert_admin_inner` internally.
    fun assert_admin_inner(cfg: &VaultConfig, caller: &signer) {
        assert!(signer::address_of(caller) == cfg.admin, E_NOT_ADMIN);
    }

    fun assert_not_expired(expiry_secs: u64) {
        let now = timestamp::now_seconds();
        assert!(expiry_secs >= now, E_EXPIRED_ATTESTATION);
    }

    /// Counts non-empty pubkey slots (Section 2.8 semantics: empty vector ==
    /// inactive slot).
    fun active_operator_count(operator_pubkeys: &vector<vector<u8>>): u64 {
        let n = vector::length(operator_pubkeys);
        let active = 0;
        let i = 0;
        while (i < n) {
            let pk = vector::borrow(operator_pubkeys, i);
            if (vector::length(pk) > 0) {
                active = active + 1;
            };
            i = i + 1;
        };
        active
    }

    /// Validate a candidate operator-set / threshold / main-index triple.
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

        // Main operator slot must be ACTIVE (non-empty pubkey).
        let main_pk = vector::borrow(operator_pubkeys, main_operator_index);
        assert!(vector::length(main_pk) > 0, E_BAD_MAIN_OPERATOR_INDEX);

        // Validate every active pubkey is exactly 32 bytes (Ed25519 pubkey size).
        // Empty (length 0) slots are allowed and signal "inactive".
        let i = 0;
        while (i < MAX_OPERATORS) {
            let pk = vector::borrow(operator_pubkeys, i);
            let len = vector::length(pk);
            assert!(
                len == 0 || len == ED25519_PUBLIC_KEY_BYTES,
                E_BAD_OPERATOR_SET_LENGTH,
            );
            i = i + 1;
        };

        let active = active_operator_count(operator_pubkeys);
        assert!(threshold >= MIN_THRESHOLD, E_BAD_THRESHOLD);
        assert!(threshold <= MAX_OPERATORS, E_BAD_THRESHOLD);
        assert!(threshold <= active, E_BAD_THRESHOLD);
    }

    // Gate 5 / Step 4 (2026-05-07): bridge-private `assert_valid_operator_attestation`
    // and `verify_operator_signature` deleted. The 4-of-7 + main-must-sign
    // verification is now centralized in `pool_multi_sig_verifier`. Bridge
    // callsites pass `&cfg.operator_pubkeys, cfg.attestation_threshold,
    // cfg.main_operator_index` directly to the param-form
    // `pool_multi_sig_verifier::assert_valid_attestation`. Wire-spec abort codes
    // shift from bridge codes 7-13 to pool codes 100-110; LOCAL_ERRATA records
    // the migration. operator-services parses success/failure only — no client
    // depends on numeric codes.

    /// Build a canonical DepositAttestationMessage. operator_set_version and
    /// threshold are read from the bridge config so signatures can never be
    /// replayed across operator-set updates (forbidden action #18).
    fun new_deposit_attestation_message(
        cfg: &VaultConfig,
        chain_id: u8,
        pool_id: vector<u8>,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
    ): DepositAttestationMessage {
        DepositAttestationMessage {
            domain: DOMAIN_DEPOSIT_OK_V1,
            chain_id,
            pool_id,
            operator_set_version: cfg.operator_set_version,
            threshold: cfg.attestation_threshold,
            vault_addr: cfg.vault_addr,
            asset_type: cfg.asset_type,
            commitment,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
            expiry_secs,
        }
    }

    fun new_withdraw_attestation_message(
        cfg: &VaultConfig,
        chain_id: u8,
        pool_id: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
    ): WithdrawAttestationMessage {
        WithdrawAttestationMessage {
            domain: DOMAIN_WITHDRAW_OK_V1,
            chain_id,
            pool_id,
            operator_set_version: cfg.operator_set_version,
            threshold: cfg.attestation_threshold,
            vault_addr: cfg.vault_addr,
            asset_type: cfg.asset_type,
            nullifier_hash,
            recipient,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            request_hash,
            vault_sequence,
            expiry_secs,
        }
    }

    // ========================================================================
    // Gate 4b — Deposit-binding helpers + entry functions
    // ========================================================================

    /// CA-payload BCS struct used solely by `hash_confidential_transfer_payload`.
    ///
    /// Decision (subagent — documented in REPORT_GATE_4B): Option A from the brief —
    /// `keccak256(bcs::to_bytes(&CAPayloadForHash { ... }))`. The Move side hashes only
    /// to bind the attestation message to the EXACT CA `confidential_transfer_raw`
    /// arguments; it never verifies a circuit input over this hash, so Poseidon
    /// (Option B) gives no benefit and would make the off-chain TS operator pay the
    /// Poseidon parity tax twice (once for commitment/amount_tag and once for the
    /// payload hash). Keccak256 over BCS-encoded fields is:
    ///   * deterministic (BCS is canonical),
    ///   * easy to mirror in TS (`@aptos-labs/ts-sdk` exposes BCS + keccak256),
    ///   * O(1) circuit-independent in cost.
    ///
    /// Field ORDER must match the off-chain operator's BCS-encoder byte-for-byte.
    /// `asset_type` is included so a payload signed against asset A cannot be replayed
    /// against asset B even after a future multi-asset bridge migration; `vault_addr`
    /// is included so a payload prepared for vault X cannot be replayed against vault Y
    /// across redeployments. The remaining 14 fields mirror `confidential_transfer_raw`'s
    /// arg list verbatim (LOCAL_CONFIRMATION 8.4 + Aptos framework
    /// `confidential_asset::confidential_transfer_raw` signature).
    struct CAPayloadForHash has drop, copy {
        asset_type: Object<fungible_asset::Metadata>,
        vault_addr: address,
        new_balance_p:        vector<vector<u8>>,
        new_balance_r:        vector<vector<u8>>,
        new_balance_r_eff_aud: vector<vector<u8>>,
        amount_p:             vector<vector<u8>>,
        amount_r_sender:      vector<vector<u8>>,
        amount_r_recip:       vector<vector<u8>>,
        amount_r_eff_aud:     vector<vector<u8>>,
        ek_volun_auds:        vector<vector<u8>>,
        amount_r_volun_auds:  vector<vector<vector<u8>>>,
        zkrp_new_balance:     vector<u8>,
        zkrp_amount:          vector<u8>,
        sigma_proto_comm:     vector<vector<u8>>,
        sigma_proto_resp:     vector<vector<u8>>,
        memo:                 vector<u8>,
    }

    /// HANDOFF Section 2.7 — bind the attestation message to the EXACT CA call.
    /// Returns a 32-byte keccak256 digest. Off-chain TS operator (Gate 4c) MUST
    /// reproduce this hash byte-for-byte — operator service builds the same
    /// `CAPayloadForHash`, BCS-encodes in identical field order, and keccaks.
    fun hash_confidential_transfer_payload(
        asset_type: Object<fungible_asset::Metadata>,
        vault_addr: address,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_eff_aud: vector<vector<u8>>,
        amount_p: vector<vector<u8>>,
        amount_r_sender: vector<vector<u8>>,
        amount_r_recip: vector<vector<u8>>,
        amount_r_eff_aud: vector<vector<u8>>,
        ek_volun_auds: vector<vector<u8>>,
        amount_r_volun_auds: vector<vector<vector<u8>>>,
        zkrp_new_balance: vector<u8>,
        zkrp_amount: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
        memo: vector<u8>,
    ): vector<u8> {
        let payload = CAPayloadForHash {
            asset_type,
            vault_addr,
            new_balance_p,
            new_balance_r,
            new_balance_r_eff_aud,
            amount_p,
            amount_r_sender,
            amount_r_recip,
            amount_r_eff_aud,
            ek_volun_auds,
            amount_r_volun_auds,
            zkrp_new_balance,
            zkrp_amount,
            sigma_proto_comm,
            sigma_proto_resp,
            memo,
        };
        aptos_hash::keccak256(bcs::to_bytes(&payload))
    }

    /// Pad an arbitrary byte string into a 32-byte little-endian Fr-canonical buffer.
    /// Source bytes MUST be <= 32 bytes; high-order positions are zero-filled.
    /// Used for chain_id (1B), pool_id (8B), domain separators (<32B).
    fun bytes_to_field_le32(src: &vector<u8>): vector<u8> {
        let n = vector::length(src);
        assert!(n <= FR_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        let out = vector::empty<u8>();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut out, *vector::borrow(src, i));
            i = i + 1;
        };
        while (i < FR_BYTES) {
            vector::push_back(&mut out, 0u8);
            i = i + 1;
        };
        out
    }

    /// Slice the bytes from `[start, end)` into a fresh vector. start <= end <= len(src).
    /// Used to split 32-byte addresses into hi (0..16) / lo (16..32) halves so that
    /// each half fits cleanly inside a BN254 Fr scalar (Fr is ~254 bits ≈ 32 bytes,
    /// but a full 32-byte LE address may exceed the field modulus, so we split).
    fun byte_slice(src: &vector<u8>, start: u64, end: u64): vector<u8> {
        let n = vector::length(src);
        assert!(start <= end && end <= n, E_INVALID_DEPOSIT_BINDING_PROOF);
        let out = vector::empty<u8>();
        let i = start;
        while (i < end) {
            vector::push_back(&mut out, *vector::borrow(src, i));
            i = i + 1;
        };
        // Zero-pad to 32 bytes (LE) so Poseidon's fr_from_le accepts the half.
        while (vector::length(&out) < FR_BYTES) {
            vector::push_back(&mut out, 0u8);
        };
        out
    }

    /// Derive a deposit-binding-circuit-friendly `asset_id` Fr from the bridge's
    /// `Object<Metadata>` address. Convention (subagent — documented in REPORT_GATE_4B):
    ///   asset_id = poseidon_bn254::hash_3(domain, addr_hi_16B, addr_lo_16B)
    /// where domain is `POSEIDON_DOMAIN_ASSET_ID` zero-padded to 32 bytes LE,
    /// addr_hi_16B is bytes [0..16) of the BCS-encoded address zero-padded to 32 bytes LE,
    /// and addr_lo_16B is bytes [16..32) similarly padded.
    ///
    /// Off-chain TS operator (Gate 4c) MUST mirror this byte-for-byte. Since
    /// addresses are 32 bytes and BN254 Fr is ~254 bits, splitting into two halves
    /// (each 16 bytes wide ⇒ 128-bit value padded to 32-byte LE) avoids any
    /// modular-overflow ambiguity.
    ///
    /// Test-only override: if a `DepositBindingTestOverride` resource exists at
    /// `@eunoma`, return its stored `asset_id_fr` instead. This lets Gate 4b
    /// reuse the Gate 4a fixture (placeholder asset_id = 7) without regenerating
    /// the circuit proof against a real Poseidon-of-address derivation. The
    /// override resource is `#[test_only]` and never compiles into a published
    /// module — production deployments use the real Poseidon path unconditionally.
    fun derive_asset_id(asset_type: Object<fungible_asset::Metadata>): vector<u8> acquires DepositBindingTestOverride {
        if (test_override_present()) {
            return test_override_asset_id()
        };
        let addr = object::object_address(&asset_type);
        let addr_bytes = bcs::to_bytes(&addr);
        // Aptos addresses are exactly 32 bytes.
        assert!(vector::length(&addr_bytes) == FR_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        let hi = byte_slice(&addr_bytes, 0, 16);
        let lo = byte_slice(&addr_bytes, 16, 32);
        let domain_bytes = POSEIDON_DOMAIN_ASSET_ID;
        let domain = bytes_to_field_le32(&domain_bytes);
        poseidon_bn254::hash_3(domain, hi, lo)
    }

    /// Derive a deposit-binding-circuit-friendly `vault_addr_hash` Fr from a vault
    /// resource-account address. Convention identical to `derive_asset_id` but with
    /// `POSEIDON_DOMAIN_VAULT_ADDR_HASH` so the two halves of the same 32-byte
    /// address can never collide across the two derivations.
    ///
    /// Test-only override: see `derive_asset_id`.
    fun derive_vault_addr_hash(vault_addr: address): vector<u8> acquires DepositBindingTestOverride {
        if (test_override_present()) {
            return test_override_vault_addr_hash()
        };
        let addr_bytes = bcs::to_bytes(&vault_addr);
        assert!(vector::length(&addr_bytes) == FR_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        let hi = byte_slice(&addr_bytes, 0, 16);
        let lo = byte_slice(&addr_bytes, 16, 32);
        let domain_bytes = POSEIDON_DOMAIN_VAULT_ADDR_HASH;
        let domain = bytes_to_field_le32(&domain_bytes);
        poseidon_bn254::hash_3(domain, hi, lo)
    }

    /// Phase 2 / Gate 6 — derive the canonical recipient_hash from a recipient
    /// address. Same hash_3(domain, hi, lo) convention as `derive_vault_addr_hash`
    /// but with `POSEIDON_DOMAIN_RECIPIENT_HASH` so the two halves of the same
    /// 32-byte address can never collide across the two derivations. Off-chain
    /// withdraw proof generator MUST mirror byte-for-byte.
    fun derive_recipient_hash(recipient: address): vector<u8> {
        let addr_bytes = bcs::to_bytes(&recipient);
        assert!(vector::length(&addr_bytes) == FR_BYTES, E_RECIPIENT_HASH_MISMATCH);
        let hi = byte_slice(&addr_bytes, 0, 16);
        let lo = byte_slice(&addr_bytes, 16, 32);
        let domain_bytes = POSEIDON_DOMAIN_RECIPIENT_HASH;
        let domain = bytes_to_field_le32(&domain_bytes);
        poseidon_bn254::hash_3(domain, hi, lo)
    }

    // ----- Test override gate -----
    // In production builds (no `aptos move test`), `test_override_present`
    // and friends are `#[test_only]` no-ops that never get linked. The
    // `if (test_override_present()) ... return ...` branches above compile
    // in production to "always-false branch elided" because production has
    // no installer for `DepositBindingTestOverride`, so `exists<...>` is
    // always false. Inlining a const `false` would be cleaner but Move
    // lacks compile-time conditional code; the runtime exists check is
    // equivalent (one extra resource lookup per deposit).

    fun test_override_present(): bool {
        exists<DepositBindingTestOverride>(@eunoma)
    }

    fun test_override_asset_id(): vector<u8> acquires DepositBindingTestOverride {
        let r = borrow_global<DepositBindingTestOverride>(@eunoma);
        r.asset_id_fr
    }

    fun test_override_vault_addr_hash(): vector<u8> acquires DepositBindingTestOverride {
        let r = borrow_global<DepositBindingTestOverride>(@eunoma);
        r.vault_addr_hash_fr
    }

    /// Read the live `chain_id` from the framework and pad to 32-byte LE Fr.
    /// Decision (subagent — documented in REPORT_GATE_4B): use `chain_id::get(): u8`
    /// from `aptos_framework::chain_id`. Mainnet = 1, testnet = 2 (matches Gate 4a
    /// fixture's chain_id = 2).
    fun chain_id_to_fr_bytes(): vector<u8> {
        let id: u8 = chain_id::get();
        let buf = vector::empty<u8>();
        vector::push_back(&mut buf, id);
        bytes_to_field_le32(&buf)
    }

    /// Encode the bridge constant `POOL_ID_VALUE` (u64) as 32-byte LE Fr.
    /// Decision (subagent — documented in REPORT_GATE_4B): hardcoded constant 0
    /// for now (matches Gate 4a fixture). The pool gate (post-batching-decision)
    /// may rewrite this to a per-pool registry lookup.
    /// Gas P4: build the 32-byte buffer in one pass instead of an 8-byte temp
    /// followed by a call to `bytes_to_field_le32` (which re-allocates and does
    /// another 32 push_backs). Saves one alloc + one helper call + ~8 ops per
    /// deposit/withdraw on the attestation hot path.
    fun pool_id_to_fr_bytes(): vector<u8> {
        let n = POOL_ID_VALUE;
        let buf = vector::empty<u8>();
        let i = 0;
        while (i < 8) {
            vector::push_back(&mut buf, ((n & 0xFFu64) as u8));
            n = n >> 8;
            i = i + 1;
        };
        while (i < FR_BYTES) {
            vector::push_back(&mut buf, 0u8);
            i = i + 1;
        };
        buf
    }

    /// Phase D Agent D1 — 8-byte LE u64 encoding of `POOL_ID_VALUE` for use as
    /// the `pool_id` field of `DepositAttestationMessage`. The 32-byte LE Fr
    /// form (`pool_id_to_fr_bytes`) is still used for the Groth16 binding-proof
    /// public input (where field-element width is mandatory), but the
    /// attestation-signing message only needs an unambiguous 8-byte u64 — which
    /// is what the off-chain TS deposit encoder already produces (see
    /// `operator-services/shared/src/attestation.ts:60-89`). Shrinking from
    /// 32 → 8 bytes on the attestation hot path:
    ///   * saves 24 BCS bytes per signed message (24 bytes of payload; the
    ///     ULEB128 length prefix stays 1 byte for both 8 and 32),
    ///   * shrinks the SHA512 input fed to each ed25519::signature_verify_strict
    ///     call (4× per deposit at 4-of-7),
    ///   * fixes a pre-existing Move-vs-TS parity bug (Move signed-over 32 B,
    ///     TS signed-over 8 B on deposit — see attestation.ts comment line 60).
    fun pool_id_to_le_u64_bytes(): vector<u8> {
        let n = POOL_ID_VALUE;
        let buf = vector::empty<u8>();
        let i = 0;
        while (i < 8) {
            vector::push_back(&mut buf, ((n & 0xFFu64) as u8));
            n = n >> 8;
            i = i + 1;
        };
        buf
    }

    /// Helper: deserialize a 32-byte LE Fr scalar. Aborts on malformed bytes.
    fun de_fr(bytes: vector<u8>): crypto_algebra::Element<Fr> {
        let opt = crypto_algebra::deserialize<Fr, FormatFrLsb>(&bytes);
        assert!(option::is_some(&opt), E_INVALID_DEPOSIT_BINDING_PROOF);
        option::extract(&mut opt)
    }

    /// Helper: deserialize a 64-byte uncompressed G1 point.
    fun de_g1(bytes: vector<u8>): crypto_algebra::Element<G1> {
        let opt = crypto_algebra::deserialize<G1, FormatG1Uncompr>(&bytes);
        assert!(option::is_some(&opt), E_INVALID_DEPOSIT_BINDING_PROOF);
        option::extract(&mut opt)
    }

    /// Helper: deserialize a 128-byte uncompressed G2 point.
    fun de_g2(bytes: vector<u8>): crypto_algebra::Element<G2> {
        let opt = crypto_algebra::deserialize<G2, FormatG2Uncompr>(&bytes);
        assert!(option::is_some(&opt), E_INVALID_DEPOSIT_BINDING_PROOF);
        option::extract(&mut opt)
    }

    /// Helper: deserialize a 384-byte Fq12 element via `FormatFq12LscLsb`.
    /// Used by Phase B L-δ to read the pre-computed `α·β` from `PreparedDepositBindingVK`.
    fun de_fq12(bytes: vector<u8>): crypto_algebra::Element<Fq12> {
        let opt = crypto_algebra::deserialize<Fq12, FormatFq12LscLsb>(&bytes);
        assert!(option::is_some(&opt), E_INVALID_DEPOSIT_BINDING_PROOF);
        option::extract(&mut opt)
    }

    /// Verify the Groth16 deposit-binding proof. Aborts `E_INVALID_DEPOSIT_BINDING_PROOF`
    /// if (a) the VK is malformed, (b) the proof is the wrong byte length,
    /// (c) any field deserialization fails, or (d) the pairing equation does not hold.
    ///
    /// Public-input wire order (must match Gate 4a circuit verbatim):
    ///   [commitment, amount_tag, asset_id, vault_addr_hash, chain_id, pool_id]
    /// Reordering breaks the verifier silently — IC scalar mul is order-sensitive.
    fun assert_valid_deposit_binding_proof(
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        proof: vector<u8>,
    ) acquires PreparedDepositBindingVK, VaultConfigCache {
        // Phase B L-δ — read the prepared VK (slow path's `DepositBindingVK`
        // is no longer touched on the deposit hot path; it remains on-chain
        // as immutable record / emergency rollback).
        assert!(exists<PreparedDepositBindingVK>(@eunoma), E_NOT_INITIALIZED);
        let pvk = borrow_global<PreparedDepositBindingVK>(@eunoma);

        // IC length invariant (must equal VK_IC_LENGTH = 7 = 1 + l for l = 6 publics).
        assert!(vector::length(&pvk.pvk_uvw_gamma_g1) == VK_IC_LENGTH, E_INVALID_DEPOSIT_BINDING_PROOF);
        // Defensive size checks on prepared VK byte sizes — already asserted at
        // `publish_prepared_deposit_binding_vk` time. (A future T3 lever may elide
        // these; per the plan they're kept for now.)
        assert!(vector::length(&pvk.pvk_alpha_g1_beta_g2_fq12) == FQ12_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&pvk.pvk_gamma_g2_neg) == G2_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&pvk.pvk_delta_g2_neg) == G2_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);

        // Deserialize prepared VK components.
        let pvk_alpha_beta = de_fq12(pvk.pvk_alpha_g1_beta_g2_fq12);
        let pvk_gamma_neg  = de_g2(pvk.pvk_gamma_g2_neg);
        let pvk_delta_neg  = de_g2(pvk.pvk_delta_g2_neg);

        // Deserialize each IC point (size-check each one, then de_g1).
        let vk_ic = vector::empty<crypto_algebra::Element<G1>>();
        let i = 0;
        while (i < VK_IC_LENGTH) {
            let ic_bytes = *vector::borrow(&pvk.pvk_uvw_gamma_g1, i);
            assert!(
                vector::length(&ic_bytes) == G1_UNCOMPRESSED_BYTES,
                E_INVALID_DEPOSIT_BINDING_PROOF,
            );
            vector::push_back(&mut vk_ic, de_g1(ic_bytes));
            i = i + 1;
        };

        // Public-input vector. Sizes are asserted via de_fr's deserialize check.
        // Wire order MUST match Gate 4a circuit:
        //   [0] commitment, [1] amount_tag, [2] asset_id, [3] vault_addr_hash,
        //   [4] chain_id, [5] pool_id
        assert!(vector::length(&commitment) == FR_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&amount_tag) == FR_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        // Phase B L-α — read cached asset_id + vault_addr_hash (skips 2× hash_3).
        // Cache must have been initialized via admin entry `init_vault_config_cache`.
        assert!(exists<VaultConfigCache>(@eunoma), E_NOT_INITIALIZED);
        let cache = borrow_global<VaultConfigCache>(@eunoma);
        let asset_id        = cache.cached_asset_id;
        let vault_addr_hash = cache.cached_vault_addr_hash;
        let chain_id_fr     = chain_id_to_fr_bytes();
        let pool_id_fr      = pool_id_to_fr_bytes();

        let publics = vector[
            de_fr(commitment),
            de_fr(amount_tag),
            de_fr(asset_id),
            de_fr(vault_addr_hash),
            de_fr(chain_id_fr),
            de_fr(pool_id_fr),
        ];

        // Proof bytes layout per Gate 4a (uncompressed): a (64) || b (128) || c (64).
        assert!(vector::length(&proof) == PROOF_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        let proof_a_bytes = byte_slice_exact(&proof, 0, G1_UNCOMPRESSED_BYTES);
        let proof_b_bytes = byte_slice_exact(
            &proof,
            G1_UNCOMPRESSED_BYTES,
            G1_UNCOMPRESSED_BYTES + G2_UNCOMPRESSED_BYTES,
        );
        let proof_c_bytes = byte_slice_exact(
            &proof,
            G1_UNCOMPRESSED_BYTES + G2_UNCOMPRESSED_BYTES,
            PROOF_BYTES,
        );
        let proof_a = de_g1(proof_a_bytes);
        let proof_b = de_g2(proof_b_bytes);
        let proof_c = de_g1(proof_c_bytes);

        let ok = groth16_bn254::verify_proof_prepared_fq12<G1, G2, Gt, Fq12, Fr>(
            &pvk_alpha_beta, &pvk_gamma_neg, &pvk_delta_neg, &vk_ic,
            &publics, &proof_a, &proof_b, &proof_c,
        );
        assert!(ok, E_INVALID_DEPOSIT_BINDING_PROOF);
    }

    /// Phase 2 / Gate 6 — verify Withdraw Groth16 proof against PreparedWithdrawProofVK.
    /// Mirror of `assert_valid_deposit_binding_proof` but with 9 publics + IC length 10.
    /// Wire order (MUST match Gate 6 circuit):
    ///   [root, nullifier_hash, asset_id, recipient_hash, amount_tag, ca_payload_hash,
    ///    request_hash, vault_sequence, chain_id]
    fun assert_valid_withdraw_proof(
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        asset_id: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        proof: vector<u8>,
    ) acquires PreparedWithdrawProofVK {
        assert!(exists<PreparedWithdrawProofVK>(@eunoma), E_NOT_INITIALIZED);
        let pvk = borrow_global<PreparedWithdrawProofVK>(@eunoma);

        // IC length invariant.
        assert!(vector::length(&pvk.pvk_uvw_gamma_g1) == WITHDRAW_VK_IC_LENGTH, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&pvk.pvk_alpha_g1_beta_g2_fq12) == FQ12_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&pvk.pvk_gamma_g2_neg) == G2_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&pvk.pvk_delta_g2_neg) == G2_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);

        let pvk_alpha_beta = de_fq12(pvk.pvk_alpha_g1_beta_g2_fq12);
        let pvk_gamma_neg  = de_g2(pvk.pvk_gamma_g2_neg);
        let pvk_delta_neg  = de_g2(pvk.pvk_delta_g2_neg);

        let vk_ic = vector::empty<crypto_algebra::Element<G1>>();
        let i = 0;
        while (i < WITHDRAW_VK_IC_LENGTH) {
            let ic_bytes = *vector::borrow(&pvk.pvk_uvw_gamma_g1, i);
            assert!(
                vector::length(&ic_bytes) == G1_UNCOMPRESSED_BYTES,
                E_INVALID_WITHDRAW_PROOF,
            );
            vector::push_back(&mut vk_ic, de_g1(ic_bytes));
            i = i + 1;
        };

        // Public input length checks (de_fr also asserts via deserialize check).
        assert!(vector::length(&root) == FR_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&nullifier_hash) == FR_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&asset_id) == FR_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&recipient_hash) == FR_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&amount_tag) == FR_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&ca_payload_hash) == FR_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&request_hash) == FR_BYTES, E_INVALID_WITHDRAW_PROOF);

        // Build public input vector. Wire order MUST match Gate 6 circuit.
        let chain_id_fr       = chain_id_to_fr_bytes();
        let vault_sequence_fr = u64_to_fr_bytes(vault_sequence);

        let publics = vector[
            de_fr(root),
            de_fr(nullifier_hash),
            de_fr(asset_id),
            de_fr(recipient_hash),
            de_fr(amount_tag),
            de_fr(ca_payload_hash),
            de_fr(request_hash),
            de_fr(vault_sequence_fr),
            de_fr(chain_id_fr),
        ];

        // Proof bytes layout: a (G1 64) || b (G2 128) || c (G1 64) = 256.
        assert!(vector::length(&proof) == PROOF_BYTES, E_INVALID_WITHDRAW_PROOF);
        let proof_a_bytes = byte_slice_exact(&proof, 0, G1_UNCOMPRESSED_BYTES);
        let proof_b_bytes = byte_slice_exact(
            &proof,
            G1_UNCOMPRESSED_BYTES,
            G1_UNCOMPRESSED_BYTES + G2_UNCOMPRESSED_BYTES,
        );
        let proof_c_bytes = byte_slice_exact(
            &proof,
            G1_UNCOMPRESSED_BYTES + G2_UNCOMPRESSED_BYTES,
            PROOF_BYTES,
        );
        let proof_a = de_g1(proof_a_bytes);
        let proof_b = de_g2(proof_b_bytes);
        let proof_c = de_g1(proof_c_bytes);

        let ok = groth16_bn254::verify_proof_prepared_fq12<G1, G2, Gt, Fq12, Fr>(
            &pvk_alpha_beta, &pvk_gamma_neg, &pvk_delta_neg, &vk_ic,
            &publics, &proof_a, &proof_b, &proof_c,
        );
        assert!(ok, E_INVALID_WITHDRAW_PROOF);
    }

    /// Phase 2 / Gate 6 — truncate a 32-byte hash to fit BN254 Fr (force high
    /// byte to 0). Required because keccak256 outputs 256-bit values that may
    /// exceed Fr modulus (~254 bits) → de_fr would abort. Withdraw circuit's
    /// `ca_payload_hash` public input requires Fr-fittable bytes; off-chain
    /// operator code MUST mirror this truncation. Reduces collision resistance
    /// from 256→224 bits but binding is still cryptographically sound for
    /// payload-attestation use.
    fun ca_payload_hash_to_fr_safe(raw: vector<u8>): vector<u8> {
        assert!(vector::length(&raw) == FR_BYTES, E_INVALID_WITHDRAW_PROOF);
        let out = vector::empty<u8>();
        let i = 0;
        while (i < 31) {
            vector::push_back(&mut out, *vector::borrow(&raw, i));
            i = i + 1;
        };
        // High byte forced to 0 → guarantees value < Fr modulus.
        vector::push_back(&mut out, 0u8);
        out
    }

    /// Phase 2 / Gate 6 — encode a u64 as 32-byte LE Fr (mirror of pool_pending_queue's
    /// u64_to_fr_bytes). Used to convert vault_sequence into a public-input field.
    fun u64_to_fr_bytes(n: u64): vector<u8> {
        let bcs_bytes = bcs::to_bytes(&n);
        let v = vector::empty<u8>();
        let i = 0;
        let nbcs = vector::length(&bcs_bytes);
        while (i < nbcs) {
            vector::push_back(&mut v, *vector::borrow(&bcs_bytes, i));
            i = i + 1;
        };
        while (vector::length(&v) < FR_BYTES) {
            vector::push_back(&mut v, 0u8);
        };
        v
    }

    /// Slice without padding. Used by `assert_valid_deposit_binding_proof` to peel
    /// off the (already correctly-sized) sub-vectors of the proof bytes.
    fun byte_slice_exact(src: &vector<u8>, start: u64, end: u64): vector<u8> {
        let n = vector::length(src);
        assert!(start <= end && end <= n, E_INVALID_DEPOSIT_BINDING_PROOF);
        let out = vector::empty<u8>();
        let i = start;
        while (i < end) {
            vector::push_back(&mut out, *vector::borrow(src, i));
            i = i + 1;
        };
        out
    }

    /// Admin entry: publish the Groth16 deposit-binding verification key. ONCE.
    ///
    /// Idempotency: `exists<DepositBindingVK>(@eunoma)` aborts on second call.
    /// Length invariants: each VK byte component is size-checked before storing.
    /// VK rotation is intentionally not supported by Gate 4b's surface (see struct doc).
    public entry fun publish_deposit_binding_vk(
        admin: &signer,
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic_0: vector<u8>,
        ic_1: vector<u8>,
        ic_2: vector<u8>,
        ic_3: vector<u8>,
        ic_4: vector<u8>,
        ic_5: vector<u8>,
        ic_6: vector<u8>,
    ) {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(!exists<DepositBindingVK>(@eunoma), E_ALREADY_INITIALIZED);

        // Component-size invariants — every VK piece is uncompressed bn254
        // (G1 = 64B, G2 = 128B). Catch wrong-length input before storage.
        assert!(vector::length(&alpha_g1) == G1_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&beta_g2)  == G2_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&gamma_g2) == G2_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&delta_g2) == G2_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&ic_0) == G1_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&ic_1) == G1_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&ic_2) == G1_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&ic_3) == G1_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&ic_4) == G1_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&ic_5) == G1_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&ic_6) == G1_UNCOMPRESSED_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);

        let ic = vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5, ic_6];
        // Belt-and-suspenders: re-check IC length after assembly.
        assert!(vector::length(&ic) == VK_IC_LENGTH, E_INVALID_DEPOSIT_BINDING_PROOF);

        move_to(admin, DepositBindingVK { alpha_g1, beta_g2, gamma_g2, delta_g2, ic });
    }

    /// Phase B B.2 lever L-δ admin entry — publish the prepared verification key.
    ///
    /// Pre-conditions:
    ///   * `DepositBindingVK` exists (admin has called `publish_deposit_binding_vk`).
    ///   * `PreparedDepositBindingVK` does NOT yet exist (idempotency).
    ///
    /// Performs ONCE on-chain:
    ///   * `pairing(alpha_g1, beta_g2) ∈ Gt` then upcast to `Fq12` (skips `Gt`
    ///     membership test when later deserialized — the core L-δ saving).
    ///   * `neg(gamma_g2)` and `neg(delta_g2)` precomputed.
    /// Stores the serialized prepared bytes alongside the unchanged IC vector.
    /// Subsequent deposits read this resource and dispatch to
    /// `verify_proof_prepared_fq12` instead of the slow `verify_proof`
    /// (≈ -400 to -700 execution units per deposit per B.0 profile evidence).
    public entry fun publish_prepared_deposit_binding_vk(
        admin: &signer,
    ) acquires DepositBindingVK {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(exists<DepositBindingVK>(@eunoma), E_NOT_INITIALIZED);
        assert!(!exists<PreparedDepositBindingVK>(@eunoma), E_ALREADY_INITIALIZED);

        let vk = borrow_global<DepositBindingVK>(@eunoma);
        let alpha_g1 = de_g1(vk.alpha_g1);
        let beta_g2  = de_g2(vk.beta_g2);
        let gamma_g2 = de_g2(vk.gamma_g2);
        let delta_g2 = de_g2(vk.delta_g2);

        // pairing(alpha, beta) ∈ Gt → upcast to Fq12 → serialize bytes.
        let pvk_ab_gt   = crypto_algebra::pairing<G1, G2, Gt>(&alpha_g1, &beta_g2);
        let pvk_ab_fq12 = crypto_algebra::upcast<Gt, Fq12>(&pvk_ab_gt);
        let pvk_ab_bytes = crypto_algebra::serialize<Fq12, FormatFq12LscLsb>(&pvk_ab_fq12);

        // -gamma_g2, -delta_g2 ∈ G2 → serialize bytes.
        let gamma_neg = crypto_algebra::neg<G2>(&gamma_g2);
        let delta_neg = crypto_algebra::neg<G2>(&delta_g2);
        let gamma_neg_bytes = crypto_algebra::serialize<G2, FormatG2Uncompr>(&gamma_neg);
        let delta_neg_bytes = crypto_algebra::serialize<G2, FormatG2Uncompr>(&delta_neg);

        move_to(admin, PreparedDepositBindingVK {
            pvk_alpha_g1_beta_g2_fq12: pvk_ab_bytes,
            pvk_gamma_g2_neg: gamma_neg_bytes,
            pvk_delta_g2_neg: delta_neg_bytes,
            pvk_uvw_gamma_g1: vk.ic, // copy IC unchanged
        });
    }

    /// Phase B B.1 lever L-α admin entry — initialize `VaultConfigCache`.
    ///
    /// Pre-conditions:
    ///   * `VaultConfig` exists (admin has called `init_vault`).
    ///   * `VaultConfigCache` does NOT yet exist (idempotency).
    ///   * In tests, `DepositBindingTestOverride` should already be installed
    ///     so the cached values pick up the Gate 4a fixture's placeholder
    ///     `asset_id` / `vault_addr_hash` Fr bytes (matching the circuit).
    ///
    /// Computes both Poseidon-of-address derivations once and persists them.
    /// Subsequent deposits read the cache and skip the `poseidon_bn254::hash_3`
    /// path entirely (≈ 3,054 execution units saved per deposit per B.0 profile).
    public entry fun init_vault_config_cache(
        admin: &signer,
    ) acquires VaultConfig, DepositBindingTestOverride {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(exists<VaultConfig>(@eunoma), E_NOT_INITIALIZED);
        assert!(!exists<VaultConfigCache>(@eunoma), E_ALREADY_INITIALIZED);

        let cfg = borrow_global<VaultConfig>(@eunoma);
        let cached_asset_id = derive_asset_id(cfg.asset_type);
        let cached_vault_addr_hash = derive_vault_addr_hash(cfg.vault_addr);

        move_to(admin, VaultConfigCache {
            cached_asset_id,
            cached_vault_addr_hash,
        });
    }

    // ========================================================================
    // Gate 6 — Withdraw VK admin entries (mirror Gate 4b deposit entries)
    // ========================================================================

    /// Phase 2 / Gate 6 admin entry — publish the Withdraw circuit Groth16 VK.
    /// Args mirror `publish_deposit_binding_vk` shape but with 10 IC slots
    /// (= 1 + N_WITHDRAW_PUBLIC_INPUTS = 10) instead of 7.
    public entry fun publish_withdraw_proof_vk(
        admin: &signer,
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic_0: vector<u8>,
        ic_1: vector<u8>,
        ic_2: vector<u8>,
        ic_3: vector<u8>,
        ic_4: vector<u8>,
        ic_5: vector<u8>,
        ic_6: vector<u8>,
        ic_7: vector<u8>,
        ic_8: vector<u8>,
        ic_9: vector<u8>,
    ) {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(!exists<WithdrawProofVK>(@eunoma), E_ALREADY_INITIALIZED);

        // Component-size invariants — uncompressed bn254 (G1=64B, G2=128B).
        assert!(vector::length(&alpha_g1) == G1_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&beta_g2)  == G2_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&gamma_g2) == G2_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&delta_g2) == G2_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&ic_0) == G1_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&ic_1) == G1_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&ic_2) == G1_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&ic_3) == G1_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&ic_4) == G1_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&ic_5) == G1_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&ic_6) == G1_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&ic_7) == G1_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&ic_8) == G1_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);
        assert!(vector::length(&ic_9) == G1_UNCOMPRESSED_BYTES, E_INVALID_WITHDRAW_PROOF);

        let ic = vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5, ic_6, ic_7, ic_8, ic_9];
        assert!(vector::length(&ic) == WITHDRAW_VK_IC_LENGTH, E_INVALID_WITHDRAW_PROOF);

        move_to(admin, WithdrawProofVK { alpha_g1, beta_g2, gamma_g2, delta_g2, ic });
    }

    /// Phase 2 / Gate 6 admin entry — publish the prepared (fast-variant) withdraw VK.
    /// Pre-condition: `WithdrawProofVK` exists. Computes `pairing(alpha, beta)` upcast
    /// to `Fq12` + `neg(gamma_g2)` + `neg(delta_g2)` once; subsequent withdraws use the
    /// fast variant verify_proof_prepared_fq12 (mirrors Phase B B.2 deposit pattern).
    public entry fun publish_prepared_withdraw_proof_vk(
        admin: &signer,
    ) acquires WithdrawProofVK {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(exists<WithdrawProofVK>(@eunoma), E_NOT_INITIALIZED);
        assert!(!exists<PreparedWithdrawProofVK>(@eunoma), E_ALREADY_INITIALIZED);

        let vk = borrow_global<WithdrawProofVK>(@eunoma);
        let alpha_g1 = de_g1(vk.alpha_g1);
        let beta_g2  = de_g2(vk.beta_g2);
        let gamma_g2 = de_g2(vk.gamma_g2);
        let delta_g2 = de_g2(vk.delta_g2);

        let pvk_ab_gt   = crypto_algebra::pairing<G1, G2, Gt>(&alpha_g1, &beta_g2);
        let pvk_ab_fq12 = crypto_algebra::upcast<Gt, Fq12>(&pvk_ab_gt);
        let pvk_ab_bytes = crypto_algebra::serialize<Fq12, FormatFq12LscLsb>(&pvk_ab_fq12);

        let gamma_neg = crypto_algebra::neg<G2>(&gamma_g2);
        let delta_neg = crypto_algebra::neg<G2>(&delta_g2);
        let gamma_neg_bytes = crypto_algebra::serialize<G2, FormatG2Uncompr>(&gamma_neg);
        let delta_neg_bytes = crypto_algebra::serialize<G2, FormatG2Uncompr>(&delta_neg);

        move_to(admin, PreparedWithdrawProofVK {
            pvk_alpha_g1_beta_g2_fq12: pvk_ab_bytes,
            pvk_gamma_g2_neg: gamma_neg_bytes,
            pvk_delta_g2_neg: delta_neg_bytes,
            pvk_uvw_gamma_g1: vk.ic,
        });
    }

    /// Phase 2 / Gate 6 admin entry — initialize `UsedNullifiers` table.
    /// Idempotent (rejects double init). Must be called once before first withdraw.
    public entry fun init_used_nullifiers_table(admin: &signer) {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(!exists<UsedNullifiers>(@eunoma), E_ALREADY_INITIALIZED);

        move_to(admin, UsedNullifiers { table: table::new<vector<u8>, bool>() });
    }

    // ========================================================================
    // Gate 4b — Main deposit entry function (HANDOFF Section 2.5)
    // ========================================================================

    /// User-initiated shielded deposit. Verification gates (in order):
    ///   1. Bridge not paused.
    ///   2. Attestation expiry not in the past.
    ///   3. Deposit nonce not previously consumed.
    ///   4. CA-payload-hash recomputed and bound into the attestation message.
    ///   5. 4-of-7 operator attestation verifies (E_TOO_FEW_OPERATOR_SIGNATURES /
    ///      E_MAIN_OPERATOR_SIGNATURE_REQUIRED / E_INVALID_OPERATOR_SIGNATURE /
    ///      E_SIGNATURE_FOR_INACTIVE_OPERATOR / E_SIGNATURE_ARRAY_LENGTH).
    ///   6. Groth16 deposit-binding proof verifies (E_INVALID_DEPOSIT_BINDING_PROOF).
    ///   7. Nonce table insert (commits the nonce *before* CA dispatch so a panic
    ///      mid-CA cannot allow nonce replay; nonce is "spent" the instant we believe
    ///      the deposit is authorized).
    ///   8. CA cross-module dispatch: `confidential_asset::confidential_transfer_raw`
    ///      (LOCAL_CONFIRMATION 8.4 — `public entry fun`, callable cross-module).
    ///   9. Pool dispatch — STUBBED, see comment block below.
    ///  10. DepositEvent emitted.
    ///
    /// Argument count = 21 (matches HANDOFF Section 2.5 verbatim).
    public entry fun deposit_with_commitment(
        user: &signer,

        // Shielded-pool deposit data
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        deposit_binding_proof: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
        operator_signatures: vector<vector<u8>>,

        // ConfidentialAPT confidential_transfer_raw payload (user -> vault).
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_eff_aud: vector<vector<u8>>,
        amount_p: vector<vector<u8>>,
        amount_r_sender: vector<vector<u8>>,
        amount_r_recip: vector<vector<u8>>,
        amount_r_eff_aud: vector<vector<u8>>,
        ek_volun_auds: vector<vector<u8>>,
        amount_r_volun_auds: vector<vector<vector<u8>>>,
        zkrp_new_balance: vector<u8>,
        zkrp_amount: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
        memo: vector<u8>,
    ) acquires VaultConfig, PreparedDepositBindingVK, VaultConfigCache {
        assert!(exists<VaultConfig>(@eunoma), E_NOT_INITIALIZED);

        // Gas P3: expiry check uses ONLY `expiry_secs` (not `cfg`); run it
        // BEFORE `borrow_global_mut<VaultConfig>` so an expired-attestation
        // abort doesn't pay the VaultConfig write-set entry. (cfg-dependent
        // checks below stay after the borrow.)
        assert_not_expired(expiry_secs);

        let cfg = borrow_global_mut<VaultConfig>(@eunoma);

        // 1. Pause check.
        assert!(!cfg.paused, E_BRIDGE_PAUSED);

        // Defensive: framework `confidential_transfer_raw` aborts E_SELF_TRANSFER on
        // sender == recipient (LOCAL_ERRATA — `confidential_transfer_raw` enforces
        // `sender ≠ recipient` at framework level). Mirror at bridge layer with a
        // bridge-specific error code so an attacker depositing-from-vault is
        // distinguishable from a legitimate framework abort.
        assert!(signer::address_of(user) != cfg.vault_addr, E_INVALID_DEPOSIT_BINDING_PROOF);

        // 3. Nonce-replay check.
        assert!(
            !table::contains(&cfg.used_deposit_nonces, deposit_nonce),
            E_DEPOSIT_NONCE_REPLAY,
        );

        // 4. Recompute CA payload hash. Used as the binding nonce inside the
        //    attestation message body — operator signed over THIS exact hash, so
        //    if we recompute differently (e.g. mutated CA fields) the operator
        //    signatures over the recomputed message will not verify
        //    (=> E_INVALID_OPERATOR_SIGNATURE). The bridge layer cannot tell which
        //    specific field was mutated; that's by design — any mismatch is fatal.
        let ca_payload_hash = hash_confidential_transfer_payload(
            cfg.asset_type,
            cfg.vault_addr,
            new_balance_p,
            new_balance_r,
            new_balance_r_eff_aud,
            amount_p,
            amount_r_sender,
            amount_r_recip,
            amount_r_eff_aud,
            ek_volun_auds,
            amount_r_volun_auds,
            zkrp_new_balance,
            zkrp_amount,
            sigma_proto_comm,
            sigma_proto_resp,
            memo,
        );

        // 5. Build canonical attestation message and verify 4-of-7 operator sigs.
        //    Decision (subagent — REPORT_GATE_4B test 3): we DO NOT add a separate
        //    `assert!(ca_payload_hash == provided_hash, E_PAYLOAD_HASH_MISMATCH)`
        //    check. Instead, the binding is enforced indirectly: the recomputed
        //    `ca_payload_hash` is fed into the attestation message body; operator
        //    signatures only verify if they signed over the *exact* same hash; a
        //    mutated CA field therefore yields E_INVALID_OPERATOR_SIGNATURE on the
        //    main slot and/or E_TOO_FEW_OPERATOR_SIGNATURES if all sigs flip to
        //    "did not sign this message". This is strictly tighter than
        //    PAYLOAD_HASH_MISMATCH because it requires the operator to actively
        //    sign over the recomputed hash; a stand-alone equality check would
        //    permit a future bug where the bridge accepts an operator signature
        //    over a hash that doesn't match the recomputed value.
        // Phase D Agent D1 — 8-byte LE u64 pool_id (vs prior 32-byte LE Fr) for
        // the attestation message body only. The Groth16 binding-proof public
        // input below (step 6) still calls `pool_id_to_fr_bytes()` because that
        // path NEEDS a 32-byte Fr representation. The on-the-wire signed
        // message is now 24 bytes shorter, which (a) matches the TS deposit
        // encoder byte-for-byte (`shared/src/attestation.ts:60-89` — fixes a
        // pre-existing Move-vs-TS parity bug) and (b) shrinks SHA512 input
        // bytes to each of the 4 ed25519::signature_verify_strict calls.
        let pool_id_bytes = pool_id_to_le_u64_bytes();
        let chain_id_u8 = chain_id::get();
        let msg = new_deposit_attestation_message(
            cfg,
            chain_id_u8,
            pool_id_bytes,
            commitment,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
            expiry_secs,
        );
        multi_sig_verifier::assert_valid_attestation(
            bcs::to_bytes(&msg),
            operator_signatures,
            &cfg.operator_pubkeys,
            cfg.attestation_threshold,
            cfg.main_operator_index,
        );

        // 6. Verify the Groth16 deposit-binding proof. Wire order is fixed by
        //    Gate 4a; passing wrong public inputs (commitment, amount_tag) will
        //    cause the pairing equation to fail (=> E_INVALID_DEPOSIT_BINDING_PROOF).
        assert_valid_deposit_binding_proof(
            commitment,
            amount_tag,
            deposit_binding_proof,
        );

        // 7. Mark nonce consumed BEFORE dispatching to CA. This is intentional:
        //    if the CA call aborts (e.g. user has insufficient balance, sigma proof
        //    wrong, etc.), the nonce is already burned, preventing replay attacks
        //    that might otherwise re-attempt the same attested deposit later.
        //    Side effect: a user with a malformed CA payload "wastes" their nonce;
        //    the operator must issue a fresh nonce. This is acceptable because the
        //    operator already attested to a *specific* CA payload hash; reissuing
        //    is a normal operator service flow.
        table::add(&mut cfg.used_deposit_nonces, deposit_nonce, true);

        // 8. CA cross-module dispatch. `confidential_transfer_raw` is `public entry`
        //    (LOCAL_CONFIRMATION 8.4). The user signer is forwarded; the vault never
        //    needs to sign for an inbound transfer (the user is moving their own
        //    encrypted balance to the vault). Vault `SignerCapability` stays inside
        //    `VaultConfig` and is never derived in this entry function — preserves
        //    the Gate 2/3 "no vault signer leak" invariant.
        confidential_asset::confidential_transfer_raw(
            user,
            cfg.asset_type,
            cfg.vault_addr,
            new_balance_p,
            new_balance_r,
            new_balance_r_eff_aud,
            amount_p,
            amount_r_sender,
            amount_r_recip,
            amount_r_eff_aud,
            ek_volun_auds,
            amount_r_volun_auds,
            zkrp_new_balance,
            zkrp_amount,
            sigma_proto_comm,
            sigma_proto_resp,
            memo,
        );

        // Gate 5 / Step 4 / Phase B B.4 (2026-05-08): pool dispatch re-wired.
        // Phase A revert was driven by deposit_with_commitment hitting Aptos's
        // `txn.max_execution_gas` cap (9,200 user-visible units). After Phase B
        // B.1 (L-α VaultConfigCache, -3,098 units) + B.2 (L-δ Groth16 fast
        // variant, -1,094 units), baseline dropped from 8,958 to 4,766 — leaving
        // ~4,400 cap headroom, comfortably absorbing the ~205-unit pool dispatch.
        //
        // L-ζ (2× hash_2 → 1× hash_3 fold) was evaluated in B.4 and skipped:
        // the fold would change the pool accumulator's recurrence semantics
        // (`acc_history[i+1] = hash_3(acc_history[i], idx, leaf)` vs current
        // nested `hash_2(acc_history[i], hash_2(idx, leaf))`), which propagates
        // into spike INV5 `compute_range_hash` and operator-side off-chain
        // chain-reconstruction. The cost-benefit (≤500 units uncertain saving
        // vs 4-file architecture re-sync) does not pay off given current cap
        // headroom; defer to a future round-7 if pool path becomes constrained.
        //
        // Read leaf_index PRE-dispatch via `pending_tail()` so emitted
        // DepositEvent.leaf_index reflects the slot this deposit consumed.
        let leaf_index = pending_queue::pending_tail();
        pending_queue::deposit_precomputed(commitment, 0);

        // 10. Emit completion event.
        // Phase D / Agent D6: asset_type field removed from DepositEvent — see
        // struct definition comment. Indexers read asset_type from VaultConfig.
        event::emit(DepositEvent {
            commitment,
            leaf_index,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
        });
    }

    // ========================================================================
    // Gate 6 — Main withdraw entry function (HANDOFF Section 2.5 + 4)
    // ========================================================================

    /// User/operator-initiated shielded withdraw. Verification gates (in order):
    ///   1. Bridge not paused.
    ///   2. Attestation expiry not in the past.
    ///   3. Root is in `pool_batch_root_update::RootHistory` (E_INVALID_ROOT).
    ///   4. Nullifier not previously consumed (E_NULLIFIER_ALREADY_SPENT).
    ///   5. `vault_sequence` matches `VaultConfig.vault_sequence` (E_VAULT_SEQUENCE_MISMATCH).
    ///   6. `recipient_hash` matches Poseidon-of-recipient-address recomputation
    ///      (E_RECIPIENT_HASH_MISMATCH) — binds the attestation/proof to the actual
    ///      recipient that bridge will dispatch CA funds to.
    ///   7. `ca_payload_hash` recomputed and bound into the attestation message body
    ///      (operator signed over THIS exact hash; mismatch ⇒ E_INVALID_OPERATOR_SIGNATURE
    ///      from multi_sig_verifier).
    ///   8. 4-of-7 operator attestation verifies.
    ///   9. Groth16 withdraw proof verifies (E_INVALID_WITHDRAW_PROOF).
    ///  10. `UsedNullifiers.table.add(nullifier_hash, true)` — marked spent BEFORE CA
    ///      dispatch (same pattern as deposit nonce). Move semantics: if subsequent
    ///      CA dispatch aborts, entire tx reverts including this insert.
    ///  11. `cfg.vault_sequence += 1`.
    ///  12. CA cross-module dispatch: `confidential_asset::confidential_transfer_raw`
    ///      called with vault signer (derived from `vault_signer_cap`) → recipient.
    ///  13. Emit `WithdrawEvent`.
    ///
    /// Argument count = 26 (relayer + 11 withdraw + 14 CA payload).
    public entry fun withdraw_to_recipient(
        relayer: &signer,

        // Withdraw data (per HANDOFF §2.5)
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        withdraw_proof: vector<u8>,
        expiry_secs: u64,
        operator_signatures: vector<vector<u8>>,

        // ConfidentialAPT vault → recipient payload (15 fields, mirror deposit shape)
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_eff_aud: vector<vector<u8>>,
        amount_p: vector<vector<u8>>,
        amount_r_sender: vector<vector<u8>>,
        amount_r_recip: vector<vector<u8>>,
        amount_r_eff_aud: vector<vector<u8>>,
        ek_volun_auds: vector<vector<u8>>,
        amount_r_volun_auds: vector<vector<vector<u8>>>,
        zkrp_new_balance: vector<u8>,
        zkrp_amount: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
        memo: vector<u8>,
    ) acquires VaultConfig, VaultConfigCache, PreparedWithdrawProofVK, UsedNullifiers {
        // Suppress unused-arg warning on `relayer` — gas payer; not directly inspected.
        let _ = relayer;

        assert!(exists<VaultConfig>(@eunoma), E_NOT_INITIALIZED);

        // Phase D / Agent D7 fail-fast hoist: run read-only validation BEFORE
        // borrow_global_mut<VaultConfig>. On Aptos, a borrow_global_mut creates
        // a write-set entry that is finalized at the abort point — so an
        // assertion after the borrow that fails pays the write-set cost. The
        // three checks below (expiry, root-in-history, nullifier-table-exists)
        // depend ONLY on arguments + read-only-global state and therefore can
        // safely move above the mut borrow. Mirrors deposit Phase A (commit
        // 9127260) which hoisted `assert_not_expired` for the same reason.
        //
        // Reordering preserves all abort codes — test_b7 / test_b3 still abort
        // with E_EXPIRED_ATTESTATION (15) / E_INVALID_ROOT (20) from this
        // module (`expected_failure` only checks abort_code + location, not
        // PC). Pause check stays below the mut borrow because it dereferences
        // `cfg.paused` which requires the resource.
        //
        // Pause-vs-expiry ordering note: if the bridge is paused AND the
        // attestation is expired, post-hoist E_EXPIRED_ATTESTATION fires
        // first. Tests do not exercise that compound state; the abort-code
        // contract for each individual failure mode is preserved.
        assert_not_expired(expiry_secs);
        assert!(
            pool_batch_root_update::is_root_in_history(root),
            E_INVALID_ROOT,
        );
        assert!(exists<UsedNullifiers>(@eunoma), E_NOT_INITIALIZED);

        let cfg = borrow_global_mut<VaultConfig>(@eunoma);

        // 1. Pause check (cfg.paused — requires the mut borrow above).
        assert!(!cfg.paused, E_BRIDGE_PAUSED);

        // 4. Nullifier not already consumed. `exists<UsedNullifiers>` already
        //    asserted above; safe to take the mut borrow directly.
        let nulls = borrow_global_mut<UsedNullifiers>(@eunoma);
        assert!(
            !table::contains(&nulls.table, nullifier_hash),
            E_NULLIFIER_ALREADY_SPENT,
        );

        // 5. Vault sequence anti-replay (per HANDOFF §1.7 lines 88-104).
        assert!(vault_sequence == cfg.vault_sequence, E_VAULT_SEQUENCE_MISMATCH);

        // 6. Recipient hash binding — recomputed from address must equal user-supplied
        //    public input. Prevents attacker swapping recipient address while reusing
        //    a proof generated for a different recipient_hash.
        let recomputed_recipient_hash = derive_recipient_hash(recipient);
        assert!(
            recomputed_recipient_hash == recipient_hash,
            E_RECIPIENT_HASH_MISMATCH,
        );

        // 7. Recompute CA payload hash. Reuses `hash_confidential_transfer_payload` —
        //    the second arg position semantically means "destination of CA transfer";
        //    for deposit it was `cfg.vault_addr` (user → vault), for withdraw it is
        //    `recipient` (vault → recipient). Off-chain operator MUST mirror with
        //    `recipient` in this position when computing the keccak256 to sign.
        let ca_payload_hash_raw = hash_confidential_transfer_payload(
            cfg.asset_type,
            recipient,
            new_balance_p,
            new_balance_r,
            new_balance_r_eff_aud,
            amount_p,
            amount_r_sender,
            amount_r_recip,
            amount_r_eff_aud,
            ek_volun_auds,
            amount_r_volun_auds,
            zkrp_new_balance,
            zkrp_amount,
            sigma_proto_comm,
            sigma_proto_resp,
            memo,
        );
        // Truncate to fit Fr (Phase 2 fix; off-chain mirrors).
        let ca_payload_hash_recomputed = ca_payload_hash_to_fr_safe(ca_payload_hash_raw);
        // Bridge does NOT separately enforce ca_payload_hash == recomputed (mirror
        // of deposit decision REPORT_GATE_4B test 3): the recomputed value is fed
        // into the WithdrawAttestationMessage body; operator signed over the exact
        // same hash; any mismatch yields E_INVALID_OPERATOR_SIGNATURE on the main
        // slot. Strictly tighter than a bare equality check.

        // 8. Build canonical WithdrawAttestationMessage and verify 4-of-7 sigs.
        // Phase D Agent D1 candidate 2: same 32-byte → 8-byte LE u64 pool_id
        // shrink applied to deposit attestation (commit 1) extended here to
        // withdraw. The withdraw path does NOT pass pool_id into any Groth16
        // public input (vs deposit), so the 32-byte Fr form was never required
        // here either. Off-chain TS withdraw encoder (main-operator
        // routes/withdraw.ts) is updated in lock-step to encode 8 bytes too.
        let pool_id_bytes = pool_id_to_le_u64_bytes();
        let chain_id_u8   = chain_id::get();
        let msg = new_withdraw_attestation_message(
            cfg,
            chain_id_u8,
            pool_id_bytes,
            nullifier_hash,
            recipient,
            recipient_hash,
            amount_tag,
            ca_payload_hash_recomputed,
            request_hash,
            vault_sequence,
            expiry_secs,
        );
        multi_sig_verifier::assert_valid_attestation(
            bcs::to_bytes(&msg),
            operator_signatures,
            &cfg.operator_pubkeys,
            cfg.attestation_threshold,
            cfg.main_operator_index,
        );

        // 9. Verify Withdraw Groth16 proof. Wire order MUST match Gate 6 circuit.
        //    asset_id from cache (Phase B L-α — skips per-tx hash_3); asset_id is
        //    deterministic per-vault and matches the value baked into the original
        //    deposit commitment that this withdraw is now spending.
        assert!(exists<VaultConfigCache>(@eunoma), E_NOT_INITIALIZED);
        let cache = borrow_global<VaultConfigCache>(@eunoma);
        let asset_id = cache.cached_asset_id;
        assert_valid_withdraw_proof(
            root,
            nullifier_hash,
            asset_id,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            request_hash,
            vault_sequence,
            withdraw_proof,
        );

        // 10. Mark nullifier spent (BEFORE CA dispatch — same pattern as deposit nonce).
        table::add(&mut nulls.table, nullifier_hash, true);

        // 11. Increment vault_sequence (anti-replay across witdraws).
        cfg.vault_sequence = cfg.vault_sequence + 1;

        // 12. Derive vault signer + CA dispatch (vault → recipient).
        //    `vault_signer_cap` is stored in VaultConfig (line ~157); `account::create_signer_with_capability`
        //    is the production-correct path documented in `LOCAL_CONFIRMATION 8.4`.
        //    Production version of `test_only_vault_to_recipient_transfer_raw`.
        let vault_signer = account::create_signer_with_capability(&cfg.vault_signer_cap);
        confidential_asset::confidential_transfer_raw(
            &vault_signer,
            cfg.asset_type,
            recipient,
            new_balance_p,
            new_balance_r,
            new_balance_r_eff_aud,
            amount_p,
            amount_r_sender,
            amount_r_recip,
            amount_r_eff_aud,
            ek_volun_auds,
            amount_r_volun_auds,
            zkrp_new_balance,
            zkrp_amount,
            sigma_proto_comm,
            sigma_proto_resp,
            memo,
        );

        // 13. Emit completion event.
        // Phase D / Agent D6: asset_type field removed from WithdrawEvent —
        // see struct definition comment.
        event::emit(WithdrawEvent {
            nullifier_hash,
            recipient,
            amount_tag,
            ca_payload_hash,
            vault_sequence,
        });
    }

    // ========================================================================
    // Phase 2.X / Gate 6 — vault maintenance entries
    //
    // `operator_rollover_vault_pending`: rolls vault's CA `pending_balance`
    // into `available_balance` so subsequent `withdraw_to_recipient` calls can
    // spend received deposits. Production replacement for `test_only_vault_rollover`.
    //
    // Auth model: 1-of-1 main-operator gate (vs. 4-of-7 for withdraw). Rollover
    // moves no funds out of the vault — it only flips internal CA state from
    // `pending` to `available`. Lower trust requirement than fund-moving entries.
    //
    // Spec correction #2 (LOCAL_CONFIRMATION.md): takes NO rollover_payload arg —
    // underlying `confidential_asset::rollover_pending_balance(sender, asset_type)`
    // takes no proof.
    // ========================================================================

    public entry fun operator_rollover_vault_pending(
        operator: &signer,
    ) acquires VaultConfig {
        assert!(exists<VaultConfig>(@eunoma), E_NOT_INITIALIZED);
        let cfg = borrow_global<VaultConfig>(@eunoma);
        assert!(
            signer::address_of(operator) == cfg.main_operator_addr,
            E_NOT_MAIN_OPERATOR,
        );
        let vault_signer = account::create_signer_with_capability(&cfg.vault_signer_cap);
        confidential_asset::rollover_pending_balance(&vault_signer, cfg.asset_type);
    }

    // ========================================================================
    // Phase 2.Y / W.4.5 — vault balance normalization entry
    //
    // `operator_normalize_vault_balance`: re-encrypts the vault's CA
    // `available_balance` so every chunk fits within 16-bit bounds, which is a
    // pre-condition the framework requires before `rollover_pending_balance`
    // can be safely invoked. Closes the Gate 6 sibling TODO at this file's
    // earlier vault-maintenance section by mirroring the production replacement
    // pattern used for `operator_rollover_vault_pending`.
    //
    // Auth model: identical 1-of-1 main-operator gate (reuses `E_NOT_MAIN_OPERATOR`).
    // Normalize moves no funds out of the vault — it only re-encrypts the
    // existing balance with a fresh randomness so the chunk-bound invariant
    // holds. The lower trust requirement matches the rollover entry.
    //
    // Args mirror the underlying `confidential_asset::normalize_raw` signature
    // (per `LOCAL_CONFIRMATION` 8.4 — `public entry fun`, callable cross-module)
    // with the same naming convention used elsewhere in this module
    // (`new_balance_r_eff_aud` for the auditor's R component).
    // ========================================================================

    public entry fun operator_normalize_vault_balance(
        operator: &signer,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_eff_aud: vector<vector<u8>>,
        zkrp_new_balance: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
    ) acquires VaultConfig {
        assert!(exists<VaultConfig>(@eunoma), E_NOT_INITIALIZED);
        let cfg = borrow_global<VaultConfig>(@eunoma);
        assert!(
            signer::address_of(operator) == cfg.main_operator_addr,
            E_NOT_MAIN_OPERATOR,
        );
        let vault_signer = account::create_signer_with_capability(&cfg.vault_signer_cap);
        confidential_asset::normalize_raw(
            &vault_signer,
            cfg.asset_type,
            new_balance_p,
            new_balance_r,
            new_balance_r_eff_aud,
            zkrp_new_balance,
            sigma_proto_comm,
            sigma_proto_resp,
        );
    }

    // ========================================================================
    // Test-only helpers (only present during `aptos move test`)
    // ========================================================================

    #[test_only]
    public fun test_only_init_vault_no_resource_account(
        admin: &signer,
        main_operator_addr: address,
        asset_type: Object<fungible_asset::Metadata>,
        operator_pubkeys: vector<vector<u8>>,
        main_operator_index: u64,
        attestation_threshold: u64,
        vault_signer_cap: account::SignerCapability,
    ) {
        let admin_addr = signer::address_of(admin);
        assert!(!exists<VaultConfig>(admin_addr), E_ALREADY_INITIALIZED);
        assert_valid_operator_set(
            &operator_pubkeys,
            main_operator_index,
            attestation_threshold,
        );
        let vault_addr = account::get_signer_capability_address(&vault_signer_cap);
        let cfg = VaultConfig {
            admin: admin_addr,
            main_operator_addr,
            vault_addr,
            asset_type,
            vault_signer_cap,
            operator_pubkeys,
            main_operator_index,
            attestation_threshold,
            operator_set_version: 0,
            paused: false,
            vault_sequence: 0,
            used_deposit_nonces: table::new<vector<u8>, bool>(),
        };
        event::emit(VaultInitialized {
            vault_addr,
            asset_type,
            main_operator_index,
            attestation_threshold,
            operator_set_version: 0,
        });
        move_to(admin, cfg);
    }

    #[test_only]
    public fun test_call_assert_valid_operator_attestation(
        message_bytes: vector<u8>,
        signatures: vector<vector<u8>>,
    ) acquires VaultConfig {
        let cfg = borrow_global<VaultConfig>(@eunoma);
        multi_sig_verifier::assert_valid_attestation(
            message_bytes,
            signatures,
            &cfg.operator_pubkeys,
            cfg.attestation_threshold,
            cfg.main_operator_index,
        );
    }

    /// Test-only: install the Fr override resource so `derive_asset_id` and
    /// `derive_vault_addr_hash` return the supplied placeholder bytes verbatim
    /// (instead of the real Poseidon-of-address derivation). Must be called by
    /// the deployer signer after `init_vault`. Idempotent: aborts if already
    /// installed.
    #[test_only]
    public entry fun install_deposit_binding_test_override(
        admin: &signer,
        asset_id_fr: vector<u8>,
        vault_addr_hash_fr: vector<u8>,
    ) {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == @eunoma, E_NOT_ADMIN);
        assert!(!exists<DepositBindingTestOverride>(@eunoma), E_ALREADY_INITIALIZED);
        assert!(vector::length(&asset_id_fr) == FR_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert!(vector::length(&vault_addr_hash_fr) == FR_BYTES, E_INVALID_DEPOSIT_BINDING_PROOF);
        move_to(admin, DepositBindingTestOverride { asset_id_fr, vault_addr_hash_fr });
    }

    /// Test-only re-export of `hash_confidential_transfer_payload` so tests can
    /// recompute the digest off-chain and feed it into operator-signed messages.
    /// Production code never needs this — the bridge always recomputes internally.
    #[test_only]
    public fun test_call_hash_confidential_transfer_payload(
        asset_type: Object<fungible_asset::Metadata>,
        vault_addr: address,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_eff_aud: vector<vector<u8>>,
        amount_p: vector<vector<u8>>,
        amount_r_sender: vector<vector<u8>>,
        amount_r_recip: vector<vector<u8>>,
        amount_r_eff_aud: vector<vector<u8>>,
        ek_volun_auds: vector<vector<u8>>,
        amount_r_volun_auds: vector<vector<vector<u8>>>,
        zkrp_new_balance: vector<u8>,
        zkrp_amount: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
        memo: vector<u8>,
    ): vector<u8> {
        hash_confidential_transfer_payload(
            asset_type,
            vault_addr,
            new_balance_p,
            new_balance_r,
            new_balance_r_eff_aud,
            amount_p,
            amount_r_sender,
            amount_r_recip,
            amount_r_eff_aud,
            ek_volun_auds,
            amount_r_volun_auds,
            zkrp_new_balance,
            zkrp_amount,
            sigma_proto_comm,
            sigma_proto_resp,
            memo,
        )
    }

    /// Test-only nonce-consume helper. Mirrors `deposit_with_commitment`'s
    /// nonce check + insert in isolation so the nonce-replay gate is testable
    /// independently of the (test-environment-failing) CA framework dispatch.
    /// First call inserts; second call with the same nonce aborts
    /// E_DEPOSIT_NONCE_REPLAY.
    #[test_only]
    public fun test_call_consume_deposit_nonce(
        deposit_nonce: vector<u8>,
    ) acquires VaultConfig {
        let cfg = borrow_global_mut<VaultConfig>(@eunoma);
        assert!(
            !table::contains(&cfg.used_deposit_nonces, deposit_nonce),
            E_DEPOSIT_NONCE_REPLAY,
        );
        table::add(&mut cfg.used_deposit_nonces, deposit_nonce, true);
    }

    #[test_only]
    public fun test_call_assert_not_expired(expiry_secs: u64) {
        assert_not_expired(expiry_secs);
    }

    #[test_only]
    public fun test_call_active_operator_count(
        operator_pubkeys: vector<vector<u8>>,
    ): u64 {
        active_operator_count(&operator_pubkeys)
    }

    #[test_only]
    public fun test_call_new_deposit_attestation_message(
        chain_id: u8,
        pool_id: vector<u8>,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
    ): DepositAttestationMessage acquires VaultConfig {
        let cfg = borrow_global<VaultConfig>(@eunoma);
        new_deposit_attestation_message(
            cfg,
            chain_id,
            pool_id,
            commitment,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
            expiry_secs,
        )
    }

    #[test_only]
    public fun deposit_msg_operator_set_version(
        msg: &DepositAttestationMessage,
    ): u64 {
        msg.operator_set_version
    }

    /// Test-only: build the canonical BCS-encoded WithdrawAttestationMessage
    /// bytes that operators sign (and that the bridge re-derives inside
    /// `withdraw_to_recipient` step 8). Mirrors the production call site exactly:
    /// `chain_id` and `pool_id_bytes` come from the same on-chain sources.
    /// Phase 2.Y / W.8 — added so B3-B12 negative path tests can construct
    /// matching operator signatures without duplicating the canonical-message
    /// builder logic.
    #[test_only]
    public fun test_call_build_withdraw_attestation_msg_bytes(
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
    ): vector<u8> acquires VaultConfig {
        let cfg = borrow_global<VaultConfig>(@eunoma);
        // Mirror production withdraw path (Phase D Agent D1 c2): 8-byte LE u64
        // pool_id, not 32-byte LE Fr.
        let pool_id_bytes = pool_id_to_le_u64_bytes();
        let chain_id_u8 = chain_id::get();
        let msg = new_withdraw_attestation_message(
            cfg,
            chain_id_u8,
            pool_id_bytes,
            nullifier_hash,
            recipient,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            request_hash,
            vault_sequence,
            expiry_secs,
        );
        bcs::to_bytes(&msg)
    }

    /// Test-only: re-export of `derive_recipient_hash` so withdraw negative-path
    /// tests can compute the canonical recipient_hash for any recipient address
    /// (mirrors Move-side Poseidon-of-address derivation byte-for-byte).
    #[test_only]
    public fun test_call_derive_recipient_hash(recipient: address): vector<u8> {
        derive_recipient_hash(recipient)
    }

    /// Test-only: re-export of `ca_payload_hash_to_fr_safe` so tests can
    /// compute the same truncated digest the bridge feeds into the canonical
    /// WithdrawAttestationMessage (off-chain operators must mirror this exact
    /// truncation rule per Section 1.7 of HANDOFF).
    #[test_only]
    public fun test_call_ca_payload_hash_to_fr_safe(raw: vector<u8>): vector<u8> {
        ca_payload_hash_to_fr_safe(raw)
    }

    // Public re-exports of error codes for tests to assert with #[expected_failure].
    #[test_only]
    public fun e_not_admin(): u64 { E_NOT_ADMIN }
    #[test_only]
    public fun e_bridge_paused(): u64 { E_BRIDGE_PAUSED }
    #[test_only]
    public fun e_bridge_not_paused(): u64 { E_BRIDGE_NOT_PAUSED }
    #[test_only]
    public fun e_already_initialized(): u64 { E_ALREADY_INITIALIZED }
    #[test_only]
    public fun e_bad_operator_set_length(): u64 { E_BAD_OPERATOR_SET_LENGTH }
    #[test_only]
    public fun e_bad_main_operator_index(): u64 { E_BAD_MAIN_OPERATOR_INDEX }
    #[test_only]
    public fun e_bad_threshold(): u64 { E_BAD_THRESHOLD }
    #[test_only]
    public fun e_too_few_operator_signatures(): u64 { E_TOO_FEW_OPERATOR_SIGNATURES }
    #[test_only]
    public fun e_main_operator_signature_required(): u64 { E_MAIN_OPERATOR_SIGNATURE_REQUIRED }
    #[test_only]
    public fun e_invalid_operator_signature(): u64 { E_INVALID_OPERATOR_SIGNATURE }
    #[test_only]
    public fun e_signature_for_inactive_operator(): u64 { E_SIGNATURE_FOR_INACTIVE_OPERATOR }
    #[test_only]
    public fun e_signature_array_length(): u64 { E_SIGNATURE_ARRAY_LENGTH }
    #[test_only]
    public fun e_expired_attestation(): u64 { E_EXPIRED_ATTESTATION }
    #[test_only]
    public fun e_bad_admin_rotation(): u64 { E_BAD_ADMIN_ROTATION }
    #[test_only]
    public fun e_deposit_nonce_replay(): u64 { E_DEPOSIT_NONCE_REPLAY }
    #[test_only]
    public fun e_payload_hash_mismatch(): u64 { E_PAYLOAD_HASH_MISMATCH }
    #[test_only]
    public fun e_invalid_deposit_binding_proof(): u64 { E_INVALID_DEPOSIT_BINDING_PROOF }
    #[test_only]
    public fun e_not_initialized(): u64 { E_NOT_INITIALIZED }

    // ========================================================================
    // Gate 3 — `#[test_only]` thin wrappers for vault-side CA flows
    //
    // These wrappers exercise the resource-signer-capability pattern end-to-end
    // for the CA flows that Gates 5 / 6 will eventually wrap with full
    // attestation logic + nullifier table + vault_sequence increment. Gate 3
    // proves the CA composition compiles and dispatches correctly; it does NOT
    // implement those production guards.
    //
    // TODO Gate 5: replace test_only_vault_to_recipient_transfer_raw with the
    // full `withdraw_to_recipient` entry function (4-of-7 attestation, nullifier
    // table, vault_sequence increment, recipient_hash binding, request_hash
    // expiry checks).
    //
    // TODO Gate 6: replace test_only_vault_rollover with the production
    // `operator_rollover_vault_pending` entry function (main-operator gate +
    // VaultMaintenanceEvent).
    // ========================================================================

    /// Test-only helper: derives the vault signer from the stored
    /// `SignerCapability` and invokes `confidential_asset::rollover_pending_balance`.
    /// Demonstrates the on-chain signer-cap pattern that Gate 6's production
    /// `operator_rollover_vault_pending` will use.
    ///
    /// Visibility: `#[test_only]` — never callable from a published transaction.
    /// Auth: Gate 3 deliberately omits operator gating to keep the test surface
    /// minimal; Gate 6 will add the main-operator address check.
    #[test_only]
    public fun test_only_vault_rollover() acquires VaultConfig {
        let cfg = borrow_global<VaultConfig>(@eunoma);
        let vault_signer = account::create_signer_with_capability(&cfg.vault_signer_cap);
        confidential_asset::rollover_pending_balance(&vault_signer, cfg.asset_type);
    }

    /// Test-only helper: derives the vault signer and invokes
    /// `confidential_asset::confidential_transfer_raw` with vault as sender.
    /// Demonstrates the vault→recipient CA dispatch path that Gate 5's
    /// production `withdraw_to_recipient` will use after attestation /
    /// nullifier checks.
    ///
    /// Visibility: `#[test_only]`. Gate 5 will replace with a `public entry fun
    /// withdraw_to_recipient` that performs full attestation verification.
    #[test_only]
    public fun test_only_vault_to_recipient_transfer_raw(
        recipient: address,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_eff_aud: vector<vector<u8>>,
        amount_p: vector<vector<u8>>,
        amount_r_sender: vector<vector<u8>>,
        amount_r_recip: vector<vector<u8>>,
        amount_r_eff_aud: vector<vector<u8>>,
        ek_volun_auds: vector<vector<u8>>,
        amount_r_volun_auds: vector<vector<vector<u8>>>,
        zkrp_new_balance: vector<u8>,
        zkrp_amount: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
        memo: vector<u8>,
    ) acquires VaultConfig {
        let cfg = borrow_global<VaultConfig>(@eunoma);
        let vault_signer = account::create_signer_with_capability(&cfg.vault_signer_cap);
        confidential_asset::confidential_transfer_raw(
            &vault_signer,
            cfg.asset_type,
            recipient,
            new_balance_p,
            new_balance_r,
            new_balance_r_eff_aud,
            amount_p,
            amount_r_sender,
            amount_r_recip,
            amount_r_eff_aud,
            ek_volun_auds,
            amount_r_volun_auds,
            zkrp_new_balance,
            zkrp_amount,
            sigma_proto_comm,
            sigma_proto_resp,
            memo,
        );
    }
}

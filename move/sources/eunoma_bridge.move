module eunoma::eunoma_bridge {
    use std::bcs;
    use std::option;
    use std::signer;
    use std::vector;

    use aptos_std::aptos_hash;
    use aptos_std::crypto_algebra;
    use aptos_std::ed25519;
    use aptos_std::table::{Self, Table};

    use std::bn254_algebra::{
        Fq12,
        FormatFq12LscLsb,
        FormatFrLsb,
        FormatG1Uncompr,
        FormatG2Uncompr,
        Fr,
        G1,
        G2,
        Gt,
    };

    use aptos_framework::account;
    use aptos_framework::aptos_account;
    use aptos_framework::chain_id;
    use aptos_framework::confidential_asset;
    use aptos_framework::event;
    use aptos_framework::fungible_asset;
    use aptos_framework::object::{Self, Object};
    use aptos_framework::timestamp;

    use eunoma::groth16_bn254;
    use eunoma_pool::poseidon_bn254;

    const MAX_DEOPERATORS: u64 = 7;
    const THRESHOLD_V2: u64 = 5;
    const ED25519_PUBLIC_KEY_BYTES: u64 = 32;
    const ED25519_SIGNATURE_BYTES: u64 = 64;
    const HASH_BYTES: u64 = 32;
    const FR_BYTES: u64 = 32;

    const G1_UNCOMPRESSED_BYTES: u64 = 64;
    const G2_UNCOMPRESSED_BYTES: u64 = 128;
    const FQ12_BYTES: u64 = 384;
    const PROOF_BYTES: u64 = 256;
    // Stage 3 A6: bumped to add amount_p_digest as additional public input.
    // Deposit publics: commitment, amount_tag, asset_id, vault_addr_hash, amount_p_digest (5) + 1 const term = 6.
    // Withdraw publics: root, nullifier_hash, asset_id, recipient_hash, amount_tag, ca_payload_hash,
    //   request_hash, vault_sequence, amount_p_digest (9) + 1 const term = 10.
    const DEPOSIT_VK_IC_LENGTH: u64 = 6;
    const WITHDRAW_VK_IC_LENGTH: u64 = 10;

    const DOMAIN_DEPOSIT_V2: vector<u8> = b"EUNOMA_DEPOSIT_BIND_V2";
    // Deposit re-key: V3 attestation binds user_addr so relayer-submitted step2a cannot be
    // misdirected. Kept additive because Aptos upgrades reject layout/signature changes.
    const DOMAIN_DEPOSIT_V3: vector<u8> = b"EUNOMA_DEPOSIT_BIND_V3";
    const DOMAIN_WITHDRAW_V2: vector<u8> = b"EUNOMA_WITHDRAW_ATTESTATION_V2";
    const POSEIDON_DOMAIN_ASSET_ID: vector<u8> = b"EUNOMA_ASSET_ID_V2";
    const POSEIDON_DOMAIN_VAULT_ADDR_HASH: vector<u8> = b"EUNOMA_VAULT_ADDR_V2";
    const POSEIDON_DOMAIN_RECIPIENT_HASH: vector<u8> = b"EUNOMA_RECIPIENT_V2";
    // Round 4 WB2.E C / FR-1.5b: precomputed Fr-bytes form of the 3 POSEIDON_DOMAIN_* strings
    // = byte sequence of the string + zero-pad to FR_BYTES (32). Equivalent to
    // bytes_to_field_le32(POSEIDON_DOMAIN_*) but computed at compile time, saving the per-call
    // pad work (formerly ~100 gas per derive_address_hash call, hit on every withdraw
    // recipient_hash + every admin asset_id / vault_addr_hash derive). Byte-equality with
    // bytes_to_field_le32 output: src[0..n] || 0u8 × (32-n), where n = string length.
    //
    // ASSET_ID_V2 (18 bytes "EUNOMA_ASSET_ID_V2" + 14 zeros):
    const POSEIDON_DOMAIN_ASSET_ID_FR: vector<u8> = x"45554e4f4d415f41535345545f49445f56320000000000000000000000000000";
    // VAULT_ADDR_V2 (20 bytes "EUNOMA_VAULT_ADDR_V2" + 12 zeros):
    const POSEIDON_DOMAIN_VAULT_ADDR_HASH_FR: vector<u8> = x"45554e4f4d415f5641554c545f414444525f5632000000000000000000000000";
    // RECIPIENT_V2 (19 bytes "EUNOMA_RECIPIENT_V2" + 13 zeros):
    const POSEIDON_DOMAIN_RECIPIENT_HASH_FR: vector<u8> = x"45554e4f4d415f524543495049454e545f563200000000000000000000000000";

    const E_NOT_ADMIN: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;
    const E_NOT_INITIALIZED: u64 = 3;
    const E_PAUSED: u64 = 4;
    const E_NOT_PAUSED: u64 = 5;
    const E_BAD_THRESHOLD: u64 = 6;
    const E_BAD_ROSTER_HASH: u64 = 7;
    const E_BAD_GROUP_PUBKEY: u64 = 8;
    const E_BAD_VAULT_EK: u64 = 9;
    const E_BAD_FALLBACK_PUBKEYS: u64 = 10;
    const E_EXPIRED: u64 = 11;
    const E_BAD_HASH_LENGTH: u64 = 12;
    const E_PAYLOAD_HASH_MISMATCH: u64 = 13;
    const E_INVALID_DEPOSIT_BINDING_PROOF: u64 = 14;
    const E_INVALID_WITHDRAW_PROOF: u64 = 15;
    const E_INVALID_DEOP_SIGNATURE: u64 = 16;
    const E_TOO_FEW_DEOP_SIGNATURES: u64 = 17;
    const E_DEPOSIT_NONCE_REPLAY: u64 = 18;
    const E_NULLIFIER_ALREADY_SPENT: u64 = 19;
    const E_VAULT_SEQUENCE_MISMATCH: u64 = 20;
    const E_INVALID_ROOT: u64 = 21;
    const E_RECIPIENT_HASH_MISMATCH: u64 = 22;
    /// Stage 3 A6: malformed amount_p (must be exactly 4 entries of 32 bytes each).
    /// See compute_amount_p_digest_v2 + circuits/{deposit_binding,withdrawal_proof}.circom Compose8.
    const E_INVALID_AMOUNT_P_SHAPE: u64 = 23;
    const E_PENDING_DEPOSIT_BINDING: u64 = 24;
    const E_PENDING_WITHDRAW_PROOF: u64 = 25;
    const E_PENDING_WITHDRAW_ATTESTATION: u64 = 26;
    const E_PENDING_WITHDRAW_PAYLOAD: u64 = 27;
    // R6-Plan-B (split-tx deposit): step2b authorization + missing-pending errors.
    const E_NOT_DEPOSIT_OWNER: u64 = 28;
    const E_NO_PENDING_FINALIZATION: u64 = 29;
    // R7-OPS-1 (recorder-delegate): delegate-based known_root recording without admin key.
    const E_RECORDER_DELEGATE_NOT_INITIALIZED: u64 = 30;
    const E_NOT_RECORDER_DELEGATE: u64 = 31;
    const E_NOT_WITHDRAW_OWNER: u64 = 32;
    const E_PENDING_WITHDRAW_FINALIZATION: u64 = 33;
    // (C) gas economics: GasFeeConfigV1 not initialized.
    const E_GAS_FEE_NOT_INITIALIZED: u64 = 34;
    // (B) deposit re-key: a (user_addr, commitment) finalization slot already exists at step2a.
    const E_PENDING_DEPOSIT_FINALIZATION: u64 = 35;

    struct BridgeVault has key {
        admin: address,
        vault_addr: address,
        vault_signer_cap: account::SignerCapability,
        asset_type: Object<fungible_asset::Metadata>,
        vault_sequence: u64,
        // Goal.md M3: monotonic deposit counter. Incremented exactly once per successful
        // deposit_with_commitment_v2 (AFTER confidential_transfer_raw succeeds). Workers
        // observe DepositConfirmedV2 events keyed by this counter to advance their own
        // local state-share cursors deterministically.
        deposit_count: u64,
        paused: bool,
        used_deposit_nonces: Table<vector<u8>, bool>,
        used_nullifiers: Table<vector<u8>, bool>,
        known_roots: Table<vector<u8>, bool>,
    }

    struct BridgeVaultTablesV2 has key {
        used_deposit_nonces: Table<vector<u8>, bool>,
        used_nullifiers: Table<vector<u8>, bool>,
        known_roots: Table<vector<u8>, bool>,
    }

    struct PendingDepositBindingsV2 has key {
        by_commitment: Table<vector<u8>, PendingDepositBindingV2>,
    }

    struct PendingDepositBindingV2 has store, drop {
        amount_tag: vector<u8>,
        amount_p_digest: vector<u8>,
    }

    // N1 (gas opt): cache amount_p directly (in addition to digest) so deposit cache-hit
    // can byte-compare amount_p without recomputing compute_amount_p_digest_v2's 4 Poseidon
    // hashes (~700 gas saved). Additive struct + resource — compatible with Aptos upgrade.
    // Frontend writes via new prepare_deposit_binding_v3 entry; consume reads V3 first then
    // V2 fallback then Groth16 fallback.
    struct PendingDepositBindingV3 has store, drop {
        amount_tag: vector<u8>,
        amount_p_digest: vector<u8>,
        amount_p: vector<vector<u8>>,
    }

    struct PendingDepositBindingsV3 has key {
        by_commitment: Table<vector<u8>, PendingDepositBindingV3>,
    }

    // R6-Plan-B (split-tx): step2a writes; step2b drains and invokes CA framework.
    // Stores all fields needed for DepositConfirmedV2 emit at step2b plus anti-drain
    // bindings (sender, ca_payload_hash, expiry_secs). Anti vault-drain critical:
    // step2b recomputes ca_payload_hash from supplied CA args + asserts == stored hash;
    // without this, attacker (= same signer) can submit step2a with args_X then step2b
    // with args_Y and bind commitment_X to deposit_Y (vault binding mismatch -> drain).
    struct PendingDepositFinalizationV3 has store, drop {
        sender: address,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
    }

    struct PendingDepositFinalizationsV3 has key {
        by_commitment: Table<vector<u8>, PendingDepositFinalizationV3>,
    }

    // R7-OPS-1: recorder-delegate authorization. Admin one-time init seeds delegate to
    // bridge admin addr; admin_set_recorder_delegate rotates to operator (alpha box relayer
    // addr typically). record_known_root_v2_via_delegate then accepts the delegate's signer
    // without requiring admin key on the operator machine. Strict scope: delegate can ONLY
    // call the via_delegate entry — cannot mint commitments, drain vault, change config,
    // or change roster. Worst-case alpha-box compromise = attacker spams known_roots table
    // with garbage (mitigated by assert_hash length check + table idempotent add).
    struct RecorderDelegate has key {
        addr: address,
    }

    // (C) gas economics: flat plain-APT relayer-gas fee collected at deposit step2b, routed to a
    // communal plain-APT gas-reserve account the withdraw relayer draws gas from. FLAT only (a
    // %-fee in cleartext APT would leak the confidential amount). Admin-settable so the fee can be
    // retuned / the reserve rotated / the fee zeroed (kill-switch) without a redeploy.
    struct GasFeeConfigV1 has key {
        flat_fee_octas: u64,
        reserve_addr: address,
    }

    // C1 (gas opt): cache circuit_versions_hash(cfg) so deposit/withdraw hot paths read a
    // 32B field instead of running keccak256+bcs every tx (~250-800 gas saved per call).
    struct CircuitVersionsHashCacheV2 has key {
        hash: vector<u8>,
    }

    struct PendingWithdrawProofsV2 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawProofV2>,
    }

    struct PendingWithdrawProofV2 has store, drop {
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        asset_id: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
        amount_p_digest: vector<u8>,
    }

    struct PendingWithdrawAttestationsV2 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawAttestationV2>,
    }

    struct PendingWithdrawAttestationV2 has store, drop {
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
    }

    struct PendingWithdrawPayloadsV2 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawPayloadV2>,
    }

    struct PendingWithdrawPayloadV2 has store, drop {
        asset_type: address,
        recipient: address,
        ca_payload_hash: vector<u8>,
        amount_p_digest: vector<u8>,
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
    }

    // Round 4 WB2.E B — Withdraw V3 cache mirror (mirror of round-1 deposit V3 pattern).
    // Three compact V3 caches replace the heavy V2 mirrors. V3-first lookup in the 3
    // consume_or_verify_* readers falls through to V2 (legacy) then to fresh
    // verify on cache-miss. Storage savings: ~58-95% per pending entry.
    //
    // ProofV3 keeps ca_payload_hash + amount_p_digest so prepare_withdraw_payload_v3 can
    // SKIP the cross-stage Compose8 recompute that prepare_v2 did (FR-4.6, ~1-2k gas/withdraw).
    struct PendingWithdrawProofsV3 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawProofV3>,
    }

    struct PendingWithdrawProofV3 has store, drop {
        msg_hash: vector<u8>,
        ca_payload_hash: vector<u8>,
        amount_p_digest: vector<u8>,
    }

    // Round 5 Wave E.5 (R5-R) — V3b proof cache: 7 explicit fields (drops asset_id like V2b;
    // drops msg_hash because we use field-by-field equality at consume instead of keccak).
    // Codex constraint (audit 2026-05-25): every Groth16-bound non-key public input MUST be
    // stored and compared. asset_id may be omitted only because VaultPublicInputsV2.asset_id_fr
    // is immutable post-V2-bootstrap. P0 hotfix at prepare_withdraw_payload_v3 + consume_or_
    // compute_withdraw_payload (recompute amount_p_digest + assert ==) MUST remain.
    struct PendingWithdrawProofsV3b has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawProofV3b>,
    }

    struct PendingWithdrawProofV3b has store, drop {
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
        amount_p_digest: vector<u8>,
    }

    // Round 5 Wave E.2 (P06-1) — V2b proof cache drops asset_id field. asset_id is read
    // from VaultPublicInputsV2.asset_id_fr at consume time. Safe because asset_type is
    // immutable post-V2-bootstrap (only init_bridge_vault_v2 / rollover_vault... write
    // it, both one-shot gated). Soft migration: prepare writes V2b, consume reads V3 →
    // V2b → V2 → miss.
    struct PendingWithdrawProofsV2b has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawProofV2b>,
    }

    struct PendingWithdrawProofV2b has store, drop {
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
        amount_p_digest: vector<u8>,
    }

    struct PendingWithdrawAttestationsV3 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawAttestationV3>,
    }

    struct PendingWithdrawAttestationV3 has store, drop {
        msg_hash: vector<u8>,
    }

    // Round 5 Wave E.1 (R5-D) — V2b attestation cache: msg_hash-only (32B vs ~600B V2).
    // Soft migration: prepare_withdraw_attestation_v2 writes V2b going forward;
    // consume_or_verify_withdraw_attestation reads V3 → V2b → V2 → miss. In-flight V2
    // entries (from pre-Round-5 deploys) still drain via the V2 fallthrough branch.
    struct PendingWithdrawAttestationsV2b has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawAttestationV2b>,
    }

    struct PendingWithdrawAttestationV2b has store, drop {
        msg_hash: vector<u8>,
    }

    struct PendingWithdrawPayloadsV3 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawPayloadV3>,
    }

    struct PendingWithdrawPayloadV3 has store, drop {
        msg_hash: vector<u8>,
        amount_p_digest: vector<u8>,
    }

    struct PendingWithdrawFinalizationsV3 has key {
        by_request_hash: Table<vector<u8>, PendingWithdrawFinalizationV3>,
    }

    struct PendingWithdrawFinalizationV3 has store, drop {
        sender: address,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
    }

    struct DeoperatorConfigV2 has key {
        operator_set_version: u64,
        dkg_epoch: u64,
        threshold: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        vault_ek: vector<u8>,
        deposit_circuit_version: vector<u8>,
        withdraw_circuit_version: vector<u8>,
        ca_payload_circuit_version: vector<u8>,
        fallback_pubkeys: vector<vector<u8>>,
    }

    struct DepositBindingVK has key {
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic: vector<vector<u8>>,
    }

    struct PreparedDepositBindingVK has key {
        pvk_alpha_g1_beta_g2_fq12: vector<u8>,
        pvk_gamma_g2_neg: vector<u8>,
        pvk_delta_g2_neg: vector<u8>,
        pvk_uvw_gamma_g1: vector<vector<u8>>,
    }

    struct WithdrawProofVK has key {
        alpha_g1: vector<u8>,
        beta_g2: vector<u8>,
        gamma_g2: vector<u8>,
        delta_g2: vector<u8>,
        ic: vector<vector<u8>>,
    }

    struct PreparedWithdrawProofVK has key {
        pvk_alpha_g1_beta_g2_fq12: vector<u8>,
        pvk_gamma_g2_neg: vector<u8>,
        pvk_delta_g2_neg: vector<u8>,
        pvk_uvw_gamma_g1: vector<vector<u8>>,
    }

    struct DepositBindingTestOverride has key {
        asset_id_fr: vector<u8>,
        vault_addr_hash_fr: vector<u8>,
    }

    struct VaultPublicInputsV2 has key {
        asset_id_fr: vector<u8>,
        vault_addr_hash_fr: vector<u8>,
    }

    struct CircuitVersionsForHash has drop, store {
        deposit_circuit_version: vector<u8>,
        withdraw_circuit_version: vector<u8>,
        ca_payload_circuit_version: vector<u8>,
    }

    struct DepositAttestationV2Message has drop, store {
        domain: vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
    }

    struct DepositAttestationV3Message has drop, store {
        domain: vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
        user_addr: address,
    }

    struct WithdrawAttestationV2Message has drop, store {
        domain: vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
    }

    struct CAPayloadForHashV2 has drop, copy {
        asset_type: Object<fungible_asset::Metadata>,
        to: address,
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
    }

    // A1 (Aptos compat fix): struct DepositEventV2 RESTORED — Aptos rejects deletion of
    // #[event] structs at upgrade time (EVENT_METADATA_VALIDATION_ERROR). We keep the
    // struct declaration but NEVER emit it (the emit was deleted in deposit_with_commitment_v2).
    // Gas saved = the emit cost (~700-900 gas), not the struct declaration (zero runtime cost).
    #[event]
    struct DepositEventV2 has drop, store {
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
    }

    #[event]
    struct VaultInitializedV2 has drop, store {
        vault_addr: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        threshold: u64,
        roster_hash: vector<u8>,
    }

    // Goal.md M3: post-success deposit event keyed by the monotonic deposit_count. The
    // worker-side observer reads this event off the chain ledger and advances its local
    // state-share cursor IFF deposit_count == observer's local_cursor + 1. Replay,
    // wrong-sequence, wrong-asset, and stale events fail closed at the observer.
    #[event]
    struct DepositConfirmedV2 has drop, store {
        vault_addr: address,
        asset_type: address,
        deposit_count: u64,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
    }

    // R6-Plan-B (split-tx): emitted at step2a so frontend/observer detect partial
    // state. step2b then emits the normal DepositConfirmedV2. Observer cursor does
    // NOT advance on Step2aRecorded — only on DepositConfirmedV2.
    #[event]
    struct DepositStep2aRecorded has drop, store {
        commitment: vector<u8>,
        sender: address,
        expiry_secs: u64,
    }

    // FR-1.1 (Round 4 F): struct retained, emit replaced by WithdrawEventV3.
    // Aptos forbids deleting #[event] fields (EVENT_METADATA_VALIDATION_ERROR); same A1
    // pattern as DepositEventV2:369-372.
    #[event]
    struct WithdrawEventV2 has drop, store {
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
    }

    // FR-1.1 (Round 4 F): bridge withdraw event no longer emits raw recipient address;
    // amount_tag + ca_payload_hash were unused off-chain. Parsed by the same V2 consumers
    // (chain_fetch::parse_tx_withdraw_event_v2, vault_resync_client::parseWithdrawEventV2FromTx,
    // testnet_e2e_checks event-binding gate) — they accept either V2 or V3 type names.
    #[event]
    struct WithdrawEventV3 has drop, store {
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
    }

    #[event]
    struct BridgePauseChangedV2 has drop, store {
        paused: bool,
    }

    #[event]
    struct RootRecordedV2 has drop, store {
        root: vector<u8>,
    }

    public entry fun init_vault_with_ca_registration_v2(
        admin: &signer,
        vault_seed: vector<u8>,
        asset_type: Object<fungible_asset::Metadata>,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        vault_ek: vector<u8>,
        registration_sigma_comm: vector<vector<u8>>,
        registration_sigma_resp: vector<vector<u8>>,
        deposit_circuit_version: vector<u8>,
        withdraw_circuit_version: vector<u8>,
        ca_payload_circuit_version: vector<u8>,
        fallback_pubkeys: vector<vector<u8>>,
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<BridgeVault>(@eunoma), E_ALREADY_INITIALIZED);
        assert!(!exists<DeoperatorConfigV2>(@eunoma), E_ALREADY_INITIALIZED);
        assert_hash(&roster_hash);
        assert!(vector::length(&frost_group_pubkey) == ED25519_PUBLIC_KEY_BYTES, E_BAD_GROUP_PUBKEY);
        assert!(vector::length(&vault_ek) == ED25519_PUBLIC_KEY_BYTES, E_BAD_VAULT_EK);
        assert_valid_fallback_pubkeys(&fallback_pubkeys);

        let (vault_signer, vault_signer_cap) = account::create_resource_account(admin, vault_seed);
        let vault_addr = signer::address_of(&vault_signer);
        confidential_asset::register_raw(
            &vault_signer,
            *&asset_type,
            *&vault_ek,
            registration_sigma_comm,
            registration_sigma_resp,
        );

        move_to(admin, BridgeVault {
            admin: signer::address_of(admin),
            vault_addr,
            vault_signer_cap,
            asset_type,
            vault_sequence: 0,
            deposit_count: 0,
            paused: false,
            used_deposit_nonces: table::new<vector<u8>, bool>(),
            used_nullifiers: table::new<vector<u8>, bool>(),
            known_roots: table::new<vector<u8>, bool>(),
        });
        move_to(admin, new_vault_tables_v2());

        move_to(admin, DeoperatorConfigV2 {
            operator_set_version,
            dkg_epoch,
            threshold: THRESHOLD_V2,
            roster_hash,
            frost_group_pubkey,
            vault_ek,
            deposit_circuit_version,
            withdraw_circuit_version,
            ca_payload_circuit_version,
            fallback_pubkeys,
        });

        event::emit(VaultInitializedV2 {
            vault_addr,
            asset_type: object::object_address(&asset_type),
            operator_set_version,
            dkg_epoch,
            threshold: THRESHOLD_V2,
            roster_hash,
        });
    }

    public entry fun rollover_vault_with_ca_registration_v2(
        admin: &signer,
        vault_seed: vector<u8>,
        asset_type: Object<fungible_asset::Metadata>,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        vault_ek: vector<u8>,
        registration_sigma_comm: vector<vector<u8>>,
        registration_sigma_resp: vector<vector<u8>>,
        deposit_circuit_version: vector<u8>,
        withdraw_circuit_version: vector<u8>,
        ca_payload_circuit_version: vector<u8>,
        fallback_pubkeys: vector<vector<u8>>,
    ) acquires BridgeVault, DeoperatorConfigV2, VaultPublicInputsV2, DepositBindingTestOverride, CircuitVersionsHashCacheV2 {
        // Codex fix: rollover is the V1→V2 bootstrap that CREATES BridgeVaultTablesV2. The
        // tightened assert_initialized() would falsely abort here because V2 tables don't
        // exist yet. Replace with narrower pre-rollover checks (BridgeVault + cfg only).
        assert!(exists<BridgeVault>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<DeoperatorConfigV2>(@eunoma), E_NOT_INITIALIZED);
        assert_admin(admin);
        assert!(!exists<BridgeVaultTablesV2>(@eunoma), E_ALREADY_INITIALIZED);
        assert_hash(&roster_hash);
        assert!(vector::length(&frost_group_pubkey) == ED25519_PUBLIC_KEY_BYTES, E_BAD_GROUP_PUBKEY);
        assert!(vector::length(&vault_ek) == ED25519_PUBLIC_KEY_BYTES, E_BAD_VAULT_EK);
        assert_valid_fallback_pubkeys(&fallback_pubkeys);

        let (vault_signer, vault_signer_cap) = account::create_resource_account(admin, vault_seed);
        let vault_addr = signer::address_of(&vault_signer);
        confidential_asset::register_raw(
            &vault_signer,
            *&asset_type,
            *&vault_ek,
            registration_sigma_comm,
            registration_sigma_resp,
        );

        let asset_id_fr = derive_asset_id(asset_type);
        let vault_addr_hash_fr = derive_vault_addr_hash(vault_addr);
        upsert_vault_public_inputs_v2(admin, asset_id_fr, vault_addr_hash_fr);
        move_to(admin, new_vault_tables_v2());

        let vault = borrow_global_mut<BridgeVault>(@eunoma);
        vault.admin = signer::address_of(admin);
        vault.vault_addr = vault_addr;
        vault.vault_signer_cap = vault_signer_cap;
        vault.asset_type = asset_type;
        vault.vault_sequence = 0;
        vault.deposit_count = 0;
        vault.paused = false;

        let cfg = borrow_global_mut<DeoperatorConfigV2>(@eunoma);
        cfg.operator_set_version = operator_set_version;
        cfg.dkg_epoch = dkg_epoch;
        cfg.threshold = THRESHOLD_V2;
        cfg.roster_hash = roster_hash;
        cfg.frost_group_pubkey = frost_group_pubkey;
        cfg.vault_ek = vault_ek;
        cfg.deposit_circuit_version = deposit_circuit_version;
        cfg.withdraw_circuit_version = withdraw_circuit_version;
        cfg.ca_payload_circuit_version = ca_payload_circuit_version;
        cfg.fallback_pubkeys = fallback_pubkeys;

        // C2 gas opt: refresh circuit_versions_hash cache. Defensive: skip if not yet initialized.
        if (exists<CircuitVersionsHashCacheV2>(@eunoma)) {
            let cfg_ref = borrow_global<DeoperatorConfigV2>(@eunoma);
            let new_hash = circuit_versions_hash(cfg_ref);
            borrow_global_mut<CircuitVersionsHashCacheV2>(@eunoma).hash = new_hash;
        };

        event::emit(VaultInitializedV2 {
            vault_addr,
            asset_type: object::object_address(&asset_type),
            operator_set_version,
            dkg_epoch,
            threshold: THRESHOLD_V2,
            roster_hash,
        });
    }

    public entry fun rotate_deoperator_config_v2(
        admin: &signer,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        vault_ek: vector<u8>,
        deposit_circuit_version: vector<u8>,
        withdraw_circuit_version: vector<u8>,
        ca_payload_circuit_version: vector<u8>,
        fallback_pubkeys: vector<vector<u8>>,
    ) acquires BridgeVault, DeoperatorConfigV2, CircuitVersionsHashCacheV2 {
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(signer::address_of(admin) == vault.admin, E_NOT_ADMIN);
        assert_hash(&roster_hash);
        assert!(vector::length(&frost_group_pubkey) == ED25519_PUBLIC_KEY_BYTES, E_BAD_GROUP_PUBKEY);
        assert!(vector::length(&vault_ek) == ED25519_PUBLIC_KEY_BYTES, E_BAD_VAULT_EK);
        assert_valid_fallback_pubkeys(&fallback_pubkeys);

        let cfg = borrow_global_mut<DeoperatorConfigV2>(@eunoma);
        cfg.operator_set_version = operator_set_version;
        cfg.dkg_epoch = dkg_epoch;
        cfg.threshold = THRESHOLD_V2;
        cfg.roster_hash = roster_hash;
        cfg.frost_group_pubkey = frost_group_pubkey;
        cfg.vault_ek = vault_ek;
        cfg.deposit_circuit_version = deposit_circuit_version;
        cfg.withdraw_circuit_version = withdraw_circuit_version;
        cfg.ca_payload_circuit_version = ca_payload_circuit_version;
        cfg.fallback_pubkeys = fallback_pubkeys;

        // C2 gas opt: refresh circuit_versions_hash cache. Defensive: skip if not yet initialized.
        if (exists<CircuitVersionsHashCacheV2>(@eunoma)) {
            let cfg_ref = borrow_global<DeoperatorConfigV2>(@eunoma);
            let new_hash = circuit_versions_hash(cfg_ref);
            borrow_global_mut<CircuitVersionsHashCacheV2>(@eunoma).hash = new_hash;
        };
    }

    public entry fun publish_vault_public_inputs_v2(
        admin: &signer,
    ) acquires BridgeVault, DepositBindingTestOverride {
        assert_admin(admin);
        assert!(!exists<VaultPublicInputsV2>(@eunoma), E_ALREADY_INITIALIZED);
        let vault = borrow_global<BridgeVault>(@eunoma);
        let asset_id_fr = derive_asset_id(vault.asset_type);
        let vault_addr_hash_fr = derive_vault_addr_hash(vault.vault_addr);
        assert_hash(&asset_id_fr);
        assert_hash(&vault_addr_hash_fr);
        move_to(admin, VaultPublicInputsV2 { asset_id_fr, vault_addr_hash_fr });
    }

    public entry fun refresh_vault_public_inputs_v2(
        admin: &signer,
    ) acquires BridgeVault, VaultPublicInputsV2, DepositBindingTestOverride {
        assert_admin(admin);
        let vault = borrow_global<BridgeVault>(@eunoma);
        let asset_id_fr = derive_asset_id(vault.asset_type);
        let vault_addr_hash_fr = derive_vault_addr_hash(vault.vault_addr);
        upsert_vault_public_inputs_v2(admin, asset_id_fr, vault_addr_hash_fr);
    }

    public entry fun pause_v2(admin: &signer) acquires BridgeVault {
        let vault = borrow_global_mut<BridgeVault>(@eunoma);
        assert!(signer::address_of(admin) == vault.admin, E_NOT_ADMIN);
        assert!(!vault.paused, E_PAUSED);
        vault.paused = true;
        event::emit(BridgePauseChangedV2 { paused: true });
    }

    public entry fun unpause_v2(admin: &signer) acquires BridgeVault {
        let vault = borrow_global_mut<BridgeVault>(@eunoma);
        assert!(signer::address_of(admin) == vault.admin, E_NOT_ADMIN);
        assert!(vault.paused, E_NOT_PAUSED);
        vault.paused = false;
        event::emit(BridgePauseChangedV2 { paused: false });
    }

    public entry fun record_known_root_v2(
        admin: &signer,
        root: vector<u8>,
    ) acquires BridgeVault, BridgeVaultTablesV2 {
        assert_admin(admin);
        assert_hash(&root);
        record_known_root_internal(*&root);
        event::emit(RootRecordedV2 { root });
    }

    // R7-OPS-1: admin one-time init seeds RecorderDelegate.addr = admin's own address.
    // After init, admin can rotate via admin_set_recorder_delegate. This is required
    // before any record_known_root_v2_via_delegate call.
    public entry fun init_recorder_delegate(admin: &signer) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<RecorderDelegate>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, RecorderDelegate { addr: signer::address_of(admin) });
    }

    // R7-OPS-1: admin rotates the recorder delegate address. Setting to a non-admin
    // operator address (e.g., alpha-box testnet-relayer) lets the operator timer call
    // record_known_root_v2_via_delegate without holding admin keys. Re-callable any time
    // by admin to revoke (set back to admin addr) or rotate to a new operator.
    public entry fun admin_set_recorder_delegate(
        admin: &signer,
        delegate_addr: address,
    ) acquires RecorderDelegate, BridgeVault {
        assert_admin(admin);
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global_mut<RecorderDelegate>(@eunoma);
        rd.addr = delegate_addr;
    }

    // (C) gas economics: one-time init of the flat plain-APT relayer-gas fee + communal reserve
    // address. No-op-safe: until this runs, deposit_step2b collects no fee (exists<> guard there).
    public entry fun init_gas_fee_config_v1(
        admin: &signer,
        flat_fee_octas: u64,
        reserve_addr: address,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<GasFeeConfigV1>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, GasFeeConfigV1 { flat_fee_octas, reserve_addr });
    }

    // (C) gas economics: admin retunes the flat fee / rotates the reserve / zeroes the fee.
    // flat_fee_octas = 0 is the incident kill-switch — disables collection with no redeploy.
    public entry fun admin_set_gas_fee_config_v1(
        admin: &signer,
        flat_fee_octas: u64,
        reserve_addr: address,
    ) acquires GasFeeConfigV1, BridgeVault {
        assert_admin(admin);
        assert!(exists<GasFeeConfigV1>(@eunoma), E_GAS_FEE_NOT_INITIALIZED);
        let c = borrow_global_mut<GasFeeConfigV1>(@eunoma);
        c.flat_fee_octas = flat_fee_octas;
        c.reserve_addr = reserve_addr;
    }

    // R7-OPS-1: delegate-signed root recording. Sender must match RecorderDelegate.addr
    // (set by admin via admin_set_recorder_delegate). Same effect as record_known_root_v2
    // but no admin key required on the operator machine. Strict scope: only writes to
    // known_roots table — cannot touch any other admin-controlled state.
    public entry fun record_known_root_v2_via_delegate(
        delegate: &signer,
        root: vector<u8>,
    ) acquires RecorderDelegate, BridgeVaultTablesV2 {
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global<RecorderDelegate>(@eunoma);
        assert!(signer::address_of(delegate) == rd.addr, E_NOT_RECORDER_DELEGATE);
        assert_hash(&root);
        record_known_root_internal(*&root);
        event::emit(RootRecordedV2 { root });
    }

    public entry fun deposit_with_commitment_v2(
        sender: &signer,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        deposit_binding_proof: vector<u8>,
        expiry_secs: u64,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
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
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingDepositBindingsV2, PendingDepositBindingsV3, DeoperatorConfigV2, VaultPublicInputsV2, PreparedDepositBindingVK, CircuitVersionsHashCacheV2 {
        assert_initialized();
        assert_not_expired(expiry_secs);
        // R6-A.1: inline 3-hash block (mirrors R5-G.2 assert_6_withdraw_hashes idiom).
        assert_3_deposit_hashes(&commitment, &amount_tag, &ca_payload_hash);

        // A5a + A4 + A2 + A6 gas opt: combined nonce check+mark via V1 helper; single mut
        // borrow of BridgeVault held across body (no helper between here and deposit_count
        // bump acquires BridgeVault post-V1); hoist asset_type_addr once; use cached
        // circuit_versions_hash via C3 helper.
        check_and_mark_deposit_nonce_v2(&deposit_nonce);
        let vault = borrow_global_mut<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        let asset_type = vault.asset_type;
        let asset_type_addr = object::object_address(&asset_type);
        let vault_addr = vault.vault_addr;

        let ca_payload_hash_raw = hash_confidential_transfer_payload_v2(
            &asset_type,
            &vault_addr,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        );
        // R6-B.4: bool-return in-place compare; avoids 32B alloc + 32-byte `==` loop.
        assert!(ca_payload_hash_matches_safe(ca_payload_hash_raw, &ca_payload_hash), E_PAYLOAD_HASH_MISMATCH);

        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        // R6-C.2 hoist: cvh local enables ref-pass to R6-C.1 struct-free serializer.
        let cvh = get_or_compute_circuit_versions_hash(cfg);
        // R6-C.1: struct-free BCS serializer (mirrors R5-C withdraw analog at line 1416).
        // Byte-identical to bcs::to_bytes(&DepositAttestationV2Message{...}) per byte-identity
        // tests in round6_wave_d_deposit_msg_byte_identity_tests.move. Saves ~500-800 gas/deposit
        // (struct walker frame + heap alloc + drop + 6 redundant vec32 bcs allocs).
        let msg_bytes = serialize_deposit_attestation_v3_msg(
            &DOMAIN_DEPOSIT_V3,
            chain_id::get(),
            @eunoma,
            vault_addr,
            asset_type_addr,
            cfg.operator_set_version,
            cfg.dkg_epoch,
            &cfg.roster_hash,
            &cfg.frost_group_pubkey,
            &commitment,
            &amount_tag,
            &ca_payload_hash,
            &deposit_nonce,
            expiry_secs,
            &cvh,
            // (B) monolith self-deposit: user IS the submitter, so user_addr = sender.
            signer::address_of(sender),
        );
        assert_deop_attestation_v2(
            &msg_bytes,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
        );
        // B1-v2 gas opt: pass &amount_p directly. consume_or_verify handles digest computation
        // internally only on cache-miss / V2-cache / Groth16 fallback. V3 cache-hit (happy
        // path post-migration) skips 4-Poseidon compute entirely (~700 gas saved per deposit).
        // R7-W1: pass sender_addr for composite (sender, commitment) V3 cache lookup.
        consume_or_verify_deposit_binding(
            signer::address_of(sender),
            &commitment,
            &amount_tag,
            &amount_p,
            deposit_binding_proof,
        );

        confidential_asset::confidential_transfer_raw(
            sender,
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
        );

        // Goal.md M3: increment deposit_count AFTER confidential_transfer_raw succeeds.
        // If the CA payload had failed verification or aborted, deposit_count must NOT
        // advance — the observer's strict-monotonic-ordering check would otherwise see a
        // counter gap that no event could explain. A4 gas opt: reuse mut borrow from line 624.
        let new_deposit_count = vault.deposit_count + 1;
        vault.deposit_count = new_deposit_count;

        // Goal.md M3: post-success deposit event keyed by deposit_count. Observers use this
        // to advance their local state-share cursor; strictly ordered by deposit_count.
        event::emit(DepositConfirmedV2 {
            vault_addr,
            asset_type: asset_type_addr,
            deposit_count: new_deposit_count,
            commitment,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
        });
    }

    // ============================================================================
    // R6-Plan-B: split-tx deposit (step2a + step2b) for Petra ~13k execution cap.
    //
    // Single-tx deposit_with_commitment_v2 hits ~14-18k step2 gas (~8-11k CA framework
    // sigma-proof + ~3-7k Eunoma own-verify). Petra rejects at sim time > ~13k.
    // Split: step2a runs Eunoma own-verify (~3-5k); step2b invokes CA framework (~10-13k).
    // Both signed by SAME user (CA framework requires sender's signer to debit balance).
    //
    // Anti vault-drain: step2b RECOMPUTES ca_payload_hash from supplied CA args + asserts
    // == ca_payload_hash stored at step2a. Without this, attacker (= same signer) could
    // submit step2a with args_X (binds commitment_X to amount_X via FROST attest), then
    // step2b with args_Y (CA framework verifies args_Y internally + transfers args_Y to
    // vault), creating commitment_X bound to amount_Y -> withdraw amount_X = vault drain.
    //
    // Re-asserts at step2b (per Plan agent B.0 audit):
    //   1. tx.sender == pending.sender (anti-frontrun, same-user enforcement)
    //   2. assert_not_expired(pending.expiry_secs) (anti delayed-attack past FROST expiry)
    //   3. !vault.paused (admin pause must abort in-flight finalizations)
    //   4. ca_payload_hash recompute + match (anti args-substitution vault drain)
    // ============================================================================

    public entry fun deposit_step2a_eunoma_verify(
        sender: &signer,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        deposit_binding_proof: vector<u8>,
        expiry_secs: u64,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
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
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingDepositBindingsV2, PendingDepositBindingsV3, PendingDepositFinalizationsV3, DeoperatorConfigV2, VaultPublicInputsV2, PreparedDepositBindingVK, CircuitVersionsHashCacheV2 {
        deposit_step2a_eunoma_verify_v3(
            sender,
            signer::address_of(sender),
            commitment,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
            deposit_binding_proof,
            expiry_secs,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
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

    public entry fun deposit_step2a_eunoma_verify_v3(
        // (B) deposit re-key: tx submitter (relayer OR the user themselves) — UNUSED for auth.
        // Authority = the deop FROST attestation (now binds user_addr) + the deposit-binding proof.
        _relayer: &signer,
        // (B) the depositing user's address; the finalization + binding cache are keyed by this,
        // and it is bound into the signed attestation message so a relayer cannot misdirect it.
        user_addr: address,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        deposit_binding_proof: vector<u8>,
        expiry_secs: u64,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
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
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingDepositBindingsV2, PendingDepositBindingsV3, PendingDepositFinalizationsV3, DeoperatorConfigV2, VaultPublicInputsV2, PreparedDepositBindingVK, CircuitVersionsHashCacheV2 {
        assert_initialized();
        assert!(exists<PendingDepositFinalizationsV3>(@eunoma), E_NOT_INITIALIZED);
        assert_not_expired(expiry_secs);
        assert_3_deposit_hashes(&commitment, &amount_tag, &ca_payload_hash);

        check_and_mark_deposit_nonce_v2(&deposit_nonce);
        let vault = borrow_global_mut<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        let asset_type = vault.asset_type;
        let asset_type_addr = object::object_address(&asset_type);
        let vault_addr = vault.vault_addr;

        let ca_payload_hash_raw = hash_confidential_transfer_payload_v2(
            &asset_type,
            &vault_addr,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        );
        assert!(ca_payload_hash_matches_safe(ca_payload_hash_raw, &ca_payload_hash), E_PAYLOAD_HASH_MISMATCH);

        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        let cvh = get_or_compute_circuit_versions_hash(cfg);
        let msg_bytes = serialize_deposit_attestation_v3_msg(
            &DOMAIN_DEPOSIT_V3,
            chain_id::get(),
            @eunoma,
            vault_addr,
            asset_type_addr,
            cfg.operator_set_version,
            cfg.dkg_epoch,
            &cfg.roster_hash,
            &cfg.frost_group_pubkey,
            &commitment,
            &amount_tag,
            &ca_payload_hash,
            &deposit_nonce,
            expiry_secs,
            &cvh,
            // (B) deposit re-key: bind the depositing user into the deop-signed attestation so a
            // relayer-submitted step2a is authenticated to user_addr and cannot be misdirected.
            user_addr,
        );
        assert_deop_attestation_v2(
            &msg_bytes,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
        );
        // (B) consume the V3 binding cache under (user_addr, commitment) — prepare_deposit_binding_v3
        // wrote it under the same user_addr. The deposit-binding Groth16 proof already binds the
        // commitment to the user's private nullifier/secret, so keying by user_addr does NOT reopen
        // the R7-W1 squat-DoS (an attacker cannot mint a valid binding for a commitment they don't own).
        consume_or_verify_deposit_binding(
            user_addr,
            &commitment,
            &amount_tag,
            &amount_p,
            deposit_binding_proof,
        );

        // Record pending finalization keyed by (user_addr, commitment). step2b (signed by the USER)
        // drains it via compose_pending_key(signer::address_of(sender), commitment) + the
        // entry.sender == signer check, so only the user — not the relayer — can finalize + CA-debit.
        let key = compose_pending_key(user_addr, &commitment);
        let pending = borrow_global_mut<PendingDepositFinalizationsV3>(@eunoma);
        // (B sub-4) contains-guard: a pre-existing (user_addr, commitment) finalization slot is
        // rejected with a named error instead of a raw table::add abort. A same-nonce relayer retry
        // is already stopped earlier by check_and_mark_deposit_nonce_v2 (E_DEPOSIT_NONCE_REPLAY).
        assert!(!table::contains(&pending.by_commitment, *&key), E_PENDING_DEPOSIT_FINALIZATION);
        table::add(&mut pending.by_commitment, key, PendingDepositFinalizationV3 {
            sender: user_addr,
            amount_tag: *&amount_tag,
            ca_payload_hash: *&ca_payload_hash,
            deposit_nonce: *&deposit_nonce,
            expiry_secs,
        });

        event::emit(DepositStep2aRecorded {
            commitment,
            sender: user_addr,
            expiry_secs,
        });

        // Owned-by-value args (new_balance_p, etc.) used by-ref above; auto-dropped at
        // scope end (vector<...> has drop). They are re-supplied at step2b for the
        // confidential_transfer_raw call.
    }

    public entry fun deposit_step2b_invoke_framework(
        sender: &signer,
        commitment: vector<u8>,
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
    ) acquires BridgeVault, PendingDepositFinalizationsV3, GasFeeConfigV1 {
        assert_initialized();
        assert!(exists<PendingDepositFinalizationsV3>(@eunoma), E_NOT_INITIALIZED);

        // R7-W1: composite (sender, commitment) key — table contains() with attacker's
        // address won't collide with victim's slot. entry.sender check below is now
        // structurally enforced by the key itself, but kept as belt-and-suspenders.
        let sender_addr = signer::address_of(sender);
        let key = compose_pending_key(sender_addr, &commitment);
        let pending = borrow_global_mut<PendingDepositFinalizationsV3>(@eunoma);
        assert!(table::contains(&pending.by_commitment, key), E_NO_PENDING_FINALIZATION);
        let entry = table::remove(&mut pending.by_commitment, key);

        // Re-checks (Plan agent B.0 audit): sender, expiry, paused, ca_payload_hash.
        assert!(sender_addr == entry.sender, E_NOT_DEPOSIT_OWNER);
        assert_not_expired(entry.expiry_secs);

        let vault = borrow_global_mut<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        let asset_type = vault.asset_type;
        let asset_type_addr = object::object_address(&asset_type);
        let vault_addr = vault.vault_addr;

        // ANTI VAULT-DRAIN: recompute ca_payload_hash from supplied CA args + assert
        // matches entry.ca_payload_hash (verified by step2a's FROST attest binding).
        let ca_payload_hash_raw = hash_confidential_transfer_payload_v2(
            &asset_type,
            &vault_addr,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        );
        assert!(ca_payload_hash_matches_safe(ca_payload_hash_raw, &entry.ca_payload_hash), E_PAYLOAD_HASH_MISMATCH);

        confidential_asset::confidential_transfer_raw(
            sender,
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
        );

        // (C) gas economics — collect a FLAT plain-APT relayer-gas fee from the user (already the
        // signer here) into the communal gas reserve. Zero extra signature. FLAT ONLY: a %-fee paid
        // in cleartext APT would reveal the confidential amount (A = F/p). No-op until admin runs
        // init_gas_fee_config_v1; flat_fee_octas = 0 disables it (incident kill-switch). Atomic with
        // the CA debit above — if the user lacks APT for the fee the whole step2b reverts (no
        // deposit without fee, no fee without deposit). Borrows a different global than `vault`.
        if (exists<GasFeeConfigV1>(@eunoma)) {
            let fee_cfg = borrow_global<GasFeeConfigV1>(@eunoma);
            if (fee_cfg.flat_fee_octas > 0) {
                aptos_account::transfer(sender, fee_cfg.reserve_addr, fee_cfg.flat_fee_octas);
            };
        };

        let new_deposit_count = vault.deposit_count + 1;
        vault.deposit_count = new_deposit_count;

        event::emit(DepositConfirmedV2 {
            vault_addr,
            asset_type: asset_type_addr,
            deposit_count: new_deposit_count,
            commitment,
            amount_tag: entry.amount_tag,
            ca_payload_hash: entry.ca_payload_hash,
            deposit_nonce: entry.deposit_nonce,
        });
    }

    public entry fun withdraw_to_recipient_v2(
        _relayer: &signer,
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
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
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
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingWithdrawProofsV2, PendingWithdrawProofsV2b, PendingWithdrawProofsV3, PendingWithdrawProofsV3b, PendingWithdrawAttestationsV2, PendingWithdrawAttestationsV2b, PendingWithdrawAttestationsV3, PendingWithdrawPayloadsV2, PendingWithdrawPayloadsV3, DeoperatorConfigV2, VaultPublicInputsV2, PreparedWithdrawProofVK, CircuitVersionsHashCacheV2 {
        assert_initialized();
        assert_not_expired(expiry_secs);
        // R5-P (Wave G.2): inlined 6-hash assertion block.
        assert_6_withdraw_hashes(&root, &nullifier_hash, &recipient_hash, &amount_tag, &ca_payload_hash, &request_hash);

        // WB2.D/FW8.3: hold ONE mut borrow on BridgeVaultTablesV2 across known_root check +
        // nullifier check + nullifier mark. Round-1 deposit V1 did the same for nonce check+mark
        // via `check_and_mark_deposit_nonce_v2`; withdraw has 3 separate uses so we expose
        // `_with_tables` variants and the borrow lives across the whole body.
        let tables = borrow_global_mut<BridgeVaultTablesV2>(@eunoma);
        assert!(known_root_recorded_with_tables(tables, &root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables(tables, &nullifier_hash), E_NULLIFIER_ALREADY_SPENT);

        // WB2.B/FS1.5+FW2.1: hold a single mut borrow on BridgeVault across the whole withdraw
        // body (round-1 A4 deposit-side pattern, now applied to withdraw). Replaces 3 separate
        // borrow_global calls (immut at 801 + immut at 862-865 + mut at 867) with one.
        let vault = borrow_global_mut<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        assert!(vault.vault_sequence == vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let asset_type = vault.asset_type;
        let vault_addr = vault.vault_addr;
        // WB2.F (codex missed opt #3): hoist asset_type_addr once instead of recomputing
        // inside consume_or_verify_withdraw_attestation callsite.
        let asset_type_addr = object::object_address(&asset_type);
        let expected_recipient_hash = derive_recipient_hash(recipient);
        assert!(expected_recipient_hash == recipient_hash, E_RECIPIENT_HASH_MISMATCH);

        let (_, amount_p_digest) = consume_or_compute_withdraw_payload(
            recipient,
            asset_type,
            &request_hash,
            &ca_payload_hash,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        );

        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        // R5-J (Round 5 A.5): compute circuit_versions_hash once outside the inner fn (which
        // calls into 3 sub-branches all using it). Eliminates inner CircuitVersionsHashCacheV2
        // borrow + 32B clone per call. Saves ~150-300 gas/withdraw.
        let circuit_versions_hash = get_or_compute_circuit_versions_hash(cfg);
        // FR-1.3: 6 `*&` hash clones eliminated; consume_or_verify_withdraw_attestation now &refs.
        consume_or_verify_withdraw_attestation(
            &root,
            &nullifier_hash,
            recipient,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            expiry_secs,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
            vault_addr,
            asset_type_addr,
            &circuit_versions_hash,
        );
        // WB2.C/FW2.4: inline VaultPublicInputsV2 read. asset_id_fr bound to a local because
        // FR-1.3 (Round 4 WB2.E B) flipped consume_or_verify_withdraw_proof to by-ref; we need
        // a named address-of target for asset_id_fr.
        let asset_id = borrow_global<VaultPublicInputsV2>(@eunoma).asset_id_fr;
        // FR-1.3: 7 `*&` clones eliminated; all hash args now passed as &vector<u8> refs.
        consume_or_verify_withdraw_proof(
            &root,
            &nullifier_hash,
            &asset_id,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            &amount_p_digest,
            withdraw_proof,
        );

        // WB2.B continued: derive signer from the held mut borrow (immut field-borrow of mut
        // borrow), then bump seq on same mut borrow. No second/third borrow_global needed.
        let vault_signer = account::create_signer_with_capability(&vault.vault_signer_cap);
        // WB2.D continued: use already-held `tables` mut borrow for the mark (no second
        // borrow_global_mut<BridgeVaultTablesV2>). nullifier_hash is still owned and consumed
        // by the event emit below; the *& makes the required clone for the table::add key.
        mark_nullifier_used_with_tables(tables, *&nullifier_hash);
        vault.vault_sequence = vault.vault_sequence + 1;

        confidential_asset::confidential_transfer_raw(
            &vault_signer,
            asset_type,
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

        // FR-1.1 (Round 4 F): emit V3 — no raw recipient/amount_tag/ca_payload_hash on chain.
        event::emit(WithdrawEventV3 {
            root,
            nullifier_hash,
            recipient_hash,
            request_hash,
            vault_sequence,
        });
    }

    public entry fun withdraw_step2a_eunoma_verify_v3(
        relayer: &signer,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingWithdrawFinalizationsV3, PendingWithdrawPayloadsV2, PendingWithdrawPayloadsV3, PendingWithdrawProofsV2, PendingWithdrawProofsV2b, PendingWithdrawProofsV3, PendingWithdrawProofsV3b, PendingWithdrawAttestationsV2, PendingWithdrawAttestationsV2b, PendingWithdrawAttestationsV3, DeoperatorConfigV2, VaultPublicInputsV2, PreparedWithdrawProofVK, CircuitVersionsHashCacheV2 {
        assert_initialized();
        assert!(exists<PendingWithdrawFinalizationsV3>(@eunoma), E_NOT_INITIALIZED);
        assert_not_expired(expiry_secs);
        assert_6_withdraw_hashes(&root, &nullifier_hash, &recipient_hash, &amount_tag, &ca_payload_hash, &request_hash);

        let tables = borrow_global<BridgeVaultTablesV2>(@eunoma);
        assert!(known_root_recorded_with_tables(tables, &root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables(tables, &nullifier_hash), E_NULLIFIER_ALREADY_SPENT);

        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        assert!(vault.vault_sequence == vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let vault_addr = vault.vault_addr;
        let asset_type = vault.asset_type;
        let asset_type_addr = object::object_address(&asset_type);
        let expected_recipient_hash = derive_recipient_hash(recipient);
        assert!(expected_recipient_hash == recipient_hash, E_RECIPIENT_HASH_MISMATCH);

        let amount_p_digest = consume_prepared_withdraw_payload_digest(&request_hash, &ca_payload_hash);
        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        let circuit_versions_hash = get_or_compute_circuit_versions_hash(cfg);
        let empty_signature: vector<u8> = vector[];
        let empty_fallback_signatures: vector<vector<u8>> = vector[];
        consume_or_verify_withdraw_attestation(
            &root,
            &nullifier_hash,
            recipient,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            expiry_secs,
            empty_signature,
            0,
            empty_fallback_signatures,
            cfg,
            vault_addr,
            asset_type_addr,
            &circuit_versions_hash,
        );

        let asset_id = borrow_global<VaultPublicInputsV2>(@eunoma).asset_id_fr;
        let empty_proof: vector<u8> = vector[];
        consume_or_verify_withdraw_proof(
            &root,
            &nullifier_hash,
            &asset_id,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            &amount_p_digest,
            empty_proof,
        );

        let sender_addr = signer::address_of(relayer);
        let key = compose_pending_key(sender_addr, &request_hash);
        let pending = borrow_global_mut<PendingWithdrawFinalizationsV3>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&key),
            E_PENDING_WITHDRAW_FINALIZATION,
        );
        table::add(&mut pending.by_request_hash, key, PendingWithdrawFinalizationV3 {
            sender: sender_addr,
            root,
            nullifier_hash,
            recipient,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            request_hash,
            vault_sequence,
            expiry_secs,
        });
    }

    public entry fun withdraw_step2b_invoke_framework_v3(
        relayer: &signer,
        request_hash: vector<u8>,
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
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingWithdrawFinalizationsV3 {
        assert_initialized();
        assert_hash(&request_hash);

        let sender_addr = signer::address_of(relayer);
        let key = compose_pending_key(sender_addr, &request_hash);
        let pending = borrow_global_mut<PendingWithdrawFinalizationsV3>(@eunoma);
        assert!(table::contains(&pending.by_request_hash, *&key), E_NO_PENDING_FINALIZATION);
        let entry = table::remove(&mut pending.by_request_hash, key);
        assert!(sender_addr == entry.sender, E_NOT_WITHDRAW_OWNER);
        assert!(&entry.request_hash == &request_hash, E_NO_PENDING_FINALIZATION);
        assert_not_expired(entry.expiry_secs);

        let tables = borrow_global_mut<BridgeVaultTablesV2>(@eunoma);
        assert!(known_root_recorded_with_tables(tables, &entry.root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables(tables, &entry.nullifier_hash), E_NULLIFIER_ALREADY_SPENT);

        let vault = borrow_global_mut<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        assert!(vault.vault_sequence == entry.vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let asset_type = vault.asset_type;
        let computed_hash = ca_payload_hash_to_fr_safe(hash_confidential_transfer_payload_v2(
            &asset_type,
            &entry.recipient,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        ));
        assert!(&computed_hash == &entry.ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);

        let vault_signer = account::create_signer_with_capability(&vault.vault_signer_cap);
        mark_nullifier_used_with_tables(tables, *&entry.nullifier_hash);
        vault.vault_sequence = vault.vault_sequence + 1;

        confidential_asset::confidential_transfer_raw(
            &vault_signer,
            asset_type,
            entry.recipient,
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

        event::emit(WithdrawEventV3 {
            root: entry.root,
            nullifier_hash: entry.nullifier_hash,
            recipient_hash: entry.recipient_hash,
            request_hash: entry.request_hash,
            vault_sequence: entry.vault_sequence,
        });
    }

    public entry fun operator_rollover_vault_pending_v2(
        operator: &signer,
    ) acquires BridgeVault {
        assert_admin(operator);
        let (vault_signer, asset_type) = vault_signer_and_asset_type();
        confidential_asset::rollover_pending_balance(&vault_signer, asset_type);
    }

    // R7-OPS-2: delegate-signed rollover. Same effect as operator_rollover_vault_pending_v2 but
    // the alpha-box operator (testnet-relayer addr, set as RecorderDelegate in OPS-1) signs
    // instead of admin — so a periodic systemd timer can keep deposits flowing pending→available
    // without admin key on the box. Auth gate is identical to record_known_root_v2_via_delegate
    // (delegate must match RecorderDelegate.addr). Strict scope: only triggers the CA framework's
    // own rollover for the bridge vault — cannot touch any other admin-controlled state.
    public entry fun operator_rollover_vault_pending_via_delegate(
        delegate: &signer,
    ) acquires RecorderDelegate, BridgeVault {
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global<RecorderDelegate>(@eunoma);
        assert!(signer::address_of(delegate) == rd.addr, E_NOT_RECORDER_DELEGATE);
        let (vault_signer, asset_type) = vault_signer_and_asset_type();
        confidential_asset::rollover_pending_balance(&vault_signer, asset_type);
    }

    public entry fun operator_normalize_vault_balance_v2(
        operator: &signer,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_aud: vector<vector<u8>>,
        zkrp_new_balance: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
    ) acquires BridgeVault {
        assert_admin(operator);
        let (vault_signer, asset_type) = vault_signer_and_asset_type();
        confidential_asset::normalize_raw(
            &vault_signer,
            asset_type,
            new_balance_p,
            new_balance_r,
            new_balance_r_aud,
            zkrp_new_balance,
            sigma_proto_comm,
            sigma_proto_resp,
        );
    }

    public entry fun operator_normalize_vault_balance_via_delegate(
        delegate: &signer,
        new_balance_p: vector<vector<u8>>,
        new_balance_r: vector<vector<u8>>,
        new_balance_r_aud: vector<vector<u8>>,
        zkrp_new_balance: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>,
    ) acquires BridgeVault, RecorderDelegate {
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global<RecorderDelegate>(@eunoma);
        assert!(signer::address_of(delegate) == rd.addr, E_NOT_RECORDER_DELEGATE);
        let (vault_signer, asset_type) = vault_signer_and_asset_type();
        confidential_asset::normalize_raw(
            &vault_signer,
            asset_type,
            new_balance_p,
            new_balance_r,
            new_balance_r_aud,
            zkrp_new_balance,
            sigma_proto_comm,
            sigma_proto_resp,
        );
    }

    public entry fun init_pending_deposit_bindings_v2(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingDepositBindingsV2>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingDepositBindingsV2 {
            by_commitment: table::new<vector<u8>, PendingDepositBindingV2>(),
        });
    }

    // N1 (gas opt): one-time admin migration after publish, populates V3 cache table.
    // Idempotent via E_ALREADY_INITIALIZED. Must run before first deposit post-upgrade.
    public entry fun init_pending_deposit_bindings_v3(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingDepositBindingsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingDepositBindingsV3 {
            by_commitment: table::new<vector<u8>, PendingDepositBindingV3>(),
        });
    }

    // R6-Plan-B: admin init for split-tx pending finalizations table. One-time,
    // idempotent. Must run before first deposit_step2a_eunoma_verify call.
    public entry fun init_pending_deposit_finalizations_v3(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingDepositFinalizationsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingDepositFinalizationsV3 {
            by_commitment: table::new<vector<u8>, PendingDepositFinalizationV3>(),
        });
    }

    // R6-Plan-B: DEPRECATED in R7-W1. Original signature kept for Aptos backward-compat;
    // body neutered to no-op since R7-W1 composite (sender, commitment) keys make
    // commitment-only sweep meaningless (lookups always miss). Use
    // admin_evict_stale_pending_deposit_finalizations_v2 instead. Zero external callers
    // existed for this entry (codex round-1 grep confirmed).
    public entry fun admin_evict_stale_pending_deposit_finalizations(
        admin: &signer,
        _commitments: vector<vector<u8>>,
    ) acquires BridgeVault {
        assert_admin(admin);
        // Intentional no-op. Old single-key entries (pre-R7-W1) cannot exist — composite
        // key was the same migration so all PendingDeposit*V3 writes use compose_pending_key.
    }

    // R7-W1: composite-key sweep. Takes parallel `senders` + `commitments` arrays.
    // Both arrays must have equal length; mismatched lengths abort with E_BAD_HASH_LENGTH.
    // Frontend/operator monitors PendingDepositFinalizationsV3 expiries + calls this.
    public entry fun admin_evict_stale_pending_deposit_finalizations_v2(
        admin: &signer,
        senders: vector<address>,
        commitments: vector<vector<u8>>,
    ) acquires PendingDepositFinalizationsV3, BridgeVault {
        assert_admin(admin);
        let n = vector::length(&commitments);
        assert!(vector::length(&senders) == n, E_BAD_HASH_LENGTH);
        let pending = borrow_global_mut<PendingDepositFinalizationsV3>(@eunoma);
        let now = timestamp::now_seconds();
        let i = 0u64;
        while (i < n) {
            let s = *vector::borrow(&senders, i);
            let c = vector::borrow(&commitments, i);
            let key = compose_pending_key(s, c);
            if (table::contains(&pending.by_commitment, key)) {
                let entry_expiry = table::borrow(&pending.by_commitment, key).expiry_secs;
                if (entry_expiry < now) {
                    let _ = table::remove(&mut pending.by_commitment, key);
                };
            };
            i = i + 1;
        };
    }

    // C1 (gas opt): one-time admin migration after publish, seeds circuit_versions_hash cache
    // from current DeoperatorConfigV2. Idempotent via E_ALREADY_INITIALIZED.
    public entry fun init_circuit_versions_hash_cache_v2(
        admin: &signer,
    ) acquires BridgeVault, DeoperatorConfigV2 {
        assert_admin(admin);
        assert!(!exists<CircuitVersionsHashCacheV2>(@eunoma), E_ALREADY_INITIALIZED);
        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        let hash = circuit_versions_hash(cfg);
        move_to(admin, CircuitVersionsHashCacheV2 { hash });
    }

    public entry fun init_pending_withdraw_proofs_v2(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingWithdrawProofsV2>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawProofsV2 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawProofV2>(),
        });
    }

    public entry fun init_pending_withdraw_attestations_v2(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingWithdrawAttestationsV2>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawAttestationsV2 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawAttestationV2>(),
        });
    }

    public entry fun init_pending_withdraw_payloads_v2(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingWithdrawPayloadsV2>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawPayloadsV2 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawPayloadV2>(),
        });
    }

    // Round 4 WB2.E B — V3 cache admin migrations (one-shot per testnet deployment).
    // Mirror init_pending_deposit_bindings_v3 (round-1) pattern: idempotent guard +
    // narrow `acquires BridgeVault` (only assert_admin reads it).
    public entry fun init_pending_withdraw_proofs_v3(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingWithdrawProofsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawProofsV3 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawProofV3>(),
        });
    }

    // Round 5 Wave E.2 (P06-1) — admin init for V2b proof cache (no asset_id field).
    public entry fun init_pending_withdraw_proofs_v2b(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingWithdrawProofsV2b>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawProofsV2b {
            by_request_hash: table::new<vector<u8>, PendingWithdrawProofV2b>(),
        });
    }

    // Round 5 Wave E.5 (R5-R) — admin init for V3b proof cache (7 explicit fields).
    public entry fun init_pending_withdraw_proofs_v3b(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingWithdrawProofsV3b>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawProofsV3b {
            by_request_hash: table::new<vector<u8>, PendingWithdrawProofV3b>(),
        });
    }

    public entry fun init_pending_withdraw_attestations_v3(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingWithdrawAttestationsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawAttestationsV3 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawAttestationV3>(),
        });
    }

    // Round 5 Wave E.1 (R5-D) — admin init for V2b attestation cache.
    public entry fun init_pending_withdraw_attestations_v2b(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingWithdrawAttestationsV2b>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawAttestationsV2b {
            by_request_hash: table::new<vector<u8>, PendingWithdrawAttestationV2b>(),
        });
    }

    public entry fun init_pending_withdraw_payloads_v3(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingWithdrawPayloadsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawPayloadsV3 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawPayloadV3>(),
        });
    }

    public entry fun init_pending_withdraw_finalizations_v3(
        admin: &signer,
    ) acquires BridgeVault {
        assert_admin(admin);
        assert!(!exists<PendingWithdrawFinalizationsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingWithdrawFinalizationsV3 {
            by_request_hash: table::new<vector<u8>, PendingWithdrawFinalizationV3>(),
        });
    }

    public entry fun prepare_deposit_binding_v2(
        _sender: &signer,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        amount_p: vector<vector<u8>>,
        deposit_binding_proof: vector<u8>,
    ) acquires PendingDepositBindingsV2, PreparedDepositBindingVK, VaultPublicInputsV2 {
        assert_initialized();
        assert_hash(&commitment);
        assert_hash(&amount_tag);
        assert!(exists<PendingDepositBindingsV2>(@eunoma), E_NOT_INITIALIZED);
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p);
        assert_valid_deposit_binding_proof(
            &commitment,
            &amount_tag,
            &amount_p_digest,
            deposit_binding_proof,
        );
        let pending = borrow_global_mut<PendingDepositBindingsV2>(@eunoma);
        assert!(!table::contains(&pending.by_commitment, *&commitment), E_PENDING_DEPOSIT_BINDING);
        table::add(&mut pending.by_commitment, commitment, PendingDepositBindingV2 {
            amount_tag,
            amount_p_digest,
        });
    }

    public entry fun prepare_deposit_binding_v3(
        sender: &signer,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        amount_p: vector<vector<u8>>,
        deposit_binding_proof: vector<u8>,
    ) acquires PendingDepositBindingsV3, VaultPublicInputsV2, PreparedDepositBindingVK {
        prepare_deposit_binding_v3_for_user(
            sender,
            signer::address_of(sender),
            commitment,
            amount_tag,
            amount_p,
            deposit_binding_proof,
        );
    }

    // Deposit re-key: additive prepare entry with explicit user_addr. Writes V3 cache table under
    // user_addr so the relayer can pre-run this proof on the depositor's behalf without changing
    // the already-published prepare_deposit_binding_v3 ABI.
    public entry fun prepare_deposit_binding_v3_for_user(
        _relayer: &signer,
        user_addr: address,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        amount_p: vector<vector<u8>>,
        deposit_binding_proof: vector<u8>,
    ) acquires PendingDepositBindingsV3, VaultPublicInputsV2, PreparedDepositBindingVK {
        assert_initialized();
        assert_hash(&commitment);
        assert_hash(&amount_tag);
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p);
        assert_valid_deposit_binding_proof(
            &commitment,
            &amount_tag,
            &amount_p_digest,
            deposit_binding_proof,
        );
        // R7-W1: composite (user_addr, commitment) key prevents squat-DoS by adversary
        // pre-occupying victim's commitment slot while still allowing relayer submission.
        let key = compose_pending_key(user_addr, &commitment);
        let pending = borrow_global_mut<PendingDepositBindingsV3>(@eunoma);
        assert!(!table::contains(&pending.by_commitment, *&key), E_PENDING_DEPOSIT_BINDING);
        table::add(&mut pending.by_commitment, key, PendingDepositBindingV3 {
            amount_tag,
            amount_p_digest,
            amount_p,
        });
    }

    public entry fun prepare_withdraw_proof_v2(
        _sender: &signer,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        amount_p: vector<vector<u8>>,
        withdraw_proof: vector<u8>,
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingWithdrawProofsV2b, PreparedWithdrawProofVK, VaultPublicInputsV2 {
        assert_initialized();
        // R5-P (Wave G.2): inlined 6-hash assertion block.
        assert_6_withdraw_hashes(&root, &nullifier_hash, &recipient_hash, &amount_tag, &ca_payload_hash, &request_hash);
        // Round 5 Wave E.2 (P06-1): write target migrated V2 → V2b (drops asset_id field;
        // consume re-reads from VaultPublicInputsV2 — safe because asset_type is immutable
        // post-V2-bootstrap).
        assert!(exists<PendingWithdrawProofsV2b>(@eunoma), E_NOT_INITIALIZED);
        // R5-B (Round 5 Wave B): hoist duplicate-pending check BEFORE Groth16 verify.
        {
            let pending_chk = borrow_global<PendingWithdrawProofsV2b>(@eunoma);
            assert!(!table::contains(&pending_chk.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_PROOF);
        };
        // FR-4.1: single borrow_global<BridgeVaultTablesV2> for root + nullifier check.
        let tables = borrow_global<BridgeVaultTablesV2>(@eunoma);
        assert!(known_root_recorded_with_tables(tables, &root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables(tables, &nullifier_hash), E_NULLIFIER_ALREADY_SPENT);
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        assert!(vault.vault_sequence == vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let asset_id = borrow_global<VaultPublicInputsV2>(@eunoma).asset_id_fr;
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p);
        assert_valid_withdraw_proof(
            &root,
            &nullifier_hash,
            &asset_id,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            &amount_p_digest,
            withdraw_proof,
        );
        let pending = borrow_global_mut<PendingWithdrawProofsV2b>(@eunoma);
        assert!(!table::contains(&pending.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_PROOF);
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawProofV2b {
            root,
            nullifier_hash,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            vault_sequence,
            amount_p_digest,
        });
    }

    // Round 5 Wave E.5 (R5-R) — prepare writes V3b (7 fields, no msg_hash, no asset_id).
    // Consume uses field-by-field equality instead of keccak. The cross-stage payload
    // reader (prepare_withdraw_payload_v3) still finds ca_payload_hash + amount_p_digest
    // because V3b retains both — codex guard for the FR-4.6 P0 hotfix is preserved.
    public entry fun prepare_withdraw_proof_v3(
        _sender: &signer,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        amount_p: vector<vector<u8>>,
        withdraw_proof: vector<u8>,
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingWithdrawProofsV3b, PreparedWithdrawProofVK, VaultPublicInputsV2 {
        assert_initialized();
        // R5-P (Wave G.2): inlined 6-hash assertion block.
        assert_6_withdraw_hashes(&root, &nullifier_hash, &recipient_hash, &amount_tag, &ca_payload_hash, &request_hash);
        // Round 5 Wave E.5 (R5-R): write target migrated V3 → V3b (field-by-field cache).
        assert!(exists<PendingWithdrawProofsV3b>(@eunoma), E_NOT_INITIALIZED);
        // R5-B (Round 5 Wave B): hoist duplicate-pending check BEFORE Groth16 verify.
        {
            let pending_chk = borrow_global<PendingWithdrawProofsV3b>(@eunoma);
            assert!(!table::contains(&pending_chk.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_PROOF);
        };
        // FR-4.1: single borrow_global<BridgeVaultTablesV2> for root + nullifier check.
        let tables = borrow_global<BridgeVaultTablesV2>(@eunoma);
        assert!(known_root_recorded_with_tables(tables, &root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables(tables, &nullifier_hash), E_NULLIFIER_ALREADY_SPENT);
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        assert!(vault.vault_sequence == vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let asset_id = borrow_global<VaultPublicInputsV2>(@eunoma).asset_id_fr;
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p);
        assert_valid_withdraw_proof(
            &root,
            &nullifier_hash,
            &asset_id,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            &amount_p_digest,
            withdraw_proof,
        );
        let pending = borrow_global_mut<PendingWithdrawProofsV3b>(@eunoma);
        assert!(!table::contains(&pending.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_PROOF);
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawProofV3b {
            root,
            nullifier_hash,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            vault_sequence,
            amount_p_digest,
        });
    }

    public entry fun prepare_withdraw_attestation_v2(
        _sender: &signer,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingWithdrawAttestationsV2b, DeoperatorConfigV2, CircuitVersionsHashCacheV2 {
        assert_initialized();
        assert_not_expired(expiry_secs);
        // R5-P (Wave G.2): inlined 6-hash assertion block.
        assert_6_withdraw_hashes(&root, &nullifier_hash, &recipient_hash, &amount_tag, &ca_payload_hash, &request_hash);
        // Round 5 Wave E.1 (R5-D): write target migrated V2 → V2b (msg_hash-only cache).
        // In-flight V2 entries from pre-Round-5 deploys still drain via consume V2 branch.
        assert!(exists<PendingWithdrawAttestationsV2b>(@eunoma), E_NOT_INITIALIZED);
        // R5-B (Round 5 Wave B): hoist duplicate-pending check BEFORE BCS + ed25519 verify.
        {
            let pending_chk = borrow_global<PendingWithdrawAttestationsV2b>(@eunoma);
            assert!(!table::contains(&pending_chk.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_ATTESTATION);
        };
        // FR-4.1: single borrow_global<BridgeVaultTablesV2> for root + nullifier check
        // (collapses 2 borrows -> 1 in each of the 4 prepare_withdraw_* entries).
        let tables = borrow_global<BridgeVaultTablesV2>(@eunoma);
        assert!(known_root_recorded_with_tables(tables, &root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables(tables, &nullifier_hash), E_NULLIFIER_ALREADY_SPENT);
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        assert!(vault.vault_sequence == vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let vault_addr = vault.vault_addr;
        let asset_type = vault.asset_type;
        // FR-1.5(a) Round 4 F: entry-level derive_recipient_hash check dropped here —
        // recipient + recipient_hash are bound cryptographically inside the FROST-signed
        // WithdrawAttestationV2Message and re-bound on cache-hit at consume_or_verify_
        // withdraw_attestation V2 branch / V2b + V3 msg_hash branches. Top-level
        // withdraw_to_recipient_v2 entry still enforces derive at line ~882-883.

        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        // A6 gas opt: use cached circuit_versions_hash via defensive helper.
        let versions_hash = get_or_compute_circuit_versions_hash(cfg);
        let asset_type_addr = object::object_address(&asset_type);
        // R5-C (Round 5 Wave C): struct-free BCS via serializer helper. Byte-identical
        // to bcs::to_bytes(&WithdrawAttestationV2Message{...}).
        let msg_bytes = serialize_withdraw_attestation_v2_msg(
            &DOMAIN_WITHDRAW_V2,
            chain_id::get(),
            @eunoma,
            vault_addr,
            asset_type_addr,
            cfg.operator_set_version,
            cfg.dkg_epoch,
            &cfg.roster_hash,
            &cfg.frost_group_pubkey,
            &root,
            &nullifier_hash,
            recipient,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            expiry_secs,
            &versions_hash,
        );
        assert_deop_attestation_v2(
            &msg_bytes,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
        );
        // Round 5 Wave E.1 (R5-D): compact V2b write — keccak256(msg_bytes) replaces 15-field
        // struct (~570B → 32B). Cache-hit reader recomputes msg_bytes via
        // serialize_withdraw_attestation_v2_msg + keccak256 and asserts equality.
        let msg_hash = aptos_hash::keccak256(msg_bytes);
        let pending = borrow_global_mut<PendingWithdrawAttestationsV2b>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_ATTESTATION,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawAttestationV2b {
            msg_hash,
        });
    }

    // Round 4 WB2.E B — V3 prepare entry for withdraw attestation. msg_hash-only cache
    // (32B vs ~600B V2). msg_bytes computed identically to V2 path so the cache-hit reader
    // can recompute byte-identically. Reuses bcs::to_bytes(&WithdrawAttestationV2Message)
    // because the FROST sig is over that exact byte form — DO NOT change struct shape.
    public entry fun prepare_withdraw_attestation_v3(
        _sender: &signer,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
    ) acquires BridgeVault, BridgeVaultTablesV2, PendingWithdrawAttestationsV3, DeoperatorConfigV2, CircuitVersionsHashCacheV2 {
        assert_initialized();
        assert_not_expired(expiry_secs);
        // R5-P (Wave G.2): inlined 6-hash assertion block.
        assert_6_withdraw_hashes(&root, &nullifier_hash, &recipient_hash, &amount_tag, &ca_payload_hash, &request_hash);
        assert!(exists<PendingWithdrawAttestationsV3>(@eunoma), E_NOT_INITIALIZED);
        // R5-B (Round 5 Wave B): hoist duplicate-pending check BEFORE BCS + ed25519 verify.
        {
            let pending_chk = borrow_global<PendingWithdrawAttestationsV3>(@eunoma);
            assert!(!table::contains(&pending_chk.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_ATTESTATION);
        };
        // FR-4.1: single borrow_global<BridgeVaultTablesV2> for root + nullifier check
        // (collapses 2 borrows -> 1 in each of the 4 prepare_withdraw_* entries).
        let tables = borrow_global<BridgeVaultTablesV2>(@eunoma);
        assert!(known_root_recorded_with_tables(tables, &root), E_INVALID_ROOT);
        assert!(!nullifier_used_with_tables(tables, &nullifier_hash), E_NULLIFIER_ALREADY_SPENT);
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        assert!(vault.vault_sequence == vault_sequence, E_VAULT_SEQUENCE_MISMATCH);
        let vault_addr = vault.vault_addr;
        let asset_type = vault.asset_type;
        // FR-1.5(a) Round 4 F: entry-level derive_recipient_hash check dropped here —
        // see prepare_withdraw_attestation_v2 sibling comment for the rationale (same
        // V3 cache-hit msg_hash bind at consume_or_verify_withdraw_attestation
        // line ~2579 + top-level withdraw_to_recipient_v2 enforcement at line ~882-883).

        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        let versions_hash = get_or_compute_circuit_versions_hash(cfg);
        // R5-C (Round 5 Wave C): struct-free BCS via serializer helper.
        let msg_bytes = serialize_withdraw_attestation_v2_msg(
            &DOMAIN_WITHDRAW_V2,
            chain_id::get(),
            @eunoma,
            vault_addr,
            object::object_address(&asset_type),
            cfg.operator_set_version,
            cfg.dkg_epoch,
            &cfg.roster_hash,
            &cfg.frost_group_pubkey,
            &root,
            &nullifier_hash,
            recipient,
            &recipient_hash,
            &amount_tag,
            &ca_payload_hash,
            &request_hash,
            vault_sequence,
            expiry_secs,
            &versions_hash,
        );
        // FR-2.5: pass by ref (was `*&msg_bytes` clone before FR-2.5 — saves ~250B clone).
        assert_deop_attestation_v2(
            &msg_bytes,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
        );
        let msg_hash = aptos_hash::keccak256(msg_bytes);
        let pending = borrow_global_mut<PendingWithdrawAttestationsV3>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_ATTESTATION,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawAttestationV3 {
            msg_hash,
        });
    }

    public entry fun prepare_withdraw_payload_v2(
        _sender: &signer,
        recipient: address,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
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
    ) acquires BridgeVault, PendingWithdrawProofsV2, PendingWithdrawPayloadsV2 {
        assert_initialized();
        assert_hash(&ca_payload_hash);
        assert_hash(&request_hash);
        // R5-O.6 (Round 5 A.10.6): drop redundant `exists<>` guards. Native `borrow_global`
        // aborts on missing resource with stdlib MISSING_DATA; the explicit guards only add
        // a different error code. Both V2 pending tables are admin-init'd once and never
        // dropped; any uninit state is a deployment bug. Saves ~80-150 gas/prepare call.
        // R5-B (Round 5 Wave B): hoist duplicate-pending check BEFORE BCS+keccak hash.
        {
            let pending_chk = borrow_global<PendingWithdrawPayloadsV2>(@eunoma);
            assert!(!table::contains(&pending_chk.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_PAYLOAD);
        };
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        let asset_type = vault.asset_type;
        let computed_hash = ca_payload_hash_to_fr_safe(hash_confidential_transfer_payload_v2(
            &asset_type,
            &recipient,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        ));
        // R5-O.3 (Round 5 A.10.3): ref equality avoids implicit by-value copies of 32B vec.
        assert!(&computed_hash == &ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
        // R5-A REVERTED (codex Wave A review RED): keep the explicit recompute +
        // assert. The withdrawal circuit binds amount_p_digest as a public input but does
        // NOT recompute it from ca_payload_hash in-circuit, so removing the cross-check
        // here would allow an attacker to submit a proof claiming amount_p_digest_A while
        // settling a CA payload containing a different amount_p_B (vote conservation
        // violation / A6 binding break). FR-4.6 V3 sibling may carry the same gap — flag
        // for separate codex security review.
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p);
        let proofs = borrow_global<PendingWithdrawProofsV2>(@eunoma);
        assert!(table::contains(&proofs.by_request_hash, *&request_hash), E_INVALID_WITHDRAW_PROOF);
        let proof_cached = table::borrow(&proofs.by_request_hash, *&request_hash);
        assert!(&proof_cached.ca_payload_hash == &ca_payload_hash, E_INVALID_WITHDRAW_PROOF);
        assert!(proof_cached.amount_p_digest == amount_p_digest, E_INVALID_WITHDRAW_PROOF);
        let pending = borrow_global_mut<PendingWithdrawPayloadsV2>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_PAYLOAD,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawPayloadV2 {
            asset_type: object::object_address(&asset_type),
            recipient,
            ca_payload_hash,
            amount_p_digest,
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
        });
    }

    // Round 4 WB2.E B — V3 prepare entry for withdraw payload. msg_hash + amount_p_digest
    // 64B cache (vs ~600B V2 17-field mirror). msg_hash = ca_payload_hash_to_fr_safe(
    // hash_confidential_transfer_payload_v2(...)) — same computation as V2 path so
    // consume V3-branch reader recomputes byte-identically.
    //
    // FR-4.6 SHIPPED HERE: instead of compute_amount_p_digest_v2(&amount_p) (Compose8,
    // ~700-1500 gas), read proof_cached.amount_p_digest directly. Stage 1
    // prepare_withdraw_proof_v3 already Compose8'd this exact amount_p + Groth16-verified
    // it; reading the cached value is sound (cache key = request_hash binds the inputs).
    public entry fun prepare_withdraw_payload_v3(
        _sender: &signer,
        recipient: address,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
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
    ) acquires BridgeVault, PendingWithdrawProofsV3, PendingWithdrawProofsV3b, PendingWithdrawPayloadsV3 {
        assert_initialized();
        assert_hash(&ca_payload_hash);
        assert_hash(&request_hash);
        // R5-B (Round 5 Wave B): hoist duplicate-pending check BEFORE BCS+keccak hash.
        {
            let pending_chk = borrow_global<PendingWithdrawPayloadsV3>(@eunoma);
            assert!(!table::contains(&pending_chk.by_request_hash, *&request_hash), E_PENDING_WITHDRAW_PAYLOAD);
        };
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(!vault.paused, E_PAUSED);
        let asset_type = vault.asset_type;
        let computed_hash = ca_payload_hash_to_fr_safe(hash_confidential_transfer_payload_v2(
            &asset_type,
            &recipient,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        ));
        // R5-O.3 (Round 5 A.10.3): ref equality avoids implicit by-value copies of 32B vec.
        assert!(&computed_hash == &ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
        // Round 5 Wave E.5 (R5-R): cross-stage proof cache read — V3b first (new schema),
        // V3 fallback (in-flight pre-Round-5 entries). Both store ca_payload_hash +
        // amount_p_digest, so the P0 hotfix cross-stage check works against either.
        let (cached_ca_payload_hash, cached_amount_p_digest) =
            if (exists<PendingWithdrawProofsV3b>(@eunoma)
                && table::contains(
                    &borrow_global<PendingWithdrawProofsV3b>(@eunoma).by_request_hash,
                    *&request_hash,
                ))
            {
                let proofs_v3b = borrow_global<PendingWithdrawProofsV3b>(@eunoma);
                let pc = table::borrow(&proofs_v3b.by_request_hash, *&request_hash);
                (*&pc.ca_payload_hash, *&pc.amount_p_digest)
            } else {
                let proofs = borrow_global<PendingWithdrawProofsV3>(@eunoma);
                assert!(table::contains(&proofs.by_request_hash, *&request_hash), E_INVALID_WITHDRAW_PROOF);
                let pc = table::borrow(&proofs.by_request_hash, *&request_hash);
                (*&pc.ca_payload_hash, *&pc.amount_p_digest)
            };
        assert!(&cached_ca_payload_hash == &ca_payload_hash, E_INVALID_WITHDRAW_PROOF);
        // FR-4.6 REVERTED (Round 5 Wave A codex audit found this was a P0 vuln): the
        // circuit binds amount_p_digest as a public input but does NOT prove that
        // ca_payload_hash was built from the same amount_p. A prover at stage 1 could
        // submit (amount_p_A_witness, amount_p_digest_A_public, ca_payload_hash_for_B_public)
        // — Groth16 verifies. Then at stage 2 settle with amount_p_B + ca_payload_hash_for_B.
        // Without the explicit Compose8 recompute + assert below, the cache would serve
        // digest_A while the actual transfer uses amount_p_B (vote conservation /
        // A6 binding violation). Cost: ~700-1500 gas back. Trade is mandatory.
        let amount_p_digest = compute_amount_p_digest_v2(&amount_p);
        assert!(cached_amount_p_digest == amount_p_digest, E_INVALID_WITHDRAW_PROOF);
        let pending = borrow_global_mut<PendingWithdrawPayloadsV3>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_PAYLOAD,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawPayloadV3 {
            msg_hash: computed_hash,
            amount_p_digest,
        });
    }

    public fun get_vault_sequence_v2(): u64 acquires BridgeVault {
        borrow_global<BridgeVault>(@eunoma).vault_sequence
    }

    public fun get_vault_address_v2(): address acquires BridgeVault {
        borrow_global<BridgeVault>(@eunoma).vault_addr
    }

    public fun get_deoperator_config_v2(): (u64, u64, u64, vector<u8>, vector<u8>, vector<u8>)
    acquires DeoperatorConfigV2 {
        let cfg = borrow_global<DeoperatorConfigV2>(@eunoma);
        (
            cfg.operator_set_version,
            cfg.dkg_epoch,
            cfg.threshold,
            *&cfg.roster_hash,
            *&cfg.frost_group_pubkey,
            *&cfg.vault_ek,
        )
    }

    public fun is_nullifier_used_v2(nullifier_hash: vector<u8>): bool acquires BridgeVaultTablesV2 {
        nullifier_used(&nullifier_hash)
    }

    public entry fun publish_deposit_binding_vk_v2(
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
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<DepositBindingVK>(@eunoma), E_ALREADY_INITIALIZED);
        assert_g1(&alpha_g1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&beta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&gamma_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&delta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_0, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_3, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_4, E_INVALID_DEPOSIT_BINDING_PROOF);
        move_to(admin, DepositBindingVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4],
        });
    }

    public entry fun publish_deposit_binding_vk_v2_a6(
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
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<DepositBindingVK>(@eunoma), E_ALREADY_INITIALIZED);
        assert_g1(&alpha_g1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&beta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&gamma_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&delta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_0, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_3, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_4, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_5, E_INVALID_DEPOSIT_BINDING_PROOF);
        move_to(admin, DepositBindingVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5],
        });
    }

    public entry fun publish_prepared_deposit_binding_vk_v2(
        admin: &signer,
    ) acquires DepositBindingVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(exists<DepositBindingVK>(@eunoma), E_NOT_INITIALIZED);
        assert!(!exists<PreparedDepositBindingVK>(@eunoma), E_ALREADY_INITIALIZED);
        let vk = borrow_global<DepositBindingVK>(@eunoma);
        let alpha_g1 = de_g1(&vk.alpha_g1);
        let beta_g2 = de_g2(&vk.beta_g2);
        let gamma_g2 = de_g2(&vk.gamma_g2);
        let delta_g2 = de_g2(&vk.delta_g2);
        move_to(admin, PreparedDepositBindingVK {
            pvk_alpha_g1_beta_g2_fq12: pairing_fq12_bytes(&alpha_g1, &beta_g2),
            pvk_gamma_g2_neg: neg_g2_bytes(&gamma_g2),
            pvk_delta_g2_neg: neg_g2_bytes(&delta_g2),
            pvk_uvw_gamma_g1: vk.ic,
        });
    }

    /// V2 deposit-binding VK rotation. Admin-only. Idempotent over presence of the
    /// existing resource: if a DepositBindingVK is already published, it is dropped
    /// FIRST (along with any cached PreparedDepositBindingVK), and the new VK is moved
    /// in. After this entry runs, the admin MUST call
    /// `rotate_prepared_deposit_binding_vk_v2` to refresh the cached prepared VK.
    /// Required when the trusted-setup zkey is regenerated and the on-chain VK no
    /// longer matches the proving key. Hard invariants unchanged: no plaintext
    /// witness, no centralized dk/inverse, no 5-of-7 weakening.
    public entry fun rotate_deposit_binding_vk_v2(
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
    ) acquires DepositBindingVK, PreparedDepositBindingVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        if (exists<PreparedDepositBindingVK>(@eunoma)) {
            let PreparedDepositBindingVK {
                pvk_alpha_g1_beta_g2_fq12: _,
                pvk_gamma_g2_neg: _,
                pvk_delta_g2_neg: _,
                pvk_uvw_gamma_g1: _,
            } = move_from<PreparedDepositBindingVK>(@eunoma);
        };
        if (exists<DepositBindingVK>(@eunoma)) {
            let DepositBindingVK {
                alpha_g1: _,
                beta_g2: _,
                gamma_g2: _,
                delta_g2: _,
                ic: _,
            } = move_from<DepositBindingVK>(@eunoma);
        };
        assert_g1(&alpha_g1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&beta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&gamma_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&delta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_0, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_3, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_4, E_INVALID_DEPOSIT_BINDING_PROOF);
        move_to(admin, DepositBindingVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4],
        });
    }

    /// A6 deposit-binding VK rotation. Added as a compatible sidecar because
    /// the deployed testnet package cannot change existing public signatures.
    public entry fun rotate_deposit_binding_vk_v2_a6(
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
    ) acquires DepositBindingVK, PreparedDepositBindingVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        if (exists<PreparedDepositBindingVK>(@eunoma)) {
            let PreparedDepositBindingVK {
                pvk_alpha_g1_beta_g2_fq12: _,
                pvk_gamma_g2_neg: _,
                pvk_delta_g2_neg: _,
                pvk_uvw_gamma_g1: _,
            } = move_from<PreparedDepositBindingVK>(@eunoma);
        };
        if (exists<DepositBindingVK>(@eunoma)) {
            let DepositBindingVK {
                alpha_g1: _,
                beta_g2: _,
                gamma_g2: _,
                delta_g2: _,
                ic: _,
            } = move_from<DepositBindingVK>(@eunoma);
        };
        assert_g1(&alpha_g1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&beta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&gamma_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g2(&delta_g2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_0, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_1, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_2, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_3, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_4, E_INVALID_DEPOSIT_BINDING_PROOF);
        assert_g1(&ic_5, E_INVALID_DEPOSIT_BINDING_PROOF);
        move_to(admin, DepositBindingVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5],
        });
    }

    /// V2 prepared deposit-binding VK rotation. Admin-only. Drops any cached
    /// PreparedDepositBindingVK and re-derives it from the currently-published
    /// DepositBindingVK. Call this AFTER `rotate_deposit_binding_vk_v2` so
    /// `assert_valid_deposit_binding_proof` consumes the refreshed pairing cache.
    public entry fun rotate_prepared_deposit_binding_vk_v2(
        admin: &signer,
    ) acquires DepositBindingVK, PreparedDepositBindingVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(exists<DepositBindingVK>(@eunoma), E_NOT_INITIALIZED);
        if (exists<PreparedDepositBindingVK>(@eunoma)) {
            let PreparedDepositBindingVK {
                pvk_alpha_g1_beta_g2_fq12: _,
                pvk_gamma_g2_neg: _,
                pvk_delta_g2_neg: _,
                pvk_uvw_gamma_g1: _,
            } = move_from<PreparedDepositBindingVK>(@eunoma);
        };
        let vk = borrow_global<DepositBindingVK>(@eunoma);
        let alpha_g1 = de_g1(&vk.alpha_g1);
        let beta_g2 = de_g2(&vk.beta_g2);
        let gamma_g2 = de_g2(&vk.gamma_g2);
        let delta_g2 = de_g2(&vk.delta_g2);
        move_to(admin, PreparedDepositBindingVK {
            pvk_alpha_g1_beta_g2_fq12: pairing_fq12_bytes(&alpha_g1, &beta_g2),
            pvk_gamma_g2_neg: neg_g2_bytes(&gamma_g2),
            pvk_delta_g2_neg: neg_g2_bytes(&delta_g2),
            pvk_uvw_gamma_g1: vk.ic,
        });
    }

    public entry fun publish_withdraw_proof_vk_v2(
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
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<WithdrawProofVK>(@eunoma), E_ALREADY_INITIALIZED);
        assert_g1(&alpha_g1, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&beta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&gamma_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&delta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_0, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_1, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_3, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_4, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_5, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_6, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_7, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_8, E_INVALID_WITHDRAW_PROOF);
        move_to(admin, WithdrawProofVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5, ic_6, ic_7, ic_8],
        });
    }

    public entry fun publish_withdraw_proof_vk_v2_a6(
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
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<WithdrawProofVK>(@eunoma), E_ALREADY_INITIALIZED);
        assert_g1(&alpha_g1, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&beta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&gamma_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&delta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_0, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_1, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_3, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_4, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_5, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_6, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_7, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_8, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_9, E_INVALID_WITHDRAW_PROOF);
        move_to(admin, WithdrawProofVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5, ic_6, ic_7, ic_8, ic_9],
        });
    }

    public entry fun publish_prepared_withdraw_proof_vk_v2(
        admin: &signer,
    ) acquires WithdrawProofVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(exists<WithdrawProofVK>(@eunoma), E_NOT_INITIALIZED);
        assert!(!exists<PreparedWithdrawProofVK>(@eunoma), E_ALREADY_INITIALIZED);
        let vk = borrow_global<WithdrawProofVK>(@eunoma);
        let alpha_g1 = de_g1(&vk.alpha_g1);
        let beta_g2 = de_g2(&vk.beta_g2);
        let gamma_g2 = de_g2(&vk.gamma_g2);
        let delta_g2 = de_g2(&vk.delta_g2);
        move_to(admin, PreparedWithdrawProofVK {
            pvk_alpha_g1_beta_g2_fq12: pairing_fq12_bytes(&alpha_g1, &beta_g2),
            pvk_gamma_g2_neg: neg_g2_bytes(&gamma_g2),
            pvk_delta_g2_neg: neg_g2_bytes(&delta_g2),
            pvk_uvw_gamma_g1: vk.ic,
        });
    }

    /// V2 withdraw-proof VK rotation. Admin-only. Mirrors
    /// `rotate_deposit_binding_vk_v2`: drop any stale prepared cache first,
    /// replace the raw VK, then call `rotate_prepared_withdraw_proof_vk_v2`.
    public entry fun rotate_withdraw_proof_vk_v2_a6(
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
    ) acquires WithdrawProofVK, PreparedWithdrawProofVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        if (exists<PreparedWithdrawProofVK>(@eunoma)) {
            let PreparedWithdrawProofVK {
                pvk_alpha_g1_beta_g2_fq12: _,
                pvk_gamma_g2_neg: _,
                pvk_delta_g2_neg: _,
                pvk_uvw_gamma_g1: _,
            } = move_from<PreparedWithdrawProofVK>(@eunoma);
        };
        if (exists<WithdrawProofVK>(@eunoma)) {
            let WithdrawProofVK {
                alpha_g1: _,
                beta_g2: _,
                gamma_g2: _,
                delta_g2: _,
                ic: _,
            } = move_from<WithdrawProofVK>(@eunoma);
        };
        assert_g1(&alpha_g1, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&beta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&gamma_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g2(&delta_g2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_0, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_1, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_2, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_3, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_4, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_5, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_6, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_7, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_8, E_INVALID_WITHDRAW_PROOF);
        assert_g1(&ic_9, E_INVALID_WITHDRAW_PROOF);
        move_to(admin, WithdrawProofVK {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: vector[ic_0, ic_1, ic_2, ic_3, ic_4, ic_5, ic_6, ic_7, ic_8, ic_9],
        });
    }

    /// V2 prepared withdraw-proof VK rotation. Admin-only. Drops only the
    /// prepared cache and re-derives it from the currently-published raw VK.
    public entry fun rotate_prepared_withdraw_proof_vk_v2(
        admin: &signer,
    ) acquires WithdrawProofVK, PreparedWithdrawProofVK {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(exists<WithdrawProofVK>(@eunoma), E_NOT_INITIALIZED);
        if (exists<PreparedWithdrawProofVK>(@eunoma)) {
            let PreparedWithdrawProofVK {
                pvk_alpha_g1_beta_g2_fq12: _,
                pvk_gamma_g2_neg: _,
                pvk_delta_g2_neg: _,
                pvk_uvw_gamma_g1: _,
            } = move_from<PreparedWithdrawProofVK>(@eunoma);
        };
        let vk = borrow_global<WithdrawProofVK>(@eunoma);
        let alpha_g1 = de_g1(&vk.alpha_g1);
        let beta_g2 = de_g2(&vk.beta_g2);
        let gamma_g2 = de_g2(&vk.gamma_g2);
        let delta_g2 = de_g2(&vk.delta_g2);
        move_to(admin, PreparedWithdrawProofVK {
            pvk_alpha_g1_beta_g2_fq12: pairing_fq12_bytes(&alpha_g1, &beta_g2),
            pvk_gamma_g2_neg: neg_g2_bytes(&gamma_g2),
            pvk_delta_g2_neg: neg_g2_bytes(&delta_g2),
            pvk_uvw_gamma_g1: vk.ic,
        });
    }

    fun assert_initialized() {
        assert!(exists<BridgeVault>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<DeoperatorConfigV2>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<BridgeVaultTablesV2>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<CircuitVersionsHashCacheV2>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<PendingDepositBindingsV3>(@eunoma), E_NOT_INITIALIZED);
    }

    fun assert_admin(admin: &signer) acquires BridgeVault {
        let vault = borrow_global<BridgeVault>(@eunoma);
        assert!(signer::address_of(admin) == vault.admin, E_NOT_ADMIN);
    }

    fun vault_signer_and_asset_type(): (signer, Object<fungible_asset::Metadata>) acquires BridgeVault {
        let vault = borrow_global<BridgeVault>(@eunoma);
        (
            account::create_signer_with_capability(&vault.vault_signer_cap),
            vault.asset_type,
        )
    }

    // Round 4 WB2.E C / FR-2.5: message_bytes by-ref. Body's two consumers already take &:
    // ed25519::signature_verify_strict takes a `message: vector<u8>` by-value but we only need
    // one `*message_bytes` deref there; assert_valid_fallback_attestation already takes &.
    // Net: 1 ~250B msg_bytes clone eliminated at every caller (4 prepare/consume sites).
    fun assert_deop_attestation_v2(
        message_bytes: &vector<u8>,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
        cfg: &DeoperatorConfigV2,
    ) {
        if (vector::length(&group_signature) > 0) {
            // R6-C.3: drop explicit ED25519_SIGNATURE_BYTES check — ed25519::new_signature_from_bytes
            // already asserts len == SIGNATURE_NUM_BYTES (stdlib ed25519.move:91). Mirrors R5-N
            // fallback-path pattern. Saves 1 vector::length call on happy path; wrong-length
            // sigs still abort, error code shifts from E_INVALID_DEOP_SIGNATURE → stdlib
            // invalid_argument (acceptable per R5-N precedent).
            let ok = ed25519::signature_verify_strict(
                &ed25519::new_signature_from_bytes(group_signature),
                &ed25519::new_unvalidated_public_key_from_bytes(*&cfg.frost_group_pubkey),
                *message_bytes,
            );
            assert!(ok, E_INVALID_DEOP_SIGNATURE);
        } else {
            assert_valid_fallback_attestation(
                message_bytes,
                fallback_bitmap,
                &fallback_signatures,
                cfg,
            );
        }
    }

    fun assert_valid_fallback_attestation(
        message_bytes: &vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: &vector<vector<u8>>,
        cfg: &DeoperatorConfigV2,
    ) {
        assert!(vector::length(fallback_signatures) == MAX_DEOPERATORS, E_TOO_FEW_DEOP_SIGNATURES);
        // Round 5 Wave F.1 (R5-S): popcount(fallback_bitmap) pre-loop guard. Aborts at
        // ~60 gas if fewer than `cfg.threshold` bits are set, skipping ~25-35k gas worth
        // of ed25519 sig verifies on patently insufficient bitmaps. Semantics preserved:
        // the loop below STILL runs all 7 iterations and verifies every non-empty slot,
        // and the final valid_count threshold check at the bottom is unchanged.
        {
            let popcount = 0u64;
            let bi = 0u64;
            while (bi < MAX_DEOPERATORS) {
                if (bit_is_set(fallback_bitmap, bi)) {
                    popcount = popcount + 1;
                };
                bi = bi + 1;
            };
            assert!(popcount >= cfg.threshold, E_TOO_FEW_DEOP_SIGNATURES);
        };
        let valid_count = 0;
        let i = 0;
        while (i < MAX_DEOPERATORS) {
            let sig = vector::borrow(fallback_signatures, i);
            if (vector::length(sig) > 0) {
                assert!(bit_is_set(fallback_bitmap, i), E_INVALID_DEOP_SIGNATURE);
                let pubkey = vector::borrow(&cfg.fallback_pubkeys, i);
                // R5-N (Round 5 A.9): outer `vector::length` guards dropped — stdlib
                // `ed25519::new_signature_from_bytes` and `new_unvalidated_public_key_from_bytes`
                // already assert their respective size constraints internally. pubkey lengths
                // are additionally pre-validated by `assert_valid_fallback_pubkeys` at admin
                // config time. Saves ~150-350 gas per fallback attestation (up to 14 length
                // calls eliminated across 7 slots). Error code on malformed sig/pubkey changes
                // from E_INVALID_DEOP_SIGNATURE to stdlib's invalid-argument abort.
                let ok = ed25519::signature_verify_strict(
                    &ed25519::new_signature_from_bytes(*sig),
                    &ed25519::new_unvalidated_public_key_from_bytes(*pubkey),
                    *message_bytes,
                );
                assert!(ok, E_INVALID_DEOP_SIGNATURE);
                valid_count = valid_count + 1;
            };
            i = i + 1;
        };
        assert!(valid_count >= cfg.threshold, E_TOO_FEW_DEOP_SIGNATURES);
    }

    fun assert_valid_fallback_pubkeys(pubkeys: &vector<vector<u8>>) {
        assert!(vector::length(pubkeys) == MAX_DEOPERATORS, E_BAD_FALLBACK_PUBKEYS);
        let active = 0;
        let i = 0;
        while (i < MAX_DEOPERATORS) {
            let pubkey = vector::borrow(pubkeys, i);
            let len = vector::length(pubkey);
            assert!(len == 0 || len == ED25519_PUBLIC_KEY_BYTES, E_BAD_FALLBACK_PUBKEYS);
            if (len == ED25519_PUBLIC_KEY_BYTES) {
                active = active + 1;
            };
            i = i + 1;
        };
        assert!(active >= THRESHOLD_V2, E_BAD_FALLBACK_PUBKEYS);
    }

    fun new_vault_tables_v2(): BridgeVaultTablesV2 {
        BridgeVaultTablesV2 {
            used_deposit_nonces: table::new<vector<u8>, bool>(),
            used_nullifiers: table::new<vector<u8>, bool>(),
            known_roots: table::new<vector<u8>, bool>(),
        }
    }

    fun deposit_nonce_used(nonce: &vector<u8>): bool acquires BridgeVaultTablesV2 {
        table::contains(
            &borrow_global<BridgeVaultTablesV2>(@eunoma).used_deposit_nonces,
            *nonce,
        )
    }

    fun mark_deposit_nonce_used(nonce: vector<u8>) acquires BridgeVaultTablesV2 {
        table::add(
            &mut borrow_global_mut<BridgeVaultTablesV2>(@eunoma).used_deposit_nonces,
            nonce,
            true,
        );
    }

    // V1 (gas opt): combined check+mark helper. Single borrow_global_mut, contains+add atomic.
    // R6-A.2: single `let n = *nonce;` reused for contains (copy) + add (move) — saves 1
    // 32B vector<u8> deref-clone vs prior 2× `*nonce`. Abort code preserved (E_DEPOSIT_NONCE_REPLAY).
    fun check_and_mark_deposit_nonce_v2(nonce: &vector<u8>) acquires BridgeVaultTablesV2 {
        let tables = borrow_global_mut<BridgeVaultTablesV2>(@eunoma);
        let n = *nonce;
        assert!(!table::contains(&tables.used_deposit_nonces, n), E_DEPOSIT_NONCE_REPLAY);
        table::add(&mut tables.used_deposit_nonces, n, true);
    }

    // FR-5.4: dropped `known_root_recorded` — 0 callers after FR-4.1 migrated all 4 prepare
    // entries to `known_root_recorded_with_tables`. Withdraw_to_recipient_v2 used the
    // `_with_tables` variant since WB2.D.

    fun record_known_root_internal(root: vector<u8>) acquires BridgeVaultTablesV2 {
        let tables = borrow_global_mut<BridgeVaultTablesV2>(@eunoma);
        if (!table::contains(&tables.known_roots, *&root)) {
            table::add(&mut tables.known_roots, root, true);
        };
    }

    fun nullifier_used(nullifier_hash: &vector<u8>): bool acquires BridgeVaultTablesV2 {
        table::contains(
            &borrow_global<BridgeVaultTablesV2>(@eunoma).used_nullifiers,
            *nullifier_hash,
        )
    }

    // WB2.D/FW8.3: `_with_tables` helper variants that take a borrowed/mut-borrowed
    // BridgeVaultTablesV2 instead of borrowing it themselves. Lets withdraw_to_recipient_v2
    // open ONE borrow_global_mut<BridgeVaultTablesV2> across the whole body and reuse it for
    // known_root check + nullifier check + nullifier mark (collapsing 3 borrow_globals → 1).
    fun known_root_recorded_with_tables(tables: &BridgeVaultTablesV2, root: &vector<u8>): bool {
        table::contains(&tables.known_roots, *root)
    }

    fun nullifier_used_with_tables(tables: &BridgeVaultTablesV2, nullifier_hash: &vector<u8>): bool {
        table::contains(&tables.used_nullifiers, *nullifier_hash)
    }

    fun mark_nullifier_used_with_tables(tables: &mut BridgeVaultTablesV2, nullifier_hash: vector<u8>) {
        table::add(&mut tables.used_nullifiers, nullifier_hash, true);
    }

    // FR-5.4: dropped `mark_nullifier_used` — 0 callers after WB2.D migrated
    // withdraw_to_recipient_v2 to `mark_nullifier_used_with_tables`.

    fun upsert_vault_public_inputs_v2(
        admin: &signer,
        asset_id_fr: vector<u8>,
        vault_addr_hash_fr: vector<u8>,
    ) acquires VaultPublicInputsV2 {
        assert_hash(&asset_id_fr);
        assert_hash(&vault_addr_hash_fr);
        if (exists<VaultPublicInputsV2>(@eunoma)) {
            let cache = borrow_global_mut<VaultPublicInputsV2>(@eunoma);
            cache.asset_id_fr = asset_id_fr;
            cache.vault_addr_hash_fr = vault_addr_hash_fr;
        } else {
            move_to(admin, VaultPublicInputsV2 { asset_id_fr, vault_addr_hash_fr });
        };
    }

    // WB1/FD5.1 gas opt: 16 params by-ref + manual BCS concat encoder.
    // Move struct fields cannot hold refs, so we skip the CAPayloadForHashV2 intermediate
    // entirely. BCS struct serialization is byte-equivalent to field-by-field concat of
    // each field's bcs::to_bytes (no struct framing / no separator), so output is identical
    // to the old `bcs::to_bytes(&CAPayloadForHashV2 { ... })` form. Eliminates 13 deep nested
    // vector clones (some `vector<vector<vector<u8>>>`) at 3 callsites (deposit/prepare_withdraw_payload/consume_or_compute_withdraw_payload).
    fun hash_confidential_transfer_payload_v2(
        asset_type: &Object<fungible_asset::Metadata>,
        to: &address,
        new_balance_p: &vector<vector<u8>>,
        new_balance_r: &vector<vector<u8>>,
        new_balance_r_eff_aud: &vector<vector<u8>>,
        amount_p: &vector<vector<u8>>,
        amount_r_sender: &vector<vector<u8>>,
        amount_r_recip: &vector<vector<u8>>,
        amount_r_eff_aud: &vector<vector<u8>>,
        ek_volun_auds: &vector<vector<u8>>,
        amount_r_volun_auds: &vector<vector<vector<u8>>>,
        zkrp_new_balance: &vector<u8>,
        zkrp_amount: &vector<u8>,
        sigma_proto_comm: &vector<vector<u8>>,
        sigma_proto_resp: &vector<vector<u8>>,
        memo: &vector<u8>,
    ): vector<u8> {
        let buf = bcs::to_bytes(asset_type);
        vector::append(&mut buf, bcs::to_bytes(to));
        vector::append(&mut buf, bcs::to_bytes(new_balance_p));
        vector::append(&mut buf, bcs::to_bytes(new_balance_r));
        vector::append(&mut buf, bcs::to_bytes(new_balance_r_eff_aud));
        vector::append(&mut buf, bcs::to_bytes(amount_p));
        vector::append(&mut buf, bcs::to_bytes(amount_r_sender));
        vector::append(&mut buf, bcs::to_bytes(amount_r_recip));
        vector::append(&mut buf, bcs::to_bytes(amount_r_eff_aud));
        vector::append(&mut buf, bcs::to_bytes(ek_volun_auds));
        vector::append(&mut buf, bcs::to_bytes(amount_r_volun_auds));
        vector::append(&mut buf, bcs::to_bytes(zkrp_new_balance));
        vector::append(&mut buf, bcs::to_bytes(zkrp_amount));
        vector::append(&mut buf, bcs::to_bytes(sigma_proto_comm));
        vector::append(&mut buf, bcs::to_bytes(sigma_proto_resp));
        vector::append(&mut buf, bcs::to_bytes(memo));
        aptos_hash::keccak256(buf)
    }

    fun ca_payload_hash_to_fr_safe(raw: vector<u8>): vector<u8> {
        // H3+R6-B.3 gas opt: single in-place byte write at index 31 instead of pop+push
        // (2 ops, 2 length recomputes, 1 memmove). Output byte-identical: [raw[0..31], 0u8].
        assert!(vector::length(&raw) == FR_BYTES, E_PAYLOAD_HASH_MISMATCH);
        *vector::borrow_mut(&mut raw, 31) = 0u8;
        raw
    }

    // R6-B.4: in-place bool-return sibling of ca_payload_hash_to_fr_safe.
    // Avoids the 32B allocation of the truncated Fr image + the 32-byte `==` loop.
    // Semantics: returns true iff (raw[0..31] || 0u8) equals *expected.
    // Note: `ca_payload_hash_to_fr_safe` still has 4 withdraw-side callers that need
    // the Fr value as a return — kept for those. Deposit hot-path switched to this.
    fun ca_payload_hash_matches_safe(raw: vector<u8>, expected: &vector<u8>): bool {
        assert!(vector::length(&raw) == FR_BYTES, E_PAYLOAD_HASH_MISMATCH);
        if (vector::length(expected) != FR_BYTES) { return false };
        if (*vector::borrow(expected, FR_BYTES - 1) != 0u8) { return false };
        let i = 0u64;
        while (i < FR_BYTES - 1) {
            if (*vector::borrow(&raw, i) != *vector::borrow(expected, i)) {
                return false
            };
            i = i + 1;
        };
        true
    }

    #[test_only]
    public fun test_call_ca_payload_hash_matches_safe(raw: vector<u8>, expected: vector<u8>): bool {
        ca_payload_hash_matches_safe(raw, &expected)
    }

    fun circuit_versions_hash(cfg: &DeoperatorConfigV2): vector<u8> {
        aptos_hash::keccak256(bcs::to_bytes(&CircuitVersionsForHash {
            deposit_circuit_version: *&cfg.deposit_circuit_version,
            withdraw_circuit_version: *&cfg.withdraw_circuit_version,
            ca_payload_circuit_version: *&cfg.ca_payload_circuit_version,
        }))
    }

    // C3 gas opt: defensive cached-lookup helper. Saves ~500-800 gas per deposit and per
    // withdraw attestation by reading a pre-computed 32B field instead of keccak256+bcs.
    // Falls back to recompute when cache resource not yet initialized (pre-migration window).
    fun get_or_compute_circuit_versions_hash(cfg: &DeoperatorConfigV2): vector<u8>
        acquires CircuitVersionsHashCacheV2
    {
        if (exists<CircuitVersionsHashCacheV2>(@eunoma)) {
            *&borrow_global<CircuitVersionsHashCacheV2>(@eunoma).hash
        } else {
            circuit_versions_hash(cfg)
        }
    }

    // R5-F (Round 5 A.2): manual BCS prefix helper. All vector<u8> hash inputs are
    // guaranteed 32 bytes (HASH_BYTES) by upstream `assert_hash` gates; BCS length
    // prefix for length=32 is always the single byte 0x20 (=32u8). Avoids the per-field
    // `bcs::to_bytes(&v)` allocation + struct walker overhead. Output is byte-identical
    // to `bcs::to_bytes(&v32: vector<u8>)`.
    fun append_vec32_bcs(buf: &mut vector<u8>, vec: &vector<u8>) {
        vector::push_back(buf, 32u8);
        vector::append(buf, *vec);
    }

    // Round 4 WB2.E B — Shared msg_hash helper for PendingWithdrawProofV3 cache.
    // Single source of truth: BOTH prepare_withdraw_proof_v3 (writer) AND
    // consume_or_verify_withdraw_proof V3-branch (reader) MUST call this — byte-identity
    // is load-bearing for cache-hit detection. Field order MUST match the Groth16 public
    // input order in assert_valid_withdraw_proof (root, nullifier_hash, asset_id,
    // recipient_hash, amount_tag, ca_payload_hash, vault_sequence_le, amount_p_digest)
    // so cache-hit is provably equivalent to Groth16 verify on identical publics.
    // vault_sequence encoded via bcs (LE u64), NOT u64_to_fr_bytes (BE) — cache key is
    // private to this module, not a circuit input (V3W-1.5 gotcha).
    //
    // R5-F (Round 5 A.2): uses append_vec32_bcs to avoid 7 intermediate bcs allocations
    // for the hash inputs. Saves ~350-560 gas per call across two callsites
    // (prepare_withdraw_proof_v3 + consume_or_verify_withdraw_proof V3-branch).
    fun compute_withdraw_proof_msg_hash(
        root: &vector<u8>,
        nullifier_hash: &vector<u8>,
        asset_id: &vector<u8>,
        recipient_hash: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        vault_sequence: u64,
        amount_p_digest: &vector<u8>,
    ): vector<u8> {
        let buf = vector::empty<u8>();
        append_vec32_bcs(&mut buf, root);
        append_vec32_bcs(&mut buf, nullifier_hash);
        append_vec32_bcs(&mut buf, asset_id);
        append_vec32_bcs(&mut buf, recipient_hash);
        append_vec32_bcs(&mut buf, amount_tag);
        append_vec32_bcs(&mut buf, ca_payload_hash);
        vector::append(&mut buf, bcs::to_bytes(&vault_sequence));
        append_vec32_bcs(&mut buf, amount_p_digest);
        aptos_hash::keccak256(buf)
    }

    // R5-C (Round 5 Wave C): struct-free BCS serializer for WithdrawAttestationV2Message.
    // Mirrors WB1's `hash_confidential_transfer_payload_v2` pattern (manual concat in
    // declaration order). Output is byte-identical to `bcs::to_bytes(&WithdrawAttestationV2Message{...})`
    // because BCS struct encoding = field-by-field concat in declaration order (no struct
    // framing prefix). Field order MUST match struct def at line 328 EXACTLY — FROST signs
    // these bytes. Saves ~500-800 gas per callsite × 4 callsites (V2 + V3 prepare + V3
    // cache-hit recompute + cache-miss).
    //
    // Uses `append_vec32_bcs` for the 9 known-32B vector fields (BCS length prefix = 0x20).
    // `domain` is 30 bytes (b"EUNOMA_WITHDRAW_ATTESTATION_V2") so uses bcs::to_bytes directly.
    // Scalars (u8/u64/address) use bcs::to_bytes directly.
    fun serialize_withdraw_attestation_v2_msg(
        domain: &vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: &vector<u8>,
        frost_group_pubkey: &vector<u8>,
        root: &vector<u8>,
        nullifier_hash: &vector<u8>,
        recipient: address,
        recipient_hash: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        request_hash: &vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        circuit_versions_hash: &vector<u8>,
    ): vector<u8> {
        let buf = vector::empty<u8>();
        vector::append(&mut buf, bcs::to_bytes(domain));
        vector::append(&mut buf, bcs::to_bytes(&chain_id));
        vector::append(&mut buf, bcs::to_bytes(&bridge));
        vector::append(&mut buf, bcs::to_bytes(&vault));
        vector::append(&mut buf, bcs::to_bytes(&asset_type));
        vector::append(&mut buf, bcs::to_bytes(&operator_set_version));
        vector::append(&mut buf, bcs::to_bytes(&dkg_epoch));
        append_vec32_bcs(&mut buf, roster_hash);
        append_vec32_bcs(&mut buf, frost_group_pubkey);
        append_vec32_bcs(&mut buf, root);
        append_vec32_bcs(&mut buf, nullifier_hash);
        vector::append(&mut buf, bcs::to_bytes(&recipient));
        append_vec32_bcs(&mut buf, recipient_hash);
        append_vec32_bcs(&mut buf, amount_tag);
        append_vec32_bcs(&mut buf, ca_payload_hash);
        append_vec32_bcs(&mut buf, request_hash);
        vector::append(&mut buf, bcs::to_bytes(&vault_sequence));
        vector::append(&mut buf, bcs::to_bytes(&expiry_secs));
        append_vec32_bcs(&mut buf, circuit_versions_hash);
        buf
    }

    // R6-C.1 (Round 6 Wave D): struct-free BCS serializer for DepositAttestationV3Message.
    // Mirrors R5-C serialize_withdraw_attestation_v2_msg exactly. Output is byte-identical
    // to bcs::to_bytes(&DepositAttestationV2Message{...}) because BCS struct encoding =
    // field-by-field concat in declaration order (no framing). Field order MUST match struct
    // def at line 361-377 EXACTLY — FROST signs these bytes. Saves ~500-800 gas/deposit.
    //
    // append_vec32_bcs for the 6 known-32B fields (roster_hash, frost_group_pubkey,
    // commitment, amount_tag, ca_payload_hash, circuit_versions_hash) — all upstream-gated
    // to 32B via assert_3_deposit_hashes (R6-A.1) + init-time roster/pubkey + keccak256 cvh.
    // deposit_nonce uses bcs::to_bytes (variable-length, NOT length-gated) so ULEB128 prefix
    // matches BCS struct encoding for any length (test coverage at 16B + 64B variants).
    fun serialize_deposit_attestation_v3_msg(
        domain: &vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: &vector<u8>,
        frost_group_pubkey: &vector<u8>,
        commitment: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        deposit_nonce: &vector<u8>,
        expiry_secs: u64,
        circuit_versions_hash: &vector<u8>,
        user_addr: address,
    ): vector<u8> {
        let buf = vector::empty<u8>();
        vector::append(&mut buf, bcs::to_bytes(domain));
        vector::append(&mut buf, bcs::to_bytes(&chain_id));
        vector::append(&mut buf, bcs::to_bytes(&bridge));
        vector::append(&mut buf, bcs::to_bytes(&vault));
        vector::append(&mut buf, bcs::to_bytes(&asset_type));
        vector::append(&mut buf, bcs::to_bytes(&operator_set_version));
        vector::append(&mut buf, bcs::to_bytes(&dkg_epoch));
        append_vec32_bcs(&mut buf, roster_hash);
        append_vec32_bcs(&mut buf, frost_group_pubkey);
        append_vec32_bcs(&mut buf, commitment);
        append_vec32_bcs(&mut buf, amount_tag);
        append_vec32_bcs(&mut buf, ca_payload_hash);
        vector::append(&mut buf, bcs::to_bytes(deposit_nonce));
        vector::append(&mut buf, bcs::to_bytes(&expiry_secs));
        append_vec32_bcs(&mut buf, circuit_versions_hash);
        // Append depositing user's address (raw 32B, no length prefix). The off-chain TS serializer
        // MUST writeAddress here too.
        vector::append(&mut buf, bcs::to_bytes(&user_addr));
        buf
    }

    // B1-v2 (codex fix + real Opt #1): take amount_p (not pre-computed digest). V3 cache-hit
    // path byte-compares amount_p directly (128B vs 32B but no Poseidon recompute — ~700 gas
    // saved). V2 cache-hit + Groth16 fallback compute digest internally. Soundness equivalent:
    // V3 cache was populated by prepare_deposit_binding_v3 which Groth16-verified amount_p
    // binds to commitment via compute_amount_p_digest_v2(amount_p). Adversary substituting
    // different amount_p must fail the 128B byte-compare.
    fun consume_or_verify_deposit_binding(
        sender_addr: address,
        commitment: &vector<u8>,
        amount_tag: &vector<u8>,
        amount_p: &vector<vector<u8>>,
        proof: vector<u8>,
    ) acquires PendingDepositBindingsV3, PendingDepositBindingsV2, PreparedDepositBindingVK, VaultPublicInputsV2 {
        // R6-D.2: hoist proof-length check (reused by V3 + V2 branches; saves
        // ~10-30 gas on V2-hit + Groth16-fallback paths; 0 on V3-hit).
        let is_cache_path = vector::length(&proof) == 0;
        // V3 fast path: byte-compare amount_p, skip 4-Poseidon compute entirely.
        // R7-W1: V3 cache lookup keyed by composite (sender, commitment) — squat-proof.
        if (is_cache_path && exists<PendingDepositBindingsV3>(@eunoma)) {
            let pending_v3 = borrow_global_mut<PendingDepositBindingsV3>(@eunoma);
            let key_v3 = compose_pending_key(sender_addr, commitment);
            if (table::contains(&pending_v3.by_commitment, key_v3)) {
                let cached_v3 = table::remove(&mut pending_v3.by_commitment, key_v3);
                // R6-D.1: fail-fast on amount_p (128B, attacker-most-likely tamper)
                // before amount_tag — defense-in-depth, 0 happy-path cost.
                assert!(&cached_v3.amount_p == amount_p, E_INVALID_DEPOSIT_BINDING_PROOF);
                // R6-D.5: ref-compare avoids 32B `*amount_tag` deref-clone.
                assert!(&cached_v3.amount_tag == amount_tag, E_INVALID_DEPOSIT_BINDING_PROOF);
                return
            };
        };
        // V2 legacy cache: must compute digest locally (no amount_p cached). Caller saved
        // having to compute it before this call. Still skips Groth16 verify on cache hit.
        // V2 deliberately NOT reordered (amount_tag check must precede ~700-gas Poseidon).
        if (is_cache_path && exists<PendingDepositBindingsV2>(@eunoma)) {
            let pending_v2 = borrow_global_mut<PendingDepositBindingsV2>(@eunoma);
            let key_v2 = *commitment;
            if (table::contains(&pending_v2.by_commitment, key_v2)) {
                let cached_v2 = table::remove(&mut pending_v2.by_commitment, key_v2);
                // R6-D.5: ref-compare avoids 32B `*amount_tag` deref-clone.
                assert!(&cached_v2.amount_tag == amount_tag, E_INVALID_DEPOSIT_BINDING_PROOF);
                let supplied_digest = compute_amount_p_digest_v2(amount_p);
                assert!(cached_v2.amount_p_digest == supplied_digest, E_INVALID_DEPOSIT_BINDING_PROOF);
                return
            };
        };
        // Groth16 fallback path: no cache, full verify with digest as public input.
        let amount_p_digest = compute_amount_p_digest_v2(amount_p);
        assert_valid_deposit_binding_proof(
            commitment,
            amount_tag,
            &amount_p_digest,
            proof,
        );
    }

    // Round 4 WB2.E B / FR-1.3+V3R-1: by-ref hash params (drops 8 `*&` clones at the single
    // withdraw_to_recipient_v2 caller). Three-tier soft lookup: V3 → V2 → Groth16 verify.
    // Both cache branches use soft `if (table::contains)` (not assert!) so a V3-prepared tx
    // doesn't abort when V2 cache is the only one whose `exists` returns true (V3D-1.4).
    // V3 cache-hit: 1 keccak + 32B byte-eq via shared compute_withdraw_proof_msg_hash
    // (writer + reader use SAME helper → byte-identity guaranteed by construction).
    // V2 cache-hit: legacy 8-field eq, kept for in-flight V2-prepared txs.
    fun consume_or_verify_withdraw_proof(
        root: &vector<u8>,
        nullifier_hash: &vector<u8>,
        asset_id: &vector<u8>,
        recipient_hash: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        request_hash: &vector<u8>,
        vault_sequence: u64,
        amount_p_digest: &vector<u8>,
        proof: vector<u8>,
    ) acquires PendingWithdrawProofsV2, PendingWithdrawProofsV2b, PendingWithdrawProofsV3, PendingWithdrawProofsV3b, PreparedWithdrawProofVK {
        let is_cache_path = vector::length(&proof) == 0;
        // Round 5 Wave E.5 (R5-R): V3b cache-hit — 7-field equality (no asset_id; no
        // msg_hash). Priority chain: V3b → V3 → V2b → V2 → miss. New prepare_withdraw_
        // proof_v3 writes V3b; legacy V3 entries drain via the V3 branch below.
        if (is_cache_path && exists<PendingWithdrawProofsV3b>(@eunoma)) {
            let pending_v3b = borrow_global_mut<PendingWithdrawProofsV3b>(@eunoma);
            if (table::contains(&pending_v3b.by_request_hash, *request_hash)) {
                let cached_v3b = table::remove(&mut pending_v3b.by_request_hash, *request_hash);
                // R5-M order: cheapest / tamper-likely first (mirrors V2 + V2b branches).
                assert!(cached_v3b.vault_sequence == vault_sequence, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v3b.nullifier_hash == nullifier_hash, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v3b.amount_p_digest == amount_p_digest, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v3b.recipient_hash == recipient_hash, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v3b.root == root, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v3b.amount_tag == amount_tag, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v3b.ca_payload_hash == ca_payload_hash, E_INVALID_WITHDRAW_PROOF);
                return
            };
        };
        if (is_cache_path && exists<PendingWithdrawProofsV3>(@eunoma)) {
            let pending_v3 = borrow_global_mut<PendingWithdrawProofsV3>(@eunoma);
            if (table::contains(&pending_v3.by_request_hash, *request_hash)) {
                let cached_v3 = table::remove(&mut pending_v3.by_request_hash, *request_hash);
                let computed_msg_hash = compute_withdraw_proof_msg_hash(
                    root, nullifier_hash, asset_id, recipient_hash, amount_tag,
                    ca_payload_hash, vault_sequence, amount_p_digest,
                );
                assert!(cached_v3.msg_hash == computed_msg_hash, E_INVALID_WITHDRAW_PROOF);
                return
            };
        };
        // Round 5 Wave E.2 (P06-1): V2b cache-hit — 7-field equality (no asset_id; the
        // caller's asset_id arg already comes from VaultPublicInputsV2.asset_id_fr, which
        // is immutable post-V2-bootstrap, so no rotation skew is possible).
        if (is_cache_path && exists<PendingWithdrawProofsV2b>(@eunoma)) {
            let pending_v2b = borrow_global_mut<PendingWithdrawProofsV2b>(@eunoma);
            if (table::contains(&pending_v2b.by_request_hash, *request_hash)) {
                let cached_v2b = table::remove(&mut pending_v2b.by_request_hash, *request_hash);
                // R5-M order: cheapest / tamper-likely first (mirrors V2 branch below).
                assert!(cached_v2b.vault_sequence == vault_sequence, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v2b.nullifier_hash == nullifier_hash, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v2b.amount_p_digest == amount_p_digest, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v2b.recipient_hash == recipient_hash, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v2b.root == root, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v2b.amount_tag == amount_tag, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached_v2b.ca_payload_hash == ca_payload_hash, E_INVALID_WITHDRAW_PROOF);
                return
            };
        };
        if (is_cache_path && exists<PendingWithdrawProofsV2>(@eunoma)) {
            let pending = borrow_global_mut<PendingWithdrawProofsV2>(@eunoma);
            if (table::contains(&pending.by_request_hash, *request_hash)) {
                let cached = table::remove(&mut pending.by_request_hash, *request_hash);
                // R5-M (Round 5 A.8): assert order reorganized for fail-fast on tampered
                // inputs. Exploits Move `==` short-circuit semantics on vectors. Order:
                //   1) vault_sequence (u64, cheapest comparison, unique per epoch)
                //   2) nullifier_hash (32B, unique per spent note — replay-attempt detector)
                //   3) amount_p_digest (32B, tamper-likely for overdraw attempts)
                //   4) recipient_hash (32B)
                //   5) root (32B)
                //   6) amount_tag (32B)
                //   7) ca_payload_hash (32B)
                //   8) asset_id (32B, constant per vault — last because least likely to differ)
                // Happy path cost unchanged. Aborts ~80-250 gas faster on tampered inputs.
                assert!(cached.vault_sequence == vault_sequence, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached.nullifier_hash == nullifier_hash, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached.amount_p_digest == amount_p_digest, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached.recipient_hash == recipient_hash, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached.root == root, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached.amount_tag == amount_tag, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached.ca_payload_hash == ca_payload_hash, E_INVALID_WITHDRAW_PROOF);
                assert!(&cached.asset_id == asset_id, E_INVALID_WITHDRAW_PROOF);
                return
            };
        };
        assert_valid_withdraw_proof(
            root, nullifier_hash, asset_id, recipient_hash, amount_tag,
            ca_payload_hash, request_hash, vault_sequence, amount_p_digest, proof,
        );
    }

    fun consume_or_compute_withdraw_payload(
        recipient: address,
        asset_type: Object<fungible_asset::Metadata>,
        request_hash: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        new_balance_p: &vector<vector<u8>>,
        new_balance_r: &vector<vector<u8>>,
        new_balance_r_eff_aud: &vector<vector<u8>>,
        amount_p: &vector<vector<u8>>,
        amount_r_sender: &vector<vector<u8>>,
        amount_r_recip: &vector<vector<u8>>,
        amount_r_eff_aud: &vector<vector<u8>>,
        ek_volun_auds: &vector<vector<u8>>,
        amount_r_volun_auds: &vector<vector<vector<u8>>>,
        zkrp_new_balance: &vector<u8>,
        zkrp_amount: &vector<u8>,
        sigma_proto_comm: &vector<vector<u8>>,
        sigma_proto_resp: &vector<vector<u8>>,
        memo: &vector<u8>,
    ): (vector<u8>, vector<u8>) acquires PendingWithdrawPayloadsV2, PendingWithdrawPayloadsV3 {
        // Round 4 WB2.E B / V3R-3: V3-first lookup. msg_hash compute MUST be byte-identical
        // to V3W-3 writer (uses same hash_confidential_transfer_payload_v2 by-ref encoder
        // shipped in WB1 + same ca_payload_hash_to_fr_safe truncation). Cache-hit returns
        // (computed_hash, cached.amount_p_digest) — same shape as V2 path. amount_p_digest
        // preserved in V3 cache so cache-hit doesn't pay Poseidon-4 (FR-4.6-style win).
        if (exists<PendingWithdrawPayloadsV3>(@eunoma)) {
            let pending_v3 = borrow_global_mut<PendingWithdrawPayloadsV3>(@eunoma);
            if (table::contains(&pending_v3.by_request_hash, *request_hash)) {
                let cached_v3 = table::remove(&mut pending_v3.by_request_hash, *request_hash);
                let computed_hash = ca_payload_hash_to_fr_safe(hash_confidential_transfer_payload_v2(
                    &asset_type, &recipient, new_balance_p, new_balance_r, new_balance_r_eff_aud,
                    amount_p, amount_r_sender, amount_r_recip, amount_r_eff_aud, ek_volun_auds,
                    amount_r_volun_auds, zkrp_new_balance, zkrp_amount, sigma_proto_comm,
                    sigma_proto_resp, memo,
                ));
                // Double bind: cached msg_hash == recomputed (proves prepare-time inputs match
                // current submit inputs) AND recomputed == ca_payload_hash arg (forecloses
                // FW5.1-style binding gap codex flagged).
                assert!(cached_v3.msg_hash == computed_hash, E_PAYLOAD_HASH_MISMATCH);
                assert!(&computed_hash == ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
                // P0 hotfix (Round 5 Wave A codex audit): defuse any V3 payload cache
                // entries that may have been written by the vulnerable FR-4.6 prepare path
                // before its revert. Recompute amount_p_digest from CURRENT submit-time
                // amount_p and assert equality to the cached digest. If a pre-revert
                // pending entry has digest_A but stage-3 amount_p_C produces digest_C,
                // this aborts before the framework call.
                let digest_now = compute_amount_p_digest_v2(amount_p);
                assert!(cached_v3.amount_p_digest == digest_now, E_INVALID_WITHDRAW_PROOF);
                return (computed_hash, digest_now)
            };
        };
        // R5-K (Round 5 A.6): collapse V2 payload-cache double `borrow_global` (immut for
        // contains + mut for remove) to single `borrow_global_mut + contains + remove`,
        // mirroring the V3 path at 2483-2486 and the V2 proof path at 2413-2415. Saves
        // ~200-500 gas per cache lookup by eliminating one resource-load round-trip.
        if (exists<PendingWithdrawPayloadsV2>(@eunoma)) {
            let pending = borrow_global_mut<PendingWithdrawPayloadsV2>(@eunoma);
            if (table::contains(&pending.by_request_hash, *request_hash)) {
            let cached = table::remove(&mut pending.by_request_hash, *request_hash);
            // WB1/FW5.3 gas opt: drop 14 `*X` derefs (each cloned the 32B-to-MB byte vector
            // just to satisfy by-value `==`). Move's `==` accepts `&vector<T>` on both sides
            // and walks element-by-element with no clone. Cache-hit savings ~500-1500 gas.
            assert!(cached.asset_type == object::object_address(&asset_type), E_PAYLOAD_HASH_MISMATCH);
            assert!(cached.recipient == recipient, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.ca_payload_hash == ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.new_balance_p == new_balance_p, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.new_balance_r == new_balance_r, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.new_balance_r_eff_aud == new_balance_r_eff_aud, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.amount_p == amount_p, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.amount_r_sender == amount_r_sender, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.amount_r_recip == amount_r_recip, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.amount_r_eff_aud == amount_r_eff_aud, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.ek_volun_auds == ek_volun_auds, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.amount_r_volun_auds == amount_r_volun_auds, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.zkrp_new_balance == zkrp_new_balance, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.zkrp_amount == zkrp_amount, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.sigma_proto_comm == sigma_proto_comm, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.sigma_proto_resp == sigma_proto_resp, E_PAYLOAD_HASH_MISMATCH);
            assert!(&cached.memo == memo, E_PAYLOAD_HASH_MISMATCH);
            return (cached.ca_payload_hash, cached.amount_p_digest)
            };
        };

        let computed_hash = ca_payload_hash_to_fr_safe(hash_confidential_transfer_payload_v2(
            &asset_type,
            &recipient,
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
        ));
        assert!(computed_hash == *ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
        (computed_hash, compute_amount_p_digest_v2(amount_p))
    }

    fun consume_prepared_withdraw_payload_digest(
        request_hash: &vector<u8>,
        ca_payload_hash: &vector<u8>,
    ): vector<u8> acquires PendingWithdrawPayloadsV2, PendingWithdrawPayloadsV3 {
        if (exists<PendingWithdrawPayloadsV3>(@eunoma)) {
            let pending_v3 = borrow_global_mut<PendingWithdrawPayloadsV3>(@eunoma);
            if (table::contains(&pending_v3.by_request_hash, *request_hash)) {
                let cached_v3 = table::remove(&mut pending_v3.by_request_hash, *request_hash);
                assert!(&cached_v3.msg_hash == ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
                return cached_v3.amount_p_digest
            };
        };
        if (exists<PendingWithdrawPayloadsV2>(@eunoma)) {
            let pending = borrow_global_mut<PendingWithdrawPayloadsV2>(@eunoma);
            if (table::contains(&pending.by_request_hash, *request_hash)) {
                let cached = table::remove(&mut pending.by_request_hash, *request_hash);
                assert!(&cached.ca_payload_hash == ca_payload_hash, E_PAYLOAD_HASH_MISMATCH);
                return cached.amount_p_digest
            };
        };
        assert!(false, E_INVALID_WITHDRAW_PROOF);
        vector[]
    }

    // Round 4 WB2.E B / FR-1.3 + V3R-2: 6 hash params by-ref (drops 6 `*&` clones at withdraw
    // caller). 3-tier soft lookup: V3 msg_hash → V2 legacy field-eq → BCS+verify path.
    // V3 cache-hit rebuilds the same WithdrawAttestationV2Message from current inputs + cfg
    // + circuit_versions_hash → keccak → byte-eq cached.msg_hash. Cfg-rotation auto-detected
    // (rotated cfg fields → different msg_hash → abort E_INVALID_DEOP_SIGNATURE). FROST sig
    // re-verify SAFELY skipped on cache-hit: sig was verified at prepare-time + bound to
    // msg_hash; msg_hash byte-equality ⇒ identical signed payload ⇒ original verify transitive.
    // R5-J (Round 5 A.5): `circuit_versions_hash` passed in by-ref from caller. The caller
    // (withdraw_to_recipient_v2) computes once via get_or_compute_circuit_versions_hash(cfg)
    // and passes ref; eliminates inner global borrow + 32B clone at all 3 sub-branches
    // (V3 cache-hit / V2 cache-hit assert / cache-miss msg struct). Saves ~150-300 gas/withdraw.
    // CircuitVersionsHashCacheV2 no longer needs to be acquired here.
    fun consume_or_verify_withdraw_attestation(
        root: &vector<u8>,
        nullifier_hash: &vector<u8>,
        recipient: address,
        recipient_hash: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        request_hash: &vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
        cfg: &DeoperatorConfigV2,
        vault_addr: address,
        asset_type_addr: address,
        circuit_versions_hash: &vector<u8>,
    ) acquires PendingWithdrawAttestationsV2, PendingWithdrawAttestationsV2b, PendingWithdrawAttestationsV3 {
        let use_pending = vector::length(&group_signature) == 0
            && fallback_bitmap == 0
            && vector::length(&fallback_signatures) == 0;
        if (use_pending && exists<PendingWithdrawAttestationsV3>(@eunoma)) {
            let pending_v3 = borrow_global_mut<PendingWithdrawAttestationsV3>(@eunoma);
            if (table::contains(&pending_v3.by_request_hash, *request_hash)) {
                let cached_v3 = table::remove(&mut pending_v3.by_request_hash, *request_hash);
                // R5-C (Round 5 Wave C): struct-free BCS via serializer helper.
                let msg_bytes_v3 = serialize_withdraw_attestation_v2_msg(
                    &DOMAIN_WITHDRAW_V2,
                    chain_id::get(),
                    @eunoma,
                    vault_addr,
                    asset_type_addr,
                    cfg.operator_set_version,
                    cfg.dkg_epoch,
                    &cfg.roster_hash,
                    &cfg.frost_group_pubkey,
                    root,
                    nullifier_hash,
                    recipient,
                    recipient_hash,
                    amount_tag,
                    ca_payload_hash,
                    request_hash,
                    vault_sequence,
                    expiry_secs,
                    circuit_versions_hash,
                );
                let computed_msg_hash = aptos_hash::keccak256(msg_bytes_v3);
                assert!(cached_v3.msg_hash == computed_msg_hash, E_INVALID_DEOP_SIGNATURE);
                return
            };
        };
        // Round 5 Wave E.1 (R5-D): V2b cache-hit (msg_hash-only, same shape as V3).
        // Priority chain: V3 → V2b → V2 → miss. New prepare_withdraw_attestation_v2 writes
        // to V2b; legacy in-flight V2 entries still drain via the V2 branch below.
        if (use_pending && exists<PendingWithdrawAttestationsV2b>(@eunoma)) {
            let pending_v2b = borrow_global_mut<PendingWithdrawAttestationsV2b>(@eunoma);
            if (table::contains(&pending_v2b.by_request_hash, *request_hash)) {
                let cached_v2b = table::remove(&mut pending_v2b.by_request_hash, *request_hash);
                let msg_bytes_v2b = serialize_withdraw_attestation_v2_msg(
                    &DOMAIN_WITHDRAW_V2,
                    chain_id::get(),
                    @eunoma,
                    vault_addr,
                    asset_type_addr,
                    cfg.operator_set_version,
                    cfg.dkg_epoch,
                    &cfg.roster_hash,
                    &cfg.frost_group_pubkey,
                    root,
                    nullifier_hash,
                    recipient,
                    recipient_hash,
                    amount_tag,
                    ca_payload_hash,
                    request_hash,
                    vault_sequence,
                    expiry_secs,
                    circuit_versions_hash,
                );
                let computed_msg_hash_v2b = aptos_hash::keccak256(msg_bytes_v2b);
                assert!(cached_v2b.msg_hash == computed_msg_hash_v2b, E_INVALID_DEOP_SIGNATURE);
                return
            };
        };
        if (use_pending && exists<PendingWithdrawAttestationsV2>(@eunoma)) {
            let pending = borrow_global_mut<PendingWithdrawAttestationsV2>(@eunoma);
            if (table::contains(&pending.by_request_hash, *request_hash)) {
                let cached = table::remove(&mut pending.by_request_hash, *request_hash);
                assert!(cached.vault == vault_addr, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.asset_type == asset_type_addr, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.operator_set_version == cfg.operator_set_version, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.dkg_epoch == cfg.dkg_epoch, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.roster_hash == cfg.roster_hash, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.frost_group_pubkey == cfg.frost_group_pubkey, E_INVALID_DEOP_SIGNATURE);
                assert!(&cached.root == root, E_INVALID_DEOP_SIGNATURE);
                assert!(&cached.nullifier_hash == nullifier_hash, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.recipient == recipient, E_INVALID_DEOP_SIGNATURE);
                assert!(&cached.recipient_hash == recipient_hash, E_INVALID_DEOP_SIGNATURE);
                assert!(&cached.amount_tag == amount_tag, E_INVALID_DEOP_SIGNATURE);
                assert!(&cached.ca_payload_hash == ca_payload_hash, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.vault_sequence == vault_sequence, E_INVALID_DEOP_SIGNATURE);
                assert!(cached.expiry_secs == expiry_secs, E_INVALID_DEOP_SIGNATURE);
                assert!(&cached.circuit_versions_hash == circuit_versions_hash, E_INVALID_DEOP_SIGNATURE);
                return
            };
        };
        // R5-C (Round 5 Wave C): struct-free BCS via serializer helper.
        let msg_bytes = serialize_withdraw_attestation_v2_msg(
            &DOMAIN_WITHDRAW_V2,
            chain_id::get(),
            @eunoma,
            vault_addr,
            asset_type_addr,
            cfg.operator_set_version,
            cfg.dkg_epoch,
            &cfg.roster_hash,
            &cfg.frost_group_pubkey,
            root,
            nullifier_hash,
            recipient,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            request_hash,
            vault_sequence,
            expiry_secs,
            circuit_versions_hash,
        );
        assert_deop_attestation_v2(
            &msg_bytes,
            group_signature,
            fallback_bitmap,
            fallback_signatures,
            cfg,
        );
    }

    fun assert_valid_deposit_binding_proof(
        commitment: &vector<u8>,
        amount_tag: &vector<u8>,
        amount_p_digest: &vector<u8>,
        proof: vector<u8>,
    ) acquires PreparedDepositBindingVK, VaultPublicInputsV2 {
        assert!(exists<PreparedDepositBindingVK>(@eunoma), E_NOT_INITIALIZED);
        assert!(exists<VaultPublicInputsV2>(@eunoma), E_NOT_INITIALIZED);
        let pvk = borrow_global<PreparedDepositBindingVK>(@eunoma);
        let cache = borrow_global<VaultPublicInputsV2>(@eunoma);
        assert!(vector::length(&pvk.pvk_uvw_gamma_g1) == DEPOSIT_VK_IC_LENGTH, E_INVALID_DEPOSIT_BINDING_PROOF);
        // WB3/FG2.1: dropped per-verify assert_prepared_vk_shape. The 3 prepared VK byte fields
        // (alpha_g1_beta_g2_fq12, gamma_g2_neg, delta_g2_neg) are produced exclusively by
        // `pairing_fq12_bytes` / `neg_g2_bytes` — both delegate to Aptos `crypto_algebra::
        // serialize` which returns canonical 384B Fq12 / 192B G2. The PreparedDepositBindingVK
        // resource is `move_to`'d once and only replaced via `move_from + move_to` on rotation
        // (no in-place field-mutation path; no `borrow_global_mut<PreparedDepositBindingVK>`
        // exists in the module — verified by codex). INVARIANT: prepared-VK byte fields must
        // only be produced by the canonical `crypto_algebra::serialize` helpers above; any new
        // writer path must preserve this or restore the runtime shape check.
        // Stage 3 A6: amount_p_digest is the 5th public input (after commitment, amount_tag,
        // asset_id, vault_addr_hash). Circuit publics order MUST match this vector exactly.
        let publics = vector[
            de_fr_with_error(commitment, E_INVALID_DEPOSIT_BINDING_PROOF),
            de_fr_with_error(amount_tag, E_INVALID_DEPOSIT_BINDING_PROOF),
            // R5-T (Wave F.2): asset_id_fr + vault_addr_hash_fr are both Poseidon-derived
            // (derive_asset_id + derive_vault_addr_hash) and stored as canonical 32B Fr in
            // VaultPublicInputsV2. amount_p_digest = compute_amount_p_digest_v2 output.
            // All three are canonical-by-construction → skip the is_some guards.
            de_fr_unchecked(&cache.asset_id_fr),
            de_fr_unchecked(&cache.vault_addr_hash_fr),
            de_fr_unchecked(amount_p_digest),
        ];
        assert_groth16_prepared(
            &pvk.pvk_alpha_g1_beta_g2_fq12,
            &pvk.pvk_gamma_g2_neg,
            &pvk.pvk_delta_g2_neg,
            &pvk.pvk_uvw_gamma_g1,
            &publics,
            proof,
            E_INVALID_DEPOSIT_BINDING_PROOF,
        );
    }

    // Round 4 WB2.E B / FR-3.3: 7 hash params + amount_p_digest taken by-ref (mirrors
    // assert_valid_deposit_binding_proof's WB3 B3 by-ref refactor). Eliminates the 8
    // *&deref clones at every caller (prepare_withdraw_proof_v2/v3 + consume_or_verify_withdraw_proof
    // cache-miss branch). vault_sequence stays by-value (u64 primitive).
    fun assert_valid_withdraw_proof(
        root: &vector<u8>,
        nullifier_hash: &vector<u8>,
        asset_id: &vector<u8>,
        recipient_hash: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        request_hash: &vector<u8>,
        vault_sequence: u64,
        amount_p_digest: &vector<u8>,
        proof: vector<u8>,
    ) acquires PreparedWithdrawProofVK {
        assert!(exists<PreparedWithdrawProofVK>(@eunoma), E_NOT_INITIALIZED);
        let pvk = borrow_global<PreparedWithdrawProofVK>(@eunoma);
        assert!(vector::length(&pvk.pvk_uvw_gamma_g1) == WITHDRAW_VK_IC_LENGTH, E_INVALID_WITHDRAW_PROOF);
        // WB3/FG2.1: dropped per-verify assert_prepared_vk_shape — see deposit-side comment in
        // assert_valid_deposit_binding_proof for the invariant: prepared-VK byte fields are
        // produced exclusively by canonical crypto_algebra::serialize helpers; resource is
        // replaced-not-mutated; no `borrow_global_mut<PreparedWithdrawProofVK>` exists.
        // Stage 3 A6: amount_p_digest is the 9th public input. Circuit publics order:
        // [root, nullifier_hash, asset_id, recipient_hash, amount_tag, ca_payload_hash,
        //  request_hash, vault_sequence, amount_p_digest] — MUST match exactly.
        let publics = vector[
            de_fr_with_error(root, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(nullifier_hash, E_INVALID_WITHDRAW_PROOF),
            // R5-T (Wave F.2): asset_id is `VaultPublicInputsV2.asset_id_fr`, set by
            // upsert_vault_public_inputs_v2 via derive_asset_id (Poseidon output, canonical
            // 32B Fr). Skip the option::is_some guard.
            de_fr_unchecked(asset_id),
            de_fr_with_error(recipient_hash, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(amount_tag, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(ca_payload_hash, E_INVALID_WITHDRAW_PROOF),
            de_fr_with_error(request_hash, E_INVALID_WITHDRAW_PROOF),
            // R5-H (Round 5 A.4): `crypto_algebra::from_u64<Fr>(vault_sequence)` direct
            // replaces `de_fr_with_error(&u64_to_fr_bytes(vault_sequence), ...)`. Eliminates
            // the 32B temp vector allocation (8B BCS + 24B zero pad) + deserialize roundtrip.
            // `from_u64` is the native field-construction path used inside `groth16_bn254` for
            // the constant `1` scalar. Saves ~150-350 gas per Groth16 verify.
            crypto_algebra::from_u64<Fr>(vault_sequence),
            // R5-T (Wave F.2): amount_p_digest is compute_amount_p_digest_v2 output —
            // Poseidon hash_2 of 4 hash_3 outputs, all canonical Fr by construction.
            de_fr_unchecked(amount_p_digest),
        ];
        assert_groth16_prepared(
            &pvk.pvk_alpha_g1_beta_g2_fq12,
            &pvk.pvk_gamma_g2_neg,
            &pvk.pvk_delta_g2_neg,
            &pvk.pvk_uvw_gamma_g1,
            &publics,
            proof,
            E_INVALID_WITHDRAW_PROOF,
        );
    }

    fun assert_groth16_prepared(
        pvk_alpha_g1_beta_g2_fq12: &vector<u8>,
        pvk_gamma_g2_neg: &vector<u8>,
        pvk_delta_g2_neg: &vector<u8>,
        pvk_uvw_gamma_g1: &vector<vector<u8>>,
        publics: &vector<crypto_algebra::Element<Fr>>,
        proof: vector<u8>,
        err: u64,
    ) {
        assert!(vector::length(&proof) == PROOF_BYTES, err);
        // WB3/FG4: pass refs to de_*_with_error directly (sig changed to &vector<u8>);
        // eliminates 3 large clones (Fq12=384B + 2×G2=192B = 768B per verify) at this hot path.
        let pvk_alpha_beta = de_fq12_with_error(pvk_alpha_g1_beta_g2_fq12, err);
        let pvk_gamma_neg = de_g2_with_error(pvk_gamma_g2_neg, err);
        let pvk_delta_neg = de_g2_with_error(pvk_delta_g2_neg, err);
        let vk_ic = vector::empty<crypto_algebra::Element<G1>>();
        let i = 0;
        let n = vector::length(pvk_uvw_gamma_g1);
        while (i < n) {
            // WB3/FG4+FG1.5: pass `vector::borrow(...)` ref directly into the deserializer
            // (no more 64B clone per IC element; 6-10 elements per verify).
            vector::push_back(&mut vk_ic, de_g1_with_error(vector::borrow(pvk_uvw_gamma_g1, i), err));
            i = i + 1;
        };
        // R5-G (Round 5 A.3): byte_slice_unchecked safe here — line 2757 already asserts
        // length(&proof) == PROOF_BYTES = G1 + G2 + G1 = 256, so all 3 slice ends are in-bounds.
        let proof_a_bytes = byte_slice_unchecked(&proof, 0, G1_UNCOMPRESSED_BYTES);
        let proof_b_bytes = byte_slice_unchecked(
            &proof,
            G1_UNCOMPRESSED_BYTES,
            G1_UNCOMPRESSED_BYTES + G2_UNCOMPRESSED_BYTES,
        );
        let proof_c_bytes = byte_slice_unchecked(
            &proof,
            G1_UNCOMPRESSED_BYTES + G2_UNCOMPRESSED_BYTES,
            PROOF_BYTES,
        );
        let proof_a = de_g1_with_error(&proof_a_bytes, err);
        let proof_b = de_g2_with_error(&proof_b_bytes, err);
        let proof_c = de_g1_with_error(&proof_c_bytes, err);
        let ok = groth16_bn254::verify_proof_prepared_fq12<G1, G2, Gt, Fq12, Fr>(
            &pvk_alpha_beta,
            &pvk_gamma_neg,
            &pvk_delta_neg,
            &vk_ic,
            publics,
            &proof_a,
            &proof_b,
            &proof_c,
        );
        assert!(ok, err);
    }

    fun pairing_fq12_bytes(
        alpha_g1: &crypto_algebra::Element<G1>,
        beta_g2: &crypto_algebra::Element<G2>,
    ): vector<u8> {
        let paired = crypto_algebra::pairing<G1, G2, Gt>(alpha_g1, beta_g2);
        let upcasted = crypto_algebra::upcast<Gt, Fq12>(&paired);
        crypto_algebra::serialize<Fq12, FormatFq12LscLsb>(&upcasted)
    }

    fun neg_g2_bytes(g2: &crypto_algebra::Element<G2>): vector<u8> {
        let neg = crypto_algebra::neg<G2>(g2);
        crypto_algebra::serialize<G2, FormatG2Uncompr>(&neg)
    }

    // WB3/FG4 gas opt: sig 6 deserializers from `vector<u8>` by-value → `&vector<u8>` ref.
    // Internal crypto_algebra::deserialize already takes &bytes, so by-value was pure overhead
    // (forced clone at every callsite). Also: 3 g1/g2/fq12 helpers had `option::extract(&mut opt)`
    // which leaves a None placeholder + drops it — `option::destroy_some(opt)` (already used by
    // de_fr) consumes by-value, cleaner + fewer ops. Codex S4 confirmed multi-call batch
    // pattern allowed (not the rejected single-callsite option::destroy_some variant).
    //
    // de_fr (no-error) + de_fq12 (no-error) DROPPED: zero callers in this file. Sole callers of
    // de_g1/de_g2 no-error are publish_prepared_*_vk entries (4 sites × 4 fields, admin only).
    fun de_fr_with_error(bytes: &vector<u8>, err: u64): crypto_algebra::Element<Fr> {
        let opt = crypto_algebra::deserialize<Fr, FormatFrLsb>(bytes);
        assert!(option::is_some(&opt), err);
        option::destroy_some(opt)
    }

    // Round 5 Wave F.2 (R5-T): unchecked Fr deserialize for canonical-by-construction
    // bytes. Callers MUST guarantee `bytes` is a canonical 32B little-endian Fr scalar
    // (Poseidon outputs, derive_asset_id output, compute_amount_p_digest_v2 output).
    // For ANY user-supplied input use `de_fr_with_error` instead. Saves the option::
    // is_some assert + the abort branch (~50-150 gas per Groth16 verify).
    fun de_fr_unchecked(bytes: &vector<u8>): crypto_algebra::Element<Fr> {
        option::destroy_some(crypto_algebra::deserialize<Fr, FormatFrLsb>(bytes))
    }

    fun de_g1(bytes: &vector<u8>): crypto_algebra::Element<G1> {
        de_g1_with_error(bytes, E_INVALID_DEPOSIT_BINDING_PROOF)
    }

    fun de_g1_with_error(bytes: &vector<u8>, err: u64): crypto_algebra::Element<G1> {
        let opt = crypto_algebra::deserialize<G1, FormatG1Uncompr>(bytes);
        assert!(option::is_some(&opt), err);
        option::destroy_some(opt)
    }

    fun de_g2(bytes: &vector<u8>): crypto_algebra::Element<G2> {
        de_g2_with_error(bytes, E_INVALID_DEPOSIT_BINDING_PROOF)
    }

    fun de_g2_with_error(bytes: &vector<u8>, err: u64): crypto_algebra::Element<G2> {
        let opt = crypto_algebra::deserialize<G2, FormatG2Uncompr>(bytes);
        assert!(option::is_some(&opt), err);
        option::destroy_some(opt)
    }

    fun de_fq12_with_error(bytes: &vector<u8>, err: u64): crypto_algebra::Element<Fq12> {
        let opt = crypto_algebra::deserialize<Fq12, FormatFq12LscLsb>(bytes);
        assert!(option::is_some(&opt), err);
        option::destroy_some(opt)
    }

    fun assert_g1(bytes: &vector<u8>, err: u64) {
        assert!(vector::length(bytes) == G1_UNCOMPRESSED_BYTES, err);
    }

    fun assert_g2(bytes: &vector<u8>, err: u64) {
        assert!(vector::length(bytes) == G2_UNCOMPRESSED_BYTES, err);
    }

    // WB3/FH4.1+FH4.2 gas opt: bulk vector::append of 24-zero tail instead of two while-loops.
    // bcs::to_bytes(&u64) deterministically returns 8 LE bytes; just append 24 zeros for the
    // FR_BYTES (32) pad. Output byte-identical (8B LE + 24B zeros). Eliminates 32 push_back
    // iters + the intermediate byte-by-byte copy loop.
    fun u64_to_fr_bytes(n: u64): vector<u8> {
        let out = bcs::to_bytes(&n);
        vector::append(&mut out, vector[0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                                        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
                                        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
        out
    }

    // WB3/FH3.1 REVERTED (codex micro-review): vendored `std::vector::slice` is itself a Move
    // loop (vector.move::732), not a native memcpy. Switching to it added our bounds assert +
    // the stdlib's bounds assert + the same per-byte push_back loop. Net was neutral-to-worse.
    // Restored the original explicit loop — at least we pay only one bounds assert path.
    fun byte_slice_exact(src: &vector<u8>, start: u64, end: u64, err: u64): vector<u8> {
        let n = vector::length(src);
        assert!(start <= end && end <= n, err);
        let out = vector::empty<u8>();
        let i = start;
        while (i < end) {
            vector::push_back(&mut out, *vector::borrow(src, i));
            i = i + 1;
        };
        out
    }

    // R5-G (Round 5 A.3): unchecked variant — skips `vector::length(src)` read + bounds
    // assert. Safe ONLY when caller has already validated `end <= length(src)` via an
    // outer gate. Used by assert_groth16_prepared where line 2757 already asserts
    // `length(&proof) == PROOF_BYTES = 256`, guaranteeing the 3 proof-element slices
    // (0..64, 64..192, 192..256) are all in-bounds. Saves ~200-400 gas per Groth16
    // verify (3 redundant vector::length + bounds-assert bundles eliminated).
    //
    // SAFETY: do NOT call this without a prior `assert!(vector::length(src) >= end, ...)`.
    fun byte_slice_unchecked(src: &vector<u8>, start: u64, end: u64): vector<u8> {
        let out = vector::empty<u8>();
        let i = start;
        while (i < end) {
            vector::push_back(&mut out, *vector::borrow(src, i));
            i = i + 1;
        };
        out
    }

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

    fun byte_slice_padded(src: &vector<u8>, start: u64, end: u64): vector<u8> {
        // Preserve our error code; vector::slice would abort with the stdlib code otherwise.
        assert!(start <= end && end <= vector::length(src), E_INVALID_DEPOSIT_BINDING_PROOF);
        let out = vector::slice(src, start, end);
        let cur = end - start;
        while (cur < FR_BYTES) {
            vector::push_back(&mut out, 0u8);
            cur = cur + 1;
        };
        out
    }

    fun derive_asset_id(asset_type: Object<fungible_asset::Metadata>): vector<u8> acquires DepositBindingTestOverride {
        if (exists<DepositBindingTestOverride>(@eunoma)) {
            return borrow_global<DepositBindingTestOverride>(@eunoma).asset_id_fr
        };
        derive_address_hash(object::object_address(&asset_type), POSEIDON_DOMAIN_ASSET_ID_FR)
    }

    fun derive_vault_addr_hash(vault_addr: address): vector<u8> acquires DepositBindingTestOverride {
        if (exists<DepositBindingTestOverride>(@eunoma)) {
            return borrow_global<DepositBindingTestOverride>(@eunoma).vault_addr_hash_fr
        };
        derive_address_hash(vault_addr, POSEIDON_DOMAIN_VAULT_ADDR_HASH_FR)
    }

    fun derive_recipient_hash(recipient: address): vector<u8> {
        derive_address_hash(recipient, POSEIDON_DOMAIN_RECIPIENT_HASH_FR)
    }

    // Round 4 WB2.E C / FR-1.5b: takes pre-computed `domain_fr` (32B, already
    // bytes_to_field_le32-equivalent of the original POSEIDON_DOMAIN_* string). Drops the
    // per-call `bytes_to_field_le32` work. Domain consts above are compile-time precomputed
    // and byte-equivalent to the old runtime-derived form.
    fun derive_address_hash(addr: address, domain_fr: vector<u8>): vector<u8> {
        let addr_bytes = bcs::to_bytes(&addr);
        assert!(vector::length(&addr_bytes) == FR_BYTES, E_BAD_HASH_LENGTH);
        let hi = byte_slice_padded(&addr_bytes, 0, 16);
        let lo = byte_slice_padded(&addr_bytes, 16, 32);
        poseidon_bn254::hash_3(domain_fr, hi, lo)
    }

    /// Stage 3 A6: compute amount_p_digest from the CA framework's 4 × 32B Ristretto amount_p.
    ///
    /// Mirrors circuits/{deposit_binding,withdrawal_proof}.circom Compose8 template +
    /// circuits/scripts/compute_{deposit,withdraw}_witness.mjs compose8() helper.
    ///
    /// Each 32B compressed Ristretto point p[k] is split into 2 × 16B little-endian limbs:
    ///   p[k]_lo = byte_slice_padded(p[k], 0, 16)   // bytes 0..16, padded right to 32B for Fr
    ///   p[k]_hi = byte_slice_padded(p[k], 16, 32)  // bytes 16..32, padded right to 32B for Fr
    /// Then 8 limbs are hashed in the Compose8 tree (only hash_2 + hash_3 are available in
    /// eunoma_pool::poseidon_bn254; matches circuit Compose8 exactly):
    ///   a = hash_3(p[0]_lo, p[0]_hi, p[1]_lo)
    ///   b = hash_3(p[1]_hi, p[2]_lo, p[2]_hi)
    ///   c = hash_2(p[3]_lo, p[3]_hi)
    ///   digest = hash_3(a, b, c)
    ///
    /// IMPORTANT: limb ORDER must exactly match the circuit / JS witness builder, which is
    /// [p[0]_lo, p[0]_hi, p[1]_lo, p[1]_hi, p[2]_lo, p[2]_hi, p[3]_lo, p[3]_hi]. The
    /// Compose8 tree consumes them in that order: a takes limbs [0,1,2], b takes [3,4,5],
    /// c takes [6,7].
    fun compute_amount_p_digest_v2(amount_p: &vector<vector<u8>>): vector<u8> {
        // CA framework TRANSFER_AMOUNT_CHUNK_COUNT = 4; each chunk is a 32B compressed Ristretto point.
        assert!(vector::length(amount_p) == 4, E_INVALID_AMOUNT_P_SHAPE);

        let p0 = vector::borrow(amount_p, 0);
        let p1 = vector::borrow(amount_p, 1);
        let p2 = vector::borrow(amount_p, 2);
        let p3 = vector::borrow(amount_p, 3);
        // R5-L REVERTED (codex Wave A review RED): exact 32-byte length asserts retained.
        // R6-F.4: collapse 4 inner length asserts into single short-circuit `&&` assert
        // — same error code, same trip behavior, saves 3 assert-frame setups on fallback
        // paths (V3-hit happy path skips this whole function). ~80-160 gas/fallback.
        assert!(
            vector::length(p0) == 32
                && vector::length(p1) == 32
                && vector::length(p2) == 32
                && vector::length(p3) == 32,
            E_INVALID_AMOUNT_P_SHAPE
        );

        // H1 gas opt: inline byte_slice_padded (8 fn-call frames eliminated, ~160 gas).
        // Each slice is 16B from p_i, padded with 16 trailing zeros to 32B (matches FR_BYTES=32).
        let p0_lo = vector::slice(p0, 0, 16);
        let i = 0; while (i < 16) { vector::push_back(&mut p0_lo, 0u8); i = i + 1; };
        let p0_hi = vector::slice(p0, 16, 32);
        let i = 0; while (i < 16) { vector::push_back(&mut p0_hi, 0u8); i = i + 1; };
        let p1_lo = vector::slice(p1, 0, 16);
        let i = 0; while (i < 16) { vector::push_back(&mut p1_lo, 0u8); i = i + 1; };
        let p1_hi = vector::slice(p1, 16, 32);
        let i = 0; while (i < 16) { vector::push_back(&mut p1_hi, 0u8); i = i + 1; };
        let p2_lo = vector::slice(p2, 0, 16);
        let i = 0; while (i < 16) { vector::push_back(&mut p2_lo, 0u8); i = i + 1; };
        let p2_hi = vector::slice(p2, 16, 32);
        let i = 0; while (i < 16) { vector::push_back(&mut p2_hi, 0u8); i = i + 1; };
        let p3_lo = vector::slice(p3, 0, 16);
        let i = 0; while (i < 16) { vector::push_back(&mut p3_lo, 0u8); i = i + 1; };
        let p3_hi = vector::slice(p3, 16, 32);
        let i = 0; while (i < 16) { vector::push_back(&mut p3_hi, 0u8); i = i + 1; };

        // Compose8 tree (matches circom Compose8 + JS compose8). VK-locked topology.
        let a = poseidon_bn254::hash_3(p0_lo, p0_hi, p1_lo);
        let b = poseidon_bn254::hash_3(p1_hi, p2_lo, p2_hi);
        let c = poseidon_bn254::hash_2(p3_lo, p3_hi);
        poseidon_bn254::hash_3(a, b, c)
    }

    fun assert_hash(bytes: &vector<u8>) {
        assert!(vector::length(bytes) == HASH_BYTES, E_BAD_HASH_LENGTH);
    }

    // Round 5 Wave G.2 (R5-P): inline helper for the 6-hash assertion block shared
    // by 5 withdraw entry points (withdraw_to_recipient_v2 + prepare_withdraw_{proof,
    // attestation}_v{2,3}). `inline fun` inlines at compile time so per-call overhead
    // = 6× direct assert! (no function-call dispatch). Saves ~225 gas total across
    // all 5 entries plus bytecode-size shrinkage. Semantics identical to 6 sequential
    // assert_hash calls.
    inline fun assert_6_withdraw_hashes(
        root: &vector<u8>,
        nullifier_hash: &vector<u8>,
        recipient_hash: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
        request_hash: &vector<u8>,
    ) {
        assert!(vector::length(root) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(nullifier_hash) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(recipient_hash) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(amount_tag) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(ca_payload_hash) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(request_hash) == HASH_BYTES, E_BAD_HASH_LENGTH);
    }

    // R6-A.1: inline 3-hash helper for deposit_with_commitment_v2 entry assert block.
    inline fun assert_3_deposit_hashes(
        commitment: &vector<u8>,
        amount_tag: &vector<u8>,
        ca_payload_hash: &vector<u8>,
    ) {
        assert!(vector::length(commitment) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(amount_tag) == HASH_BYTES, E_BAD_HASH_LENGTH);
        assert!(vector::length(ca_payload_hash) == HASH_BYTES, E_BAD_HASH_LENGTH);
    }

    #[test_only]
    public fun test_only_assert_3_deposit_hashes(c: vector<u8>, a: vector<u8>, p: vector<u8>) {
        assert_3_deposit_hashes(&c, &a, &p);
    }

    // R7-W1: composite (sender, commitment) key for PendingDeposit*V3 tables. Closes
    // squat-DoS class — attacker can no longer occupy a victim's commitment slot because
    // their own address is part of the key. sender_bytes (32B BCS) || commitment (32B) = 64B key.
    inline fun compose_pending_key(sender: address, commitment: &vector<u8>): vector<u8> {
        let key = bcs::to_bytes(&sender);
        vector::append(&mut key, *commitment);
        key
    }

    #[test_only]
    public fun test_only_compose_pending_key(sender: address, commitment: vector<u8>): vector<u8> {
        compose_pending_key(sender, &commitment)
    }

    fun assert_not_expired(expiry_secs: u64) {
        assert!(timestamp::now_seconds() <= expiry_secs, E_EXPIRED);
    }

    fun bit_is_set(bitmap: u8, index: u64): bool {
        ((bitmap >> (index as u8)) & 1u8) == 1u8
    }

    #[test_only]
    public entry fun install_deposit_binding_test_override_v2(
        admin: &signer,
        asset_id_fr: vector<u8>,
        vault_addr_hash_fr: vector<u8>,
    ) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<DepositBindingTestOverride>(@eunoma), E_ALREADY_INITIALIZED);
        assert_hash(&asset_id_fr);
        assert_hash(&vault_addr_hash_fr);
        move_to(admin, DepositBindingTestOverride { asset_id_fr, vault_addr_hash_fr });
    }

    #[test_only]
    public fun test_call_hash_confidential_transfer_payload_v2(
        asset_type: Object<fungible_asset::Metadata>,
        to: address,
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
        hash_confidential_transfer_payload_v2(
            &asset_type,
            &to,
            &new_balance_p,
            &new_balance_r,
            &new_balance_r_eff_aud,
            &amount_p,
            &amount_r_sender,
            &amount_r_recip,
            &amount_r_eff_aud,
            &ek_volun_auds,
            &amount_r_volun_auds,
            &zkrp_new_balance,
            &zkrp_amount,
            &sigma_proto_comm,
            &sigma_proto_resp,
            &memo,
        )
    }

    #[test_only]
    public fun test_call_ca_payload_hash_to_fr_safe_v2(raw: vector<u8>): vector<u8> {
        ca_payload_hash_to_fr_safe(raw)
    }

    public fun e_bad_threshold(): u64 { E_BAD_THRESHOLD }
    public fun e_invalid_deop_signature(): u64 { E_INVALID_DEOP_SIGNATURE }
    public fun e_too_few_deop_signatures(): u64 { E_TOO_FEW_DEOP_SIGNATURES }
    public fun e_payload_hash_mismatch(): u64 { E_PAYLOAD_HASH_MISMATCH }
    public fun e_invalid_deposit_binding_proof(): u64 { E_INVALID_DEPOSIT_BINDING_PROOF }
    public fun e_invalid_withdraw_proof(): u64 { E_INVALID_WITHDRAW_PROOF }
    public fun e_recipient_hash_mismatch(): u64 { E_RECIPIENT_HASH_MISMATCH }
    public fun e_pending_withdraw_attestation(): u64 { E_PENDING_WITHDRAW_ATTESTATION }

    // =================================================================================
    // FR-1.5(a) Round 4 F: codex-required cache-pollution unit-test scaffolding.
    // Shims are #[test_only] (excluded from production bytecode). They expose minimal
    // state injection + cache-comparison hooks so tests verify the downstream cache-
    // mismatch detection (consume_or_verify_withdraw_attestation V2-branch line ~2587-2603
    // and V3-branch line ~2553-2581) still fires after F5 drops the redundant entry-level
    // derive_recipient_hash checks at prepare_withdraw_attestation_v{2,3}. Production
    // code paths are unchanged.
    // =================================================================================

    #[test_only]
    public fun test_only_init_pending_attestations(admin: &signer) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_INITIALIZED);
        if (!exists<PendingWithdrawAttestationsV2>(@eunoma)) {
            move_to(admin, PendingWithdrawAttestationsV2 { by_request_hash: table::new() });
        };
        if (!exists<PendingWithdrawAttestationsV2b>(@eunoma)) {
            move_to(admin, PendingWithdrawAttestationsV2b { by_request_hash: table::new() });
        };
        if (!exists<PendingWithdrawAttestationsV3>(@eunoma)) {
            move_to(admin, PendingWithdrawAttestationsV3 { by_request_hash: table::new() });
        };
    }

    // Round 5 Wave E.1 (R5-D) test shim: inject a V2b cache entry (msg_hash-only).
    #[test_only]
    public fun test_only_inject_v2b_attestation(
        request_hash: vector<u8>,
        msg_hash: vector<u8>,
    ) acquires PendingWithdrawAttestationsV2b {
        let pending = borrow_global_mut<PendingWithdrawAttestationsV2b>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_ATTESTATION,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawAttestationV2b { msg_hash });
    }

    // Round 5 Wave E.1 (R5-D): V2b cache-hit msg_hash equality check (same shape as V3).
    #[test_only]
    public fun test_only_v2b_cache_msg_hash_matches(
        request_hash: vector<u8>,
        expected_msg_hash: vector<u8>,
    ): bool acquires PendingWithdrawAttestationsV2b {
        let pending = borrow_global<PendingWithdrawAttestationsV2b>(@eunoma);
        if (!table::contains(&pending.by_request_hash, *&request_hash)) {
            return false
        };
        let cached = table::borrow(&pending.by_request_hash, *&request_hash);
        cached.msg_hash == expected_msg_hash
    }

    #[test_only]
    public fun test_only_v2b_cache_entry_exists(
        request_hash: vector<u8>,
    ): bool acquires PendingWithdrawAttestationsV2b {
        let pending = borrow_global<PendingWithdrawAttestationsV2b>(@eunoma);
        table::contains(&pending.by_request_hash, *&request_hash)
    }

    // Round 5 Wave E.1 (R5-D): pop V2b entry (mimics consume_or_verify_withdraw_attestation
    // V2b branch table::remove after msg_hash equality). Returns the cached msg_hash so
    // the round-trip test can verify it matches what prepare wrote.
    #[test_only]
    public fun test_only_v2b_pop(
        request_hash: vector<u8>,
    ): vector<u8> acquires PendingWithdrawAttestationsV2b {
        let pending = borrow_global_mut<PendingWithdrawAttestationsV2b>(@eunoma);
        let cached = table::remove(&mut pending.by_request_hash, request_hash);
        cached.msg_hash
    }

    // Round 5 Wave E.2 (P06-1) test shims: V2b proof cache (no asset_id field).
    #[test_only]
    public fun test_only_init_pending_proofs_v2b(admin: &signer) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_INITIALIZED);
        if (!exists<PendingWithdrawProofsV2b>(@eunoma)) {
            move_to(admin, PendingWithdrawProofsV2b { by_request_hash: table::new() });
        };
    }

    #[test_only]
    public fun test_only_inject_v2b_proof(
        request_hash: vector<u8>,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
        amount_p_digest: vector<u8>,
    ) acquires PendingWithdrawProofsV2b {
        let pending = borrow_global_mut<PendingWithdrawProofsV2b>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_PROOF,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawProofV2b {
            root, nullifier_hash, recipient_hash, amount_tag,
            ca_payload_hash, vault_sequence, amount_p_digest,
        });
    }

    #[test_only]
    public fun test_only_v2b_proof_entry_exists(
        request_hash: vector<u8>,
    ): bool acquires PendingWithdrawProofsV2b {
        let pending = borrow_global<PendingWithdrawProofsV2b>(@eunoma);
        table::contains(&pending.by_request_hash, *&request_hash)
    }

    // Returns (vault_sequence, amount_p_digest, recipient_hash) so the test can verify the
    // 7 fields survive a round-trip. asset_id deliberately NOT stored.
    #[test_only]
    public fun test_only_v2b_proof_pop_triplet(
        request_hash: vector<u8>,
    ): (u64, vector<u8>, vector<u8>) acquires PendingWithdrawProofsV2b {
        let pending = borrow_global_mut<PendingWithdrawProofsV2b>(@eunoma);
        let c = table::remove(&mut pending.by_request_hash, request_hash);
        let PendingWithdrawProofV2b {
            root: _, nullifier_hash: _, recipient_hash, amount_tag: _,
            ca_payload_hash: _, vault_sequence, amount_p_digest,
        } = c;
        (vault_sequence, amount_p_digest, recipient_hash)
    }

    // Round 5 Wave E.5 (R5-R) test shims: V3b proof cache (7 fields).
    #[test_only]
    public fun test_only_init_pending_proofs_v3b(admin: &signer) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_INITIALIZED);
        if (!exists<PendingWithdrawProofsV3b>(@eunoma)) {
            move_to(admin, PendingWithdrawProofsV3b { by_request_hash: table::new() });
        };
    }

    #[test_only]
    public fun test_only_inject_v3b_proof(
        request_hash: vector<u8>,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
        amount_p_digest: vector<u8>,
    ) acquires PendingWithdrawProofsV3b {
        let pending = borrow_global_mut<PendingWithdrawProofsV3b>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_PROOF,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawProofV3b {
            root, nullifier_hash, recipient_hash, amount_tag,
            ca_payload_hash, vault_sequence, amount_p_digest,
        });
    }

    #[test_only]
    public fun test_only_v3b_proof_entry_exists(
        request_hash: vector<u8>,
    ): bool acquires PendingWithdrawProofsV3b {
        let pending = borrow_global<PendingWithdrawProofsV3b>(@eunoma);
        table::contains(&pending.by_request_hash, *&request_hash)
    }

    // Returns the cross-stage fields used by prepare_withdraw_payload_v3 FR-4.6 hotfix:
    // (ca_payload_hash, amount_p_digest). Same fields V3 partial cache exposes; this test
    // verifies V3b also exposes them so the stage-2 reader can swap V3 → V3b transparently.
    #[test_only]
    public fun test_only_v3b_proof_cross_stage_fields(
        request_hash: vector<u8>,
    ): (vector<u8>, vector<u8>) acquires PendingWithdrawProofsV3b {
        let pending = borrow_global<PendingWithdrawProofsV3b>(@eunoma);
        let c = table::borrow(&pending.by_request_hash, *&request_hash);
        (*&c.ca_payload_hash, *&c.amount_p_digest)
    }

    #[test_only]
    public fun test_only_v3b_proof_pop_triplet(
        request_hash: vector<u8>,
    ): (u64, vector<u8>, vector<u8>) acquires PendingWithdrawProofsV3b {
        let pending = borrow_global_mut<PendingWithdrawProofsV3b>(@eunoma);
        let c = table::remove(&mut pending.by_request_hash, request_hash);
        let PendingWithdrawProofV3b {
            root: _, nullifier_hash: _, recipient_hash, amount_tag: _,
            ca_payload_hash: _, vault_sequence, amount_p_digest,
        } = c;
        // (vault_sequence, amount_p_digest, recipient_hash) — same shape as V2b shim so
        // both round-trip tests can share assert pattern.
        (vault_sequence, amount_p_digest, recipient_hash)
    }

    // Simulates a maliciously-signed-but-mismatched prepare_v2 (which would require
    // 5-of-7 deoperator threshold compromise to actually craft a valid sig). Asserts
    // the same collision-check production uses (line ~1353-1356): second insert with
    // the same request_hash aborts with E_PENDING_WITHDRAW_ATTESTATION.
    #[test_only]
    public fun test_only_inject_v2_attestation(
        request_hash: vector<u8>,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
    ) acquires PendingWithdrawAttestationsV2 {
        let pending = borrow_global_mut<PendingWithdrawAttestationsV2>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_ATTESTATION,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawAttestationV2 {
            vault, asset_type, operator_set_version, dkg_epoch, roster_hash,
            frost_group_pubkey, root, nullifier_hash, recipient, recipient_hash,
            amount_tag, ca_payload_hash, vault_sequence, expiry_secs, circuit_versions_hash,
        });
    }

    #[test_only]
    public fun test_only_inject_v3_attestation(
        request_hash: vector<u8>,
        msg_hash: vector<u8>,
    ) acquires PendingWithdrawAttestationsV3 {
        let pending = borrow_global_mut<PendingWithdrawAttestationsV3>(@eunoma);
        assert!(
            !table::contains(&pending.by_request_hash, *&request_hash),
            E_PENDING_WITHDRAW_ATTESTATION,
        );
        table::add(&mut pending.by_request_hash, request_hash, PendingWithdrawAttestationV3 { msg_hash });
    }

    // Mirrors line ~2595 V2-branch assertion: returns false (would abort
    // E_INVALID_DEOP_SIGNATURE) when cached.recipient != expected_recipient.
    #[test_only]
    public fun test_only_v2_cache_recipient_matches(
        request_hash: vector<u8>,
        expected_recipient: address,
    ): bool acquires PendingWithdrawAttestationsV2 {
        let pending = borrow_global<PendingWithdrawAttestationsV2>(@eunoma);
        if (!table::contains(&pending.by_request_hash, *&request_hash)) {
            return false
        };
        let cached = table::borrow(&pending.by_request_hash, *&request_hash);
        cached.recipient == expected_recipient
    }

    // Mirrors line ~2579 V3-branch assertion: returns false (would abort
    // E_INVALID_DEOP_SIGNATURE) when cached.msg_hash != expected_msg_hash.
    #[test_only]
    public fun test_only_v3_cache_msg_hash_matches(
        request_hash: vector<u8>,
        expected_msg_hash: vector<u8>,
    ): bool acquires PendingWithdrawAttestationsV3 {
        let pending = borrow_global<PendingWithdrawAttestationsV3>(@eunoma);
        if (!table::contains(&pending.by_request_hash, *&request_hash)) {
            return false
        };
        let cached = table::borrow(&pending.by_request_hash, *&request_hash);
        cached.msg_hash == expected_msg_hash
    }

    // Mirrors the `use_pending` gate at consume_or_verify_withdraw_attestation
    // (line ~2550-2552): cache is consulted ONLY when caller passes no signature.
    // Any non-empty group_signature OR non-zero fallback_bitmap OR non-empty
    // fallback_signatures bypasses the cache entirely (no table::remove, no
    // cache-mismatch assertion) and goes straight to FROST/fallback sig verify.
    // Returns true iff the cache path would be taken (= use_pending semantics).
    #[test_only]
    public fun test_only_compute_use_pending(
        group_signature: vector<u8>,
        fallback_bitmap: u8,
        fallback_signatures: vector<vector<u8>>,
    ): bool {
        vector::length(&group_signature) == 0
            && fallback_bitmap == 0
            && vector::length(&fallback_signatures) == 0
    }

    // Returns true iff a V2 cache entry exists for the given request_hash.
    // Used by bypass tests to assert that non-cache paths do NOT consume the entry.
    #[test_only]
    public fun test_only_v2_cache_entry_exists(
        request_hash: vector<u8>,
    ): bool acquires PendingWithdrawAttestationsV2 {
        let pending = borrow_global<PendingWithdrawAttestationsV2>(@eunoma);
        table::contains(&pending.by_request_hash, *&request_hash)
    }

    #[test_only]
    public fun test_only_v3_cache_entry_exists(
        request_hash: vector<u8>,
    ): bool acquires PendingWithdrawAttestationsV3 {
        let pending = borrow_global<PendingWithdrawAttestationsV3>(@eunoma);
        table::contains(&pending.by_request_hash, *&request_hash)
    }

    // R5-C (Round 5 Wave C) byte-identity test shims.
    #[test_only]
    public fun test_only_serialize_withdraw_attestation_v2_msg(
        domain: vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
    ): vector<u8> {
        serialize_withdraw_attestation_v2_msg(
            &domain, chain_id, bridge, vault, asset_type,
            operator_set_version, dkg_epoch,
            &roster_hash, &frost_group_pubkey,
            &root, &nullifier_hash, recipient,
            &recipient_hash, &amount_tag, &ca_payload_hash, &request_hash,
            vault_sequence, expiry_secs, &circuit_versions_hash,
        )
    }

    #[test_only]
    public fun test_only_struct_bcs_withdraw_attestation_v2_msg(
        domain: vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        root: vector<u8>,
        nullifier_hash: vector<u8>,
        recipient: address,
        recipient_hash: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        request_hash: vector<u8>,
        vault_sequence: u64,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
    ): vector<u8> {
        let msg = WithdrawAttestationV2Message {
            domain,
            chain_id,
            bridge,
            vault,
            asset_type,
            operator_set_version,
            dkg_epoch,
            roster_hash,
            frost_group_pubkey,
            root,
            nullifier_hash,
            recipient,
            recipient_hash,
            amount_tag,
            ca_payload_hash,
            request_hash,
            vault_sequence,
            expiry_secs,
            circuit_versions_hash,
        };
        bcs::to_bytes(&msg)
    }

    // R6-Plan-B test shims for split-tx deposit (PendingDepositFinalizationV3).
    #[test_only]
    public entry fun test_only_init_pending_deposit_finalizations_v3(admin: &signer) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<PendingDepositFinalizationsV3>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, PendingDepositFinalizationsV3 {
            by_commitment: table::new<vector<u8>, PendingDepositFinalizationV3>(),
        });
    }

    // R7-OPS-1: test shims for RecorderDelegate (bypass assert_admin which requires
    // full BridgeVault init — out of scope for unit tests; integration covered by
    // testnet admin init tx + alpha box deploy).
    #[test_only]
    public entry fun test_only_init_recorder_delegate(admin: &signer) {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(!exists<RecorderDelegate>(@eunoma), E_ALREADY_INITIALIZED);
        move_to(admin, RecorderDelegate { addr: signer::address_of(admin) });
    }

    #[test_only]
    public entry fun test_only_set_recorder_delegate(admin: &signer, delegate_addr: address)
        acquires RecorderDelegate
    {
        assert!(signer::address_of(admin) == @eunoma, E_NOT_ADMIN);
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global_mut<RecorderDelegate>(@eunoma);
        rd.addr = delegate_addr;
    }

    #[test_only]
    public fun test_only_recorder_delegate_addr(): address acquires RecorderDelegate {
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        borrow_global<RecorderDelegate>(@eunoma).addr
    }

    #[test_only]
    public fun test_only_assert_delegate_auth(delegate: &signer) acquires RecorderDelegate {
        // Mirrors the auth check inside record_known_root_v2_via_delegate without
        // calling record_known_root_internal (which needs BridgeVaultTablesV2 init).
        assert!(exists<RecorderDelegate>(@eunoma), E_RECORDER_DELEGATE_NOT_INITIALIZED);
        let rd = borrow_global<RecorderDelegate>(@eunoma);
        assert!(signer::address_of(delegate) == rd.addr, E_NOT_RECORDER_DELEGATE);
    }

    // R7-W1: composite key (sender, commitment) for test injection / read.
    #[test_only]
    public fun test_only_inject_pending_finalization(
        commitment: vector<u8>,
        sender: address,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
    ) acquires PendingDepositFinalizationsV3 {
        let key = compose_pending_key(sender, &commitment);
        let pending = borrow_global_mut<PendingDepositFinalizationsV3>(@eunoma);
        table::add(&mut pending.by_commitment, key, PendingDepositFinalizationV3 {
            sender,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
            expiry_secs,
        });
    }

    #[test_only]
    public fun test_only_pending_finalization_exists(sender: address, commitment: vector<u8>): bool
        acquires PendingDepositFinalizationsV3
    {
        if (!exists<PendingDepositFinalizationsV3>(@eunoma)) { return false };
        let key = compose_pending_key(sender, &commitment);
        let pending = borrow_global<PendingDepositFinalizationsV3>(@eunoma);
        table::contains(&pending.by_commitment, key)
    }

    #[test_only]
    public fun test_only_pending_finalization_read(sender: address, commitment: vector<u8>): (address, vector<u8>, vector<u8>, vector<u8>, u64)
        acquires PendingDepositFinalizationsV3
    {
        let key = compose_pending_key(sender, &commitment);
        let pending = borrow_global<PendingDepositFinalizationsV3>(@eunoma);
        let entry = table::borrow(&pending.by_commitment, key);
        (entry.sender, *&entry.amount_tag, *&entry.ca_payload_hash, *&entry.deposit_nonce, entry.expiry_secs)
    }

    // R6-C.1 byte-identity test shims (mirror R5-C pattern above).
    #[test_only]
    public fun test_only_serialize_deposit_attestation_v3_msg(
        domain: vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
        user_addr: address,
    ): vector<u8> {
        serialize_deposit_attestation_v3_msg(
            &domain, chain_id, bridge, vault, asset_type,
            operator_set_version, dkg_epoch,
            &roster_hash, &frost_group_pubkey,
            &commitment, &amount_tag, &ca_payload_hash, &deposit_nonce,
            expiry_secs, &circuit_versions_hash, user_addr,
        )
    }

    #[test_only]
    public fun test_only_struct_bcs_deposit_attestation_v3_msg(
        domain: vector<u8>,
        chain_id: u8,
        bridge: address,
        vault: address,
        asset_type: address,
        operator_set_version: u64,
        dkg_epoch: u64,
        roster_hash: vector<u8>,
        frost_group_pubkey: vector<u8>,
        commitment: vector<u8>,
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
        expiry_secs: u64,
        circuit_versions_hash: vector<u8>,
        user_addr: address,
    ): vector<u8> {
        let msg = DepositAttestationV3Message {
            domain,
            chain_id,
            bridge,
            vault,
            asset_type,
            operator_set_version,
            dkg_epoch,
            roster_hash,
            frost_group_pubkey,
            commitment,
            amount_tag,
            ca_payload_hash,
            deposit_nonce,
            expiry_secs,
            circuit_versions_hash,
            user_addr,
        };
        bcs::to_bytes(&msg)
    }
}

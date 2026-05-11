// Phase D.0 gas-measurement bench wrappers around eunoma's hot-path functions.
//
// One `entry fun` per measurement target. Each one is called once via
// `aptos move run --session --function-id eunoma_bench::bench_eunoma::<fn>`
// and `gas_used` is parsed from the JSON output. The constant tx-entry overhead
// (auth, sequence bump, etc.) cancels out in candidate-vs-baseline comparisons.
//
// Run via `mvp-backend/move/scripts/measure_gas.sh <fn_name>`.
//
// Bench module is in a separate subpackage (eunoma_bench) so it is *never*
// published to the live testnet — only to ephemeral sim sessions. No attack
// surface on the production deployment.

module eunoma_bench::bench_eunoma {
    use std::vector;
    use aptos_framework::event;
    use eunoma::pool_multi_sig_verifier;
    use eunoma_bench::bench_keys;

    // Bare-minimum entry. Measures the tx envelope cost (~29 gas). Useful as a
    // floor — subtract this from other bench numbers to get the "pure function
    // cost". Phase D.0 smoke test target.
    public entry fun bench_noop() {
        // Intentionally empty.
    }

    /// Phase D.0 — measure `pool_multi_sig_verifier::assert_valid_attestation`
    /// with a valid 4-of-7 attestation (slot 0 = main + slots 1,2,3, slots 4-6
    /// empty). Pubkeys + sigs + message are hardcoded from bench_keys.move
    /// (auto-generated via scripts/gen_bench_keys.ts).
    ///
    /// Expected gas: ~1500-2000 (4× ed25519::signature_verify_strict +
    /// 7-slot loop overhead + length asserts). Used to bound the impact of
    /// changes Agent D5 (multi-deposit), D7 (fail-fast), and any other agent
    /// that touches assert_valid_attestation.
    public entry fun bench_multi_sig_4of7() {
        let msg = bench_keys::message_bytes();
        let sigs = bench_keys::signatures_4of7();
        let pks = bench_keys::pubkeys();
        pool_multi_sig_verifier::assert_valid_attestation(
            msg, sigs, &pks, 4, 0,
        );
    }

    // ========================================================================
    // Phase D / Agent D6 — Event payload trim micro-benches.
    //
    // PURPOSE
    //   Quantify per-byte storage gas for emitting Eunoma's four hot-path
    //   events. The bench cannot call the real `event::emit(DepositEvent {...})`
    //   sites because (a) those events are defined `has store` in modules
    //   that own them and the structs are not public, (b) the real emit sites
    //   require fully initialized VaultConfig / PendingQueue resources which
    //   are expensive sim-session setup.
    //
    // BYTE-LAYOUT EQUIVALENCE
    //   Aptos charges per-byte storage-fee gas on event payload BCS bytes.
    //   `Object<T>` is defined in aptos_framework::object as
    //       struct Object<phantom T> has copy, drop, store { inner: address }
    //   so its BCS encoding is identical to a bare `address` (32 bytes). We
    //   therefore mirror DepositEvent / WithdrawEvent here with the
    //   `Object<Metadata>` field replaced by `address`. The fixed-size fields
    //   (`u64`) and variable-size fields (`vector<u8>`) have identical BCS
    //   layout. Net effect: the per-emit BCS byte count is byte-exact, and
    //   the storage-fee gas charged is the same as the production emit.
    //
    // BASELINE vs CANDIDATE
    //   For each event we provide two structs + two entry funs:
    //     bench_emit_<event>_baseline()  — all fields present (current ABI)
    //     bench_emit_<event>_candidate() — proposed trimmed fields removed
    //   Delta = baseline - candidate is the per-emit storage-gas saved by
    //   dropping the field.
    // ========================================================================

    // ---- Helpers ----

    // Build a 32-byte vector with deterministic content (i = i-th byte).
    fun bytes32(): vector<u8> {
        let v = vector::empty<u8>();
        let i: u64 = 0;
        while (i < 32) {
            vector::push_back(&mut v, (i as u8));
            i = i + 1;
        };
        v
    }

    // Fixed placeholder asset address — byte-cost-equivalent to a real
    // `Object<Metadata>.inner`. Chosen to mirror the inner address that a
    // real APT-metadata Object would carry.
    const BENCH_ASSET_ADDR: address =
        @0x000000000000000000000000000000000000000000000000000000000000000a;

    // ---- DepositEvent (eunoma_bridge.move:405) ----
    //
    // Real layout:
    //   commitment: vector<u8>,    leaf_index: u64,
    //   asset_type: Object<Metadata>, amount_tag: vector<u8>,
    //   ca_payload_hash: vector<u8>, deposit_nonce: vector<u8>,
    //
    // Candidate drops asset_type (32 bytes, fixed per deployment — readable
    // from VaultConfig view).

    #[event]
    struct BenchDepositEventBaseline has drop, store {
        commitment: vector<u8>,
        leaf_index: u64,
        asset_type: address,        // mirror of Object<Metadata> (32 bytes)
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
    }

    #[event]
    struct BenchDepositEventCandidate has drop, store {
        commitment: vector<u8>,
        leaf_index: u64,
        // asset_type DROPPED — readable from VaultConfig
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        deposit_nonce: vector<u8>,
    }

    public entry fun bench_emit_deposit_event_baseline() {
        event::emit(BenchDepositEventBaseline {
            commitment: bytes32(),
            leaf_index: 42,
            asset_type: BENCH_ASSET_ADDR,
            amount_tag: bytes32(),
            ca_payload_hash: bytes32(),
            deposit_nonce: bytes32(),
        });
    }

    public entry fun bench_emit_deposit_event_candidate() {
        event::emit(BenchDepositEventCandidate {
            commitment: bytes32(),
            leaf_index: 42,
            amount_tag: bytes32(),
            ca_payload_hash: bytes32(),
            deposit_nonce: bytes32(),
        });
    }

    // ---- WithdrawEvent (eunoma_bridge.move:376) ----
    //
    // Real layout:
    //   nullifier_hash: vector<u8>, recipient: address,
    //   asset_type: Object<Metadata>, amount_tag: vector<u8>,
    //   ca_payload_hash: vector<u8>, vault_sequence: u64,
    //
    // Candidate drops asset_type (32 bytes).

    #[event]
    struct BenchWithdrawEventBaseline has drop, store {
        nullifier_hash: vector<u8>,
        recipient: address,
        asset_type: address,        // mirror of Object<Metadata> (32 bytes)
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
    }

    #[event]
    struct BenchWithdrawEventCandidate has drop, store {
        nullifier_hash: vector<u8>,
        recipient: address,
        // asset_type DROPPED
        amount_tag: vector<u8>,
        ca_payload_hash: vector<u8>,
        vault_sequence: u64,
    }

    public entry fun bench_emit_withdraw_event_baseline() {
        event::emit(BenchWithdrawEventBaseline {
            nullifier_hash: bytes32(),
            recipient: @0xbeef,
            asset_type: BENCH_ASSET_ADDR,
            amount_tag: bytes32(),
            ca_payload_hash: bytes32(),
            vault_sequence: 123,
        });
    }

    public entry fun bench_emit_withdraw_event_candidate() {
        event::emit(BenchWithdrawEventCandidate {
            nullifier_hash: bytes32(),
            recipient: @0xbeef,
            amount_tag: bytes32(),
            ca_payload_hash: bytes32(),
            vault_sequence: 123,
        });
    }

    // ---- BatchRootUpdated (pool/batch_root_update.move:196) ----
    //
    // Real layout:
    //   batch_id: u64, old_root: vector<u8>, new_root: vector<u8>,
    //   start_index: u64, end_index: u64, batch_size: u64,
    //   queue_range_hash: vector<u8>, frontier_or_meta_hash: vector<u8>,
    //
    // Candidate drops queue_range_hash + frontier_or_meta_hash (64 bytes).
    // Both are inputs to the on-chain invariant verification (E_INV5) — once
    // verified, they're observability-only. No operator-services consumer
    // reads them back from the emitted event (verified via grep).

    #[event]
    struct BenchBatchRootUpdatedBaseline has drop, store {
        batch_id: u64,
        old_root: vector<u8>,
        new_root: vector<u8>,
        start_index: u64,
        end_index: u64,
        batch_size: u64,
        queue_range_hash: vector<u8>,
        frontier_or_meta_hash: vector<u8>,
    }

    #[event]
    struct BenchBatchRootUpdatedCandidate has drop, store {
        batch_id: u64,
        old_root: vector<u8>,
        new_root: vector<u8>,
        start_index: u64,
        end_index: u64,
        batch_size: u64,
        // queue_range_hash + frontier_or_meta_hash DROPPED (observability only)
    }

    public entry fun bench_emit_batch_root_updated_baseline() {
        event::emit(BenchBatchRootUpdatedBaseline {
            batch_id: 7,
            old_root: bytes32(),
            new_root: bytes32(),
            start_index: 0,
            end_index: 4,
            batch_size: 4,
            queue_range_hash: bytes32(),
            frontier_or_meta_hash: bytes32(),
        });
    }

    public entry fun bench_emit_batch_root_updated_candidate() {
        event::emit(BenchBatchRootUpdatedCandidate {
            batch_id: 7,
            old_root: bytes32(),
            new_root: bytes32(),
            start_index: 0,
            end_index: 4,
            batch_size: 4,
        });
    }

    // ---- DepositQueued (pool/pending_queue.move:151) ----
    //
    // Real layout:
    //   deposit_index: u64, leaf_commitment: vector<u8>,
    //   deposit_batch_id: u64, queue_position: u64,
    //   compliance_attestation_id: u64,
    //
    // Candidate drops queue_position (8 bytes). Comment in source says
    // "equal to deposit_index for MVP (1:1)" — operator-services script
    // (testnet_batch_root_update.ts) reads deposit_index, not queue_position.

    #[event]
    struct BenchDepositQueuedBaseline has drop, store {
        deposit_index: u64,
        leaf_commitment: vector<u8>,
        deposit_batch_id: u64,
        queue_position: u64,
        compliance_attestation_id: u64,
    }

    #[event]
    struct BenchDepositQueuedCandidate has drop, store {
        deposit_index: u64,
        leaf_commitment: vector<u8>,
        deposit_batch_id: u64,
        // queue_position DROPPED (= deposit_index in MVP 1:1)
        compliance_attestation_id: u64,
    }

    public entry fun bench_emit_deposit_queued_baseline() {
        event::emit(BenchDepositQueuedBaseline {
            deposit_index: 0,
            leaf_commitment: bytes32(),
            deposit_batch_id: 0,
            queue_position: 0,
            compliance_attestation_id: 0,
        });
    }

    public entry fun bench_emit_deposit_queued_candidate() {
        event::emit(BenchDepositQueuedCandidate {
            deposit_index: 0,
            leaf_commitment: bytes32(),
            deposit_batch_id: 0,
            compliance_attestation_id: 0,
        });
    }
}

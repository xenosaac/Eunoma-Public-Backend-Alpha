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
}

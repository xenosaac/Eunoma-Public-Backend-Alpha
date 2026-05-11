/// Generic implementation of Groth16 (proof verification) as defined in https://eprint.iacr.org/2016/260.pdf, Section 3.2.
/// Actual proof verifiers can be constructed using the pairings supported in the generic algebra module.
/// See the test cases in this module for an example of constructing with BLS12-381 curves.
///
/// **WARNING:** This code has NOT been audited. If using it in a production system, proceed at your own risk.
///
/// VENDORED from `groth16_example::groth16` at
/// `/tmp/aptos-core/aptos-move/move-examples/groth16_example/sources/groth16.move`
/// (commit `40673b79a7cf91a387e91d39f202615eca24bad5`, captured 2026-05-07 by Gate 4a).
/// Only the module path/namespace is changed (`eunoma::groth16_bn254`); the
/// verification logic is byte-identical to upstream. Tests are stripped — see
/// `move/tests/groth16_verify_test.move` for the bridge-side tests.
module eunoma::groth16_bn254 {
    use aptos_std::crypto_algebra::{Element, from_u64, multi_scalar_mul, eq, multi_pairing, upcast, pairing, add, zero};

    /// Proof verification as specified in the original paper,
    /// with the following input (in the original paper notations).
    /// - Verification key: $\left([\alpha]_1, [\beta]_2, [\gamma]_2, [\delta]_2, \left\\{ \left[ \frac{\beta \cdot u_i(x) + \alpha \cdot v_i(x) + w_i(x)}{\gamma} \right]_1 \right\\}\_{i=0}^l \right)$.
    /// - Public inputs: $\\{a_i\\}_{i=1}^l$.
    /// - Proof $\left( \left[ A \right]_1, \left[ B \right]_2, \left[ C \right]_1 \right)$.
    public fun verify_proof<G1,G2,Gt,S>(
        vk_alpha_g1: &Element<G1>,
        vk_beta_g2: &Element<G2>,
        vk_gamma_g2: &Element<G2>,
        vk_delta_g2: &Element<G2>,
        vk_uvw_gamma_g1: &vector<Element<G1>>,
        public_inputs: &vector<Element<S>>,
        proof_a: &Element<G1>,
        proof_b: &Element<G2>,
        proof_c: &Element<G1>,
    ): bool {
        let left = pairing<G1,G2,Gt>(proof_a, proof_b);
        let scalars = vector[from_u64<S>(1)];
        std::vector::append(&mut scalars, *public_inputs);
        let right = zero<Gt>();
        let right = add(&right, &pairing<G1,G2,Gt>(vk_alpha_g1, vk_beta_g2));
        let right = add(&right, &pairing(&multi_scalar_mul(vk_uvw_gamma_g1, &scalars), vk_gamma_g2));
        let right = add(&right, &pairing(proof_c, vk_delta_g2));
        eq(&left, &right)
    }

    /// Modified proof verification which is optimized for low verification latency
    /// but requires a pairing and 2 `G2` negations to be pre-computed.
    /// Below are the full input (in the original paper notations).
    /// - Prepared verification key: $\left([\alpha]_1 \cdot [\beta]_2, -[\gamma]_2, -[\delta]_2, \left\\{ \left[ \frac{\beta \cdot u_i(x) + \alpha \cdot v_i(x) + w_i(x)}{\gamma} \right]_1 \right\\}\_{i=0}^l \right)$.
    /// - Public inputs: $\\{a_i\\}_{i=1}^l$.
    /// - Proof: $\left( \left[ A \right]_1, \left[ B \right]_2, \left[ C \right]_1 \right)$.
    public fun verify_proof_prepared<G1,G2,Gt,S>(
        pvk_alpha_g1_beta_g2: &Element<Gt>,
        pvk_gamma_g2_neg: &Element<G2>,
        pvk_delta_g2_neg: &Element<G2>,
        pvk_uvw_gamma_g1: &vector<Element<G1>>,
        public_inputs: &vector<Element<S>>,
        proof_a: &Element<G1>,
        proof_b: &Element<G2>,
        proof_c: &Element<G1>,
    ): bool {
        let scalars = vector[from_u64<S>(1)];
        std::vector::append(&mut scalars, *public_inputs);
        let g1_elements = vector[*proof_a, multi_scalar_mul(pvk_uvw_gamma_g1, &scalars), *proof_c];
        let g2_elements = vector[*proof_b, *pvk_gamma_g2_neg, *pvk_delta_g2_neg];
        eq(pvk_alpha_g1_beta_g2, &multi_pairing<G1,G2,Gt>(&g1_elements, &g2_elements))
    }

    /// A variant of `verify_proof_prepared()` that requires `pvk_alpha_g1_beta_g2` to be an element of `Fq12` instead of its subgroup `Gt`.
    /// With this variant, the caller may save a `Gt` deserialization (which involves an expensive `Gt` membership test).
    /// Below are the full input (in the original paper notations).
    /// - Prepared verification key: $\left([\alpha]_1 \cdot [\beta]_2, -[\gamma]_2, -[\delta]_2, \left\\{ \left[ \frac{\beta \cdot u_i(x) + \alpha \cdot v_i(x) + w_i(x)}{\gamma} \right]_1 \right\\}\_{i=0}^l \right)$.
    /// - Public inputs: $\\{a_i\\}_{i=1}^l$.
    /// - Proof: $\left( \left[ A \right]_1, \left[ B \right]_2, \left[ C \right]_1 \right)$.
    public fun verify_proof_prepared_fq12<G1, G2, Gt, Fq12, S>(
        pvk_alpha_g1_beta_g2: &Element<Fq12>,
        pvk_gamma_g2_neg: &Element<G2>,
        pvk_delta_g2_neg: &Element<G2>,
        pvk_uvw_gamma_g1: &vector<Element<G1>>,
        public_inputs: &vector<Element<S>>,
        proof_a: &Element<G1>,
        proof_b: &Element<G2>,
        proof_c: &Element<G1>,
    ): bool {
        let scalars = vector[from_u64<S>(1)];
        std::vector::append(&mut scalars, *public_inputs);
        let g1_elements = vector[*proof_a, multi_scalar_mul(pvk_uvw_gamma_g1, &scalars), *proof_c];
        let g2_elements = vector[*proof_b, *pvk_gamma_g2_neg, *pvk_delta_g2_neg];
        eq(pvk_alpha_g1_beta_g2, &upcast(&multi_pairing<G1,G2,Gt>(&g1_elements, &g2_elements)))
    }
}

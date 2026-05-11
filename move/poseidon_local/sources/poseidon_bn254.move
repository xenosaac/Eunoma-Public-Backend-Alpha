// OPTIMIZED Poseidon hash (BN254) — round-5 candidate A2
// (= C14 source-layer wins applied on top of circomlibjs's optimized C/M/P/S
// schedule, with partial rounds executed as TRUE-SPARSE matrices —
// 2t-1 multiplications per partial round, NOT t² as iter-1 C5/C6 mistakenly
// did.)
//
// Schedule (matches circomlibjs/src/poseidon_opt.js exactly, byte-equivalent
// outputs to the C14 naive baseline; covered by 36 cross-checked vectors):
//
//   state = [0, ..inputs]
//   state[i] += C[i]                              for i in 0..t          (init add)
//   for r in 0..(Rf/2 - 1):                        ─ first half (3 rounds for Rf=8)
//       state = pow5(state)                                                (full S-box)
//       state[i] += C[(r+1)*t + i]
//       state = M · state                                                  (dense MDS)
//   state = pow5(state)                            ─ pre-sparse bridge
//   state[i] += C[(Rf/2)*t + i]
//   state = P · state                                                      (one-shot dense P)
//   for r in 0..Rp:                                ─ partial rounds (true-sparse mix)
//       state[0] = pow5(state[0])                                          (partial S-box)
//       state[0] += C[(Rf/2 + 1)*t + r]
//       sparse-mix with S_packed[r] (2t-1 entries):
//           new[0] = sum_{j=0..t-1} row0[j] * state[j]                     (t muls)
//           new[i] = state[i] + col_i_0 * state[0]      for i in 1..t-1    (t-1 muls)
//   for r in 0..(Rf/2 - 1):                       ─ second half (3 rounds)
//       state = pow5(state)
//       state[i] += C[(Rf/2 + 1)*t + Rp + r*t + i]
//       state = M · state
//   state = pow5(state)                           ─ final pow5+M, no C add
//   state = M · state                             ─ but only s0 needed (last-round skip)
//   return s0
//
// Sparse multiplication count per partial round (the load-bearing invariant):
//   t = 3:  5 muls  (vs naive full-MDS 9)
//   t = 4:  7 muls  (vs naive full-MDS 16)
// Across all partial rounds (Rp partial rounds total):
//   t = 3, Rp = 57:  saves (9 - 5) × 57 = 228 muls
//   t = 4, Rp = 56:  saves (16 - 7) × 56 = 504 muls
//
// C14 source-layer wins inherited (iter-3/4 stack):
//   1. Inline pow5 (no helper-call frames; in-place x→x²→x⁴→x⁵).
//   2. Inline fr_from_le for input deserialize.
//   3. On-demand const deserialize in the round body (no per-call
//      vector<Element<Fr>> alloc).
//   4. No redundant option::is_some asserts on hardcoded-constant paths.
//   5. First-product MDS accumulator (acc = M[i][0]·s[0], not 0+...).
//   6. Width-specialized unrolled mat_mul for full + bridge rounds.
//   7. Fused round body, state in scalar locals.
//   8. Last-round MDS-row skip: final pow5+M only computes n0 since hash
//      returns s0. Skips MDS rows 1..t-1.
//
// Public API (output bytes are bit-identical to C14):
//   hash_2(a, b)       — Poseidon([0, a, b]),    t=3, Rf=8, Rp=57
//   hash_3(a, b, c)    — Poseidon([0, a, b, c]), t=4, Rf=8, Rp=56
module eunoma_pool::poseidon_bn254 {
    use std::option;
    use std::vector;
    use aptos_std::crypto_algebra::{Self as algebra, Element};
    use std::bn254_algebra::{Fr, FormatFrLsb};
    use eunoma_pool::poseidon_constants;

    // -------- error codes --------
    const E_DESERIALIZE: u64 = 1;
    const E_BAD_CONSTANTS: u64 = 3;

    // -------- pinned Poseidon parameters --------
    const RF: u64 = 8;
    const RP_T3: u64 = 57;
    const RP_T4: u64 = 56;

    // -------- public entry points --------

    public fun hash_2(a: vector<u8>, b: vector<u8>): vector<u8> {
        let s0 = fr_zero();
        let s1 = fr_from_le(&a);
        let s2 = fr_from_le(&b);

        let c_bytes = poseidon_constants::c_opt_t3();
        let m_bytes = poseidon_constants::m_t3();
        let p_bytes = poseidon_constants::p_t3();
        let s_bytes = poseidon_constants::s_packed_t3();
        // Optimized C length = RF*t + RP = 8*3 + 57 = 81.
        assert!(vector::length(&c_bytes) == RF * 3 + RP_T3, E_BAD_CONSTANTS);
        assert!(vector::length(&m_bytes) == 9, E_BAD_CONSTANTS);
        assert!(vector::length(&p_bytes) == 9, E_BAD_CONSTANTS);
        // S_packed length = RP * (2t-1) = 57 * 5 = 285.
        assert!(vector::length(&s_bytes) == RP_T3 * 5, E_BAD_CONSTANTS);

        let out = poseidon_opt_t3(s0, s1, s2, &c_bytes, &m_bytes, &p_bytes, &s_bytes);
        fr_to_le(&out)
    }

    public fun hash_3(a: vector<u8>, b: vector<u8>, c: vector<u8>): vector<u8> {
        let s0 = fr_zero();
        let s1 = fr_from_le(&a);
        let s2 = fr_from_le(&b);
        let s3 = fr_from_le(&c);

        let c_bytes = poseidon_constants::c_opt_t4();
        let m_bytes = poseidon_constants::m_t4();
        let p_bytes = poseidon_constants::p_t4();
        let s_bytes = poseidon_constants::s_packed_t4();
        // Optimized C length = RF*t + RP = 8*4 + 56 = 88.
        assert!(vector::length(&c_bytes) == RF * 4 + RP_T4, E_BAD_CONSTANTS);
        assert!(vector::length(&m_bytes) == 16, E_BAD_CONSTANTS);
        assert!(vector::length(&p_bytes) == 16, E_BAD_CONSTANTS);
        // S_packed length = RP * (2t-1) = 56 * 7 = 392.
        assert!(vector::length(&s_bytes) == RP_T4 * 7, E_BAD_CONSTANTS);

        let out = poseidon_opt_t4(s0, s1, s2, s3, &c_bytes, &m_bytes, &p_bytes, &s_bytes);
        fr_to_le(&out)
    }

    // -------- helpers --------

    fun fr_zero(): Element<Fr> {
        algebra::zero<Fr>()
    }

    // Inline-friendly form (called only twice per call from hash_2 / three from hash_3,
    // not in the hot loop).
    fun fr_from_le(bytes: &vector<u8>): Element<Fr> {
        assert!(vector::length(bytes) == 32, E_DESERIALIZE);
        let opt = algebra::deserialize<Fr, FormatFrLsb>(bytes);
        assert!(option::is_some(&opt), E_DESERIALIZE);
        option::extract(&mut opt)
    }

    fun fr_to_le(x: &Element<Fr>): vector<u8> {
        algebra::serialize<Fr, FormatFrLsb>(x)
    }

    // Hoist deserialize from byte-vector at index i (no is_some assert; constants
    // are hardcoded and statically valid). Inlined into round body; this helper
    // is provided for readability but not used in the hot path.
    inline fun deser_at(c: &vector<vector<u8>>, i: u64): Element<Fr> {
        let cb = vector::borrow(c, i);
        let opt = algebra::deserialize<Fr, FormatFrLsb>(cb);
        option::extract(&mut opt)
    }

    // -------- t = 3 optimized hash --------

    /// Width-3 optimized Poseidon. Implements circomlibjs's poseidon_opt
    /// schedule with TRUE-SPARSE partial rounds (5 muls per round, not 9).
    fun poseidon_opt_t3(
        s0: Element<Fr>, s1: Element<Fr>, s2: Element<Fr>,
        c: &vector<vector<u8>>,
        m: &vector<vector<u8>>,
        p: &vector<vector<u8>>,
        s_packed: &vector<vector<u8>>,
    ): Element<Fr> {
        // ---- Hoist M (used in 3+3 = 6 full rounds + final M-mix) ----
        let mb0 = vector::borrow(m, 0);
        let mopt0 = algebra::deserialize<Fr, FormatFrLsb>(mb0);
        let m00 = option::extract(&mut mopt0);
        let mb1 = vector::borrow(m, 1);
        let mopt1 = algebra::deserialize<Fr, FormatFrLsb>(mb1);
        let m01 = option::extract(&mut mopt1);
        let mb2 = vector::borrow(m, 2);
        let mopt2 = algebra::deserialize<Fr, FormatFrLsb>(mb2);
        let m02 = option::extract(&mut mopt2);
        let mb3 = vector::borrow(m, 3);
        let mopt3 = algebra::deserialize<Fr, FormatFrLsb>(mb3);
        let m10 = option::extract(&mut mopt3);
        let mb4 = vector::borrow(m, 4);
        let mopt4 = algebra::deserialize<Fr, FormatFrLsb>(mb4);
        let m11 = option::extract(&mut mopt4);
        let mb5 = vector::borrow(m, 5);
        let mopt5 = algebra::deserialize<Fr, FormatFrLsb>(mb5);
        let m12 = option::extract(&mut mopt5);
        let mb6 = vector::borrow(m, 6);
        let mopt6 = algebra::deserialize<Fr, FormatFrLsb>(mb6);
        let m20 = option::extract(&mut mopt6);
        let mb7 = vector::borrow(m, 7);
        let mopt7 = algebra::deserialize<Fr, FormatFrLsb>(mb7);
        let m21 = option::extract(&mut mopt7);
        let mb8 = vector::borrow(m, 8);
        let mopt8 = algebra::deserialize<Fr, FormatFrLsb>(mb8);
        let m22 = option::extract(&mut mopt8);

        // ---- Initial constant add: state[i] += C[i] ----
        let cb0 = vector::borrow(c, 0);
        let kopt0 = algebra::deserialize<Fr, FormatFrLsb>(cb0);
        let k0 = option::extract(&mut kopt0);
        let cb1 = vector::borrow(c, 1);
        let kopt1 = algebra::deserialize<Fr, FormatFrLsb>(cb1);
        let k1 = option::extract(&mut kopt1);
        let cb2 = vector::borrow(c, 2);
        let kopt2 = algebra::deserialize<Fr, FormatFrLsb>(cb2);
        let k2 = option::extract(&mut kopt2);
        s0 = algebra::add<Fr>(&s0, &k0);
        s1 = algebra::add<Fr>(&s1, &k1);
        s2 = algebra::add<Fr>(&s2, &k2);

        // ---- First half: Rf/2 - 1 = 3 full rounds ----
        let half_minus_1 = RF / 2 - 1;
        let r = 0;
        while (r < half_minus_1) {
            let cb = (r + 1) * 3;
            // pow5 (full S-box on all 3 lanes), then add C, then M·state.
            let s0_2 = algebra::sqr<Fr>(&s0);
            let s0_4 = algebra::sqr<Fr>(&s0_2);
            let p0 = algebra::mul<Fr>(&s0_4, &s0);
            let s1_2 = algebra::sqr<Fr>(&s1);
            let s1_4 = algebra::sqr<Fr>(&s1_2);
            let p1 = algebra::mul<Fr>(&s1_4, &s1);
            let s2_2 = algebra::sqr<Fr>(&s2);
            let s2_4 = algebra::sqr<Fr>(&s2_2);
            let p2 = algebra::mul<Fr>(&s2_4, &s2);
            let kb0 = vector::borrow(c, cb);
            let kop0 = algebra::deserialize<Fr, FormatFrLsb>(kb0);
            let kk0 = option::extract(&mut kop0);
            let kb1 = vector::borrow(c, cb + 1);
            let kop1 = algebra::deserialize<Fr, FormatFrLsb>(kb1);
            let kk1 = option::extract(&mut kop1);
            let kb2 = vector::borrow(c, cb + 2);
            let kop2 = algebra::deserialize<Fr, FormatFrLsb>(kb2);
            let kk2 = option::extract(&mut kop2);
            let a0 = algebra::add<Fr>(&p0, &kk0);
            let a1 = algebra::add<Fr>(&p1, &kk1);
            let a2 = algebra::add<Fr>(&p2, &kk2);
            // Dense 3x3 M·state (first-product accumulator).
            let q00 = algebra::mul<Fr>(&m00, &a0);
            let q01 = algebra::mul<Fr>(&m01, &a1);
            let r01 = algebra::add<Fr>(&q00, &q01);
            let q02 = algebra::mul<Fr>(&m02, &a2);
            s0 = algebra::add<Fr>(&r01, &q02);
            let q10 = algebra::mul<Fr>(&m10, &a0);
            let q11 = algebra::mul<Fr>(&m11, &a1);
            let r11 = algebra::add<Fr>(&q10, &q11);
            let q12 = algebra::mul<Fr>(&m12, &a2);
            s1 = algebra::add<Fr>(&r11, &q12);
            let q20 = algebra::mul<Fr>(&m20, &a0);
            let q21 = algebra::mul<Fr>(&m21, &a1);
            let r21 = algebra::add<Fr>(&q20, &q21);
            let q22 = algebra::mul<Fr>(&m22, &a2);
            s2 = algebra::add<Fr>(&r21, &q22);
            r = r + 1;
        };

        // ---- Pre-sparse bridge: pow5(state) + C[(Rf/2)*t + i] + P·state ----
        // (one round, not partial; full S-box, then add C, then mix by P.)
        let half = RF / 2;
        let bridge_cb = half * 3;
        let bs0_2 = algebra::sqr<Fr>(&s0);
        let bs0_4 = algebra::sqr<Fr>(&bs0_2);
        let bp0 = algebra::mul<Fr>(&bs0_4, &s0);
        let bs1_2 = algebra::sqr<Fr>(&s1);
        let bs1_4 = algebra::sqr<Fr>(&bs1_2);
        let bp1 = algebra::mul<Fr>(&bs1_4, &s1);
        let bs2_2 = algebra::sqr<Fr>(&s2);
        let bs2_4 = algebra::sqr<Fr>(&bs2_2);
        let bp2 = algebra::mul<Fr>(&bs2_4, &s2);
        let bkb0 = vector::borrow(c, bridge_cb);
        let bkop0 = algebra::deserialize<Fr, FormatFrLsb>(bkb0);
        let bk0 = option::extract(&mut bkop0);
        let bkb1 = vector::borrow(c, bridge_cb + 1);
        let bkop1 = algebra::deserialize<Fr, FormatFrLsb>(bkb1);
        let bk1 = option::extract(&mut bkop1);
        let bkb2 = vector::borrow(c, bridge_cb + 2);
        let bkop2 = algebra::deserialize<Fr, FormatFrLsb>(bkb2);
        let bk2 = option::extract(&mut bkop2);
        let ba0 = algebra::add<Fr>(&bp0, &bk0);
        let ba1 = algebra::add<Fr>(&bp1, &bk1);
        let ba2 = algebra::add<Fr>(&bp2, &bk2);
        // Hoist P and apply 3x3 dense P·state.
        let pb0 = vector::borrow(p, 0);
        let pop0 = algebra::deserialize<Fr, FormatFrLsb>(pb0);
        let p00 = option::extract(&mut pop0);
        let pb1 = vector::borrow(p, 1);
        let pop1 = algebra::deserialize<Fr, FormatFrLsb>(pb1);
        let p01 = option::extract(&mut pop1);
        let pb2 = vector::borrow(p, 2);
        let pop2 = algebra::deserialize<Fr, FormatFrLsb>(pb2);
        let p02 = option::extract(&mut pop2);
        let pb3 = vector::borrow(p, 3);
        let pop3 = algebra::deserialize<Fr, FormatFrLsb>(pb3);
        let p10 = option::extract(&mut pop3);
        let pb4 = vector::borrow(p, 4);
        let pop4 = algebra::deserialize<Fr, FormatFrLsb>(pb4);
        let p11 = option::extract(&mut pop4);
        let pb5 = vector::borrow(p, 5);
        let pop5 = algebra::deserialize<Fr, FormatFrLsb>(pb5);
        let p12 = option::extract(&mut pop5);
        let pb6 = vector::borrow(p, 6);
        let pop6 = algebra::deserialize<Fr, FormatFrLsb>(pb6);
        let p20 = option::extract(&mut pop6);
        let pb7 = vector::borrow(p, 7);
        let pop7 = algebra::deserialize<Fr, FormatFrLsb>(pb7);
        let p21 = option::extract(&mut pop7);
        let pb8 = vector::borrow(p, 8);
        let pop8 = algebra::deserialize<Fr, FormatFrLsb>(pb8);
        let p22 = option::extract(&mut pop8);
        // P·state.
        let v00 = algebra::mul<Fr>(&p00, &ba0);
        let v01 = algebra::mul<Fr>(&p01, &ba1);
        let v01s = algebra::add<Fr>(&v00, &v01);
        let v02 = algebra::mul<Fr>(&p02, &ba2);
        s0 = algebra::add<Fr>(&v01s, &v02);
        let w00 = algebra::mul<Fr>(&p10, &ba0);
        let w01 = algebra::mul<Fr>(&p11, &ba1);
        let w01s = algebra::add<Fr>(&w00, &w01);
        let w02 = algebra::mul<Fr>(&p12, &ba2);
        s1 = algebra::add<Fr>(&w01s, &w02);
        let x00 = algebra::mul<Fr>(&p20, &ba0);
        let x01 = algebra::mul<Fr>(&p21, &ba1);
        let x01s = algebra::add<Fr>(&x00, &x01);
        let x02 = algebra::mul<Fr>(&p22, &ba2);
        s2 = algebra::add<Fr>(&x01s, &x02);

        // ---- Rp partial rounds: TRUE SPARSE (5 muls per round for t=3) ----
        // C-base for partial rounds: (Rf/2 + 1) * t = 4 * 3 = 12.
        let part_c_base = (half + 1) * 3;
        // S_packed[r] occupies indices r*5 .. r*5 + 5 (5 entries per round, t=3).
        let pr = 0;
        while (pr < RP_T3) {
            // Partial S-box: pow5 only on s0.
            let q0_2 = algebra::sqr<Fr>(&s0);
            let q0_4 = algebra::sqr<Fr>(&q0_2);
            let q0 = algebra::mul<Fr>(&q0_4, &s0);
            // Add partial-round constant C[(Rf/2+1)*t + r].
            let pcb = vector::borrow(c, part_c_base + pr);
            let pcopt = algebra::deserialize<Fr, FormatFrLsb>(pcb);
            let pc = option::extract(&mut pcopt);
            let qa0 = algebra::add<Fr>(&q0, &pc);
            // Sparse mix S_packed[pr]: 5 entries
            //   row0 = [s_packed[pr*5+0], s_packed[pr*5+1], s_packed[pr*5+2]]
            //   col_below = [s_packed[pr*5+3] (row 1, col 0),
            //                s_packed[pr*5+4] (row 2, col 0)]
            let sb_base = pr * 5;
            let sb0 = vector::borrow(s_packed, sb_base);
            let sopt0 = algebra::deserialize<Fr, FormatFrLsb>(sb0);
            let sr0 = option::extract(&mut sopt0);
            let sb1 = vector::borrow(s_packed, sb_base + 1);
            let sopt1 = algebra::deserialize<Fr, FormatFrLsb>(sb1);
            let sr1 = option::extract(&mut sopt1);
            let sb2 = vector::borrow(s_packed, sb_base + 2);
            let sopt2 = algebra::deserialize<Fr, FormatFrLsb>(sb2);
            let sr2 = option::extract(&mut sopt2);
            let sb3 = vector::borrow(s_packed, sb_base + 3);
            let sopt3 = algebra::deserialize<Fr, FormatFrLsb>(sb3);
            let sc1 = option::extract(&mut sopt3);
            let sb4 = vector::borrow(s_packed, sb_base + 4);
            let sopt4 = algebra::deserialize<Fr, FormatFrLsb>(sb4);
            let sc2 = option::extract(&mut sopt4);
            // new[0] = row0[0]*qa0 + row0[1]*s1 + row0[2]*s2   (3 muls = t muls)
            let n00 = algebra::mul<Fr>(&sr0, &qa0);
            let n01 = algebra::mul<Fr>(&sr1, &s1);
            let n012 = algebra::add<Fr>(&n00, &n01);
            let n02 = algebra::mul<Fr>(&sr2, &s2);
            let new_s0 = algebra::add<Fr>(&n012, &n02);
            // new[1] = s1 + col1_0 * qa0   (1 mul = t-1 = 2 → 1 here for i=1)
            let m1 = algebra::mul<Fr>(&sc1, &qa0);
            let new_s1 = algebra::add<Fr>(&s1, &m1);
            // new[2] = s2 + col2_0 * qa0   (1 mul, i=2)
            let m2 = algebra::mul<Fr>(&sc2, &qa0);
            let new_s2 = algebra::add<Fr>(&s2, &m2);
            // Total muls: 3 (row0) + 1 + 1 = 5 = 2t-1 for t=3.
            s0 = new_s0;
            s1 = new_s1;
            s2 = new_s2;
            pr = pr + 1;
        };

        // ---- Second half: Rf/2 - 1 = 3 full rounds ----
        // C-base for second-half full rounds: (Rf/2+1)*t + RP = 12 + 57 = 69.
        let post_c_base = (half + 1) * 3 + RP_T3;
        let r2 = 0;
        while (r2 < half_minus_1) {
            let cb2 = post_c_base + r2 * 3;
            let s0_2b = algebra::sqr<Fr>(&s0);
            let s0_4b = algebra::sqr<Fr>(&s0_2b);
            let pp0 = algebra::mul<Fr>(&s0_4b, &s0);
            let s1_2b = algebra::sqr<Fr>(&s1);
            let s1_4b = algebra::sqr<Fr>(&s1_2b);
            let pp1 = algebra::mul<Fr>(&s1_4b, &s1);
            let s2_2b = algebra::sqr<Fr>(&s2);
            let s2_4b = algebra::sqr<Fr>(&s2_2b);
            let pp2 = algebra::mul<Fr>(&s2_4b, &s2);
            let kkb0 = vector::borrow(c, cb2);
            let kkop0 = algebra::deserialize<Fr, FormatFrLsb>(kkb0);
            let nk0 = option::extract(&mut kkop0);
            let kkb1 = vector::borrow(c, cb2 + 1);
            let kkop1 = algebra::deserialize<Fr, FormatFrLsb>(kkb1);
            let nk1 = option::extract(&mut kkop1);
            let kkb2 = vector::borrow(c, cb2 + 2);
            let kkop2 = algebra::deserialize<Fr, FormatFrLsb>(kkb2);
            let nk2 = option::extract(&mut kkop2);
            let na0 = algebra::add<Fr>(&pp0, &nk0);
            let na1 = algebra::add<Fr>(&pp1, &nk1);
            let na2 = algebra::add<Fr>(&pp2, &nk2);
            let z00 = algebra::mul<Fr>(&m00, &na0);
            let z01 = algebra::mul<Fr>(&m01, &na1);
            let zr01 = algebra::add<Fr>(&z00, &z01);
            let z02 = algebra::mul<Fr>(&m02, &na2);
            s0 = algebra::add<Fr>(&zr01, &z02);
            let y00 = algebra::mul<Fr>(&m10, &na0);
            let y01 = algebra::mul<Fr>(&m11, &na1);
            let yr01 = algebra::add<Fr>(&y00, &y01);
            let y02 = algebra::mul<Fr>(&m12, &na2);
            s1 = algebra::add<Fr>(&yr01, &y02);
            let u00 = algebra::mul<Fr>(&m20, &na0);
            let u01 = algebra::mul<Fr>(&m21, &na1);
            let ur01 = algebra::add<Fr>(&u00, &u01);
            let u02 = algebra::mul<Fr>(&m22, &na2);
            s2 = algebra::add<Fr>(&ur01, &u02);
            r2 = r2 + 1;
        };

        // ---- Final pow5 + M-mix, no C add. Last-round skip: only n0. ----
        let f0_2 = algebra::sqr<Fr>(&s0);
        let f0_4 = algebra::sqr<Fr>(&f0_2);
        let f0 = algebra::mul<Fr>(&f0_4, &s0);
        let f1_2 = algebra::sqr<Fr>(&s1);
        let f1_4 = algebra::sqr<Fr>(&f1_2);
        let f1 = algebra::mul<Fr>(&f1_4, &s1);
        let f2_2 = algebra::sqr<Fr>(&s2);
        let f2_4 = algebra::sqr<Fr>(&f2_2);
        let f2 = algebra::mul<Fr>(&f2_4, &s2);
        // Last-round: only compute s0 = M[0][·] · state. Skip rows 1 and 2.
        let l00 = algebra::mul<Fr>(&m00, &f0);
        let l01 = algebra::mul<Fr>(&m01, &f1);
        let lr01 = algebra::add<Fr>(&l00, &l01);
        let l02 = algebra::mul<Fr>(&m02, &f2);
        algebra::add<Fr>(&lr01, &l02)
    }

    // -------- t = 4 optimized hash --------

    /// Pre-sparse bridge step: out = P · state. Helper to keep
    /// poseidon_opt_t4's local count under Move's 255 cap.
    fun bridge_p_apply_t4(
        p: &vector<vector<u8>>,
        a0: &Element<Fr>, a1: &Element<Fr>, a2: &Element<Fr>, a3: &Element<Fr>,
    ): (Element<Fr>, Element<Fr>, Element<Fr>, Element<Fr>) {
        // Deserialize P entries on demand. P is a 4x4 row-major matrix.
        let pb0 = vector::borrow(p, 0);
        let pop0 = algebra::deserialize<Fr, FormatFrLsb>(pb0);
        let p00 = option::extract(&mut pop0);
        let pb1 = vector::borrow(p, 1);
        let pop1 = algebra::deserialize<Fr, FormatFrLsb>(pb1);
        let p01 = option::extract(&mut pop1);
        let pb2 = vector::borrow(p, 2);
        let pop2 = algebra::deserialize<Fr, FormatFrLsb>(pb2);
        let p02 = option::extract(&mut pop2);
        let pb3 = vector::borrow(p, 3);
        let pop3 = algebra::deserialize<Fr, FormatFrLsb>(pb3);
        let p03 = option::extract(&mut pop3);
        let pb4 = vector::borrow(p, 4);
        let pop4 = algebra::deserialize<Fr, FormatFrLsb>(pb4);
        let p10 = option::extract(&mut pop4);
        let pb5 = vector::borrow(p, 5);
        let pop5 = algebra::deserialize<Fr, FormatFrLsb>(pb5);
        let p11 = option::extract(&mut pop5);
        let pb6 = vector::borrow(p, 6);
        let pop6 = algebra::deserialize<Fr, FormatFrLsb>(pb6);
        let p12 = option::extract(&mut pop6);
        let pb7 = vector::borrow(p, 7);
        let pop7 = algebra::deserialize<Fr, FormatFrLsb>(pb7);
        let p13 = option::extract(&mut pop7);
        let pb8 = vector::borrow(p, 8);
        let pop8 = algebra::deserialize<Fr, FormatFrLsb>(pb8);
        let p20 = option::extract(&mut pop8);
        let pb9 = vector::borrow(p, 9);
        let pop9 = algebra::deserialize<Fr, FormatFrLsb>(pb9);
        let p21 = option::extract(&mut pop9);
        let pb10 = vector::borrow(p, 10);
        let pop10 = algebra::deserialize<Fr, FormatFrLsb>(pb10);
        let p22 = option::extract(&mut pop10);
        let pb11 = vector::borrow(p, 11);
        let pop11 = algebra::deserialize<Fr, FormatFrLsb>(pb11);
        let p23 = option::extract(&mut pop11);
        let pb12 = vector::borrow(p, 12);
        let pop12 = algebra::deserialize<Fr, FormatFrLsb>(pb12);
        let p30 = option::extract(&mut pop12);
        let pb13 = vector::borrow(p, 13);
        let pop13 = algebra::deserialize<Fr, FormatFrLsb>(pb13);
        let p31 = option::extract(&mut pop13);
        let pb14 = vector::borrow(p, 14);
        let pop14 = algebra::deserialize<Fr, FormatFrLsb>(pb14);
        let p32 = option::extract(&mut pop14);
        let pb15 = vector::borrow(p, 15);
        let pop15 = algebra::deserialize<Fr, FormatFrLsb>(pb15);
        let p33 = option::extract(&mut pop15);
        // P·state, first-product accumulator.
        let v00 = algebra::mul<Fr>(&p00, a0);
        let v01 = algebra::mul<Fr>(&p01, a1);
        let v01s = algebra::add<Fr>(&v00, &v01);
        let v02 = algebra::mul<Fr>(&p02, a2);
        let v012 = algebra::add<Fr>(&v01s, &v02);
        let v03 = algebra::mul<Fr>(&p03, a3);
        let n0 = algebra::add<Fr>(&v012, &v03);
        let w00 = algebra::mul<Fr>(&p10, a0);
        let w01 = algebra::mul<Fr>(&p11, a1);
        let w01s = algebra::add<Fr>(&w00, &w01);
        let w02 = algebra::mul<Fr>(&p12, a2);
        let w012 = algebra::add<Fr>(&w01s, &w02);
        let w03 = algebra::mul<Fr>(&p13, a3);
        let n1 = algebra::add<Fr>(&w012, &w03);
        let x00 = algebra::mul<Fr>(&p20, a0);
        let x01 = algebra::mul<Fr>(&p21, a1);
        let x01s = algebra::add<Fr>(&x00, &x01);
        let x02 = algebra::mul<Fr>(&p22, a2);
        let x012 = algebra::add<Fr>(&x01s, &x02);
        let x03 = algebra::mul<Fr>(&p23, a3);
        let n2 = algebra::add<Fr>(&x012, &x03);
        let y00 = algebra::mul<Fr>(&p30, a0);
        let y01 = algebra::mul<Fr>(&p31, a1);
        let y01s = algebra::add<Fr>(&y00, &y01);
        let y02 = algebra::mul<Fr>(&p32, a2);
        let y012 = algebra::add<Fr>(&y01s, &y02);
        let y03 = algebra::mul<Fr>(&p33, a3);
        let n3 = algebra::add<Fr>(&y012, &y03);
        (n0, n1, n2, n3)
    }

    /// Width-4 optimized Poseidon (true-sparse partial rounds, 7 muls per round).
    fun poseidon_opt_t4(
        s0: Element<Fr>, s1: Element<Fr>, s2: Element<Fr>, s3: Element<Fr>,
        c: &vector<vector<u8>>,
        m: &vector<vector<u8>>,
        p: &vector<vector<u8>>,
        s_packed: &vector<vector<u8>>,
    ): Element<Fr> {
        // ---- Hoist M (4x4) ----
        let mb0 = vector::borrow(m, 0);
        let mopt0 = algebra::deserialize<Fr, FormatFrLsb>(mb0);
        let m00 = option::extract(&mut mopt0);
        let mb1 = vector::borrow(m, 1);
        let mopt1 = algebra::deserialize<Fr, FormatFrLsb>(mb1);
        let m01 = option::extract(&mut mopt1);
        let mb2 = vector::borrow(m, 2);
        let mopt2 = algebra::deserialize<Fr, FormatFrLsb>(mb2);
        let m02 = option::extract(&mut mopt2);
        let mb3 = vector::borrow(m, 3);
        let mopt3 = algebra::deserialize<Fr, FormatFrLsb>(mb3);
        let m03 = option::extract(&mut mopt3);
        let mb4 = vector::borrow(m, 4);
        let mopt4 = algebra::deserialize<Fr, FormatFrLsb>(mb4);
        let m10 = option::extract(&mut mopt4);
        let mb5 = vector::borrow(m, 5);
        let mopt5 = algebra::deserialize<Fr, FormatFrLsb>(mb5);
        let m11 = option::extract(&mut mopt5);
        let mb6 = vector::borrow(m, 6);
        let mopt6 = algebra::deserialize<Fr, FormatFrLsb>(mb6);
        let m12 = option::extract(&mut mopt6);
        let mb7 = vector::borrow(m, 7);
        let mopt7 = algebra::deserialize<Fr, FormatFrLsb>(mb7);
        let m13 = option::extract(&mut mopt7);
        let mb8 = vector::borrow(m, 8);
        let mopt8 = algebra::deserialize<Fr, FormatFrLsb>(mb8);
        let m20 = option::extract(&mut mopt8);
        let mb9 = vector::borrow(m, 9);
        let mopt9 = algebra::deserialize<Fr, FormatFrLsb>(mb9);
        let m21 = option::extract(&mut mopt9);
        let mb10 = vector::borrow(m, 10);
        let mopt10 = algebra::deserialize<Fr, FormatFrLsb>(mb10);
        let m22 = option::extract(&mut mopt10);
        let mb11 = vector::borrow(m, 11);
        let mopt11 = algebra::deserialize<Fr, FormatFrLsb>(mb11);
        let m23 = option::extract(&mut mopt11);
        let mb12 = vector::borrow(m, 12);
        let mopt12 = algebra::deserialize<Fr, FormatFrLsb>(mb12);
        let m30 = option::extract(&mut mopt12);
        let mb13 = vector::borrow(m, 13);
        let mopt13 = algebra::deserialize<Fr, FormatFrLsb>(mb13);
        let m31 = option::extract(&mut mopt13);
        let mb14 = vector::borrow(m, 14);
        let mopt14 = algebra::deserialize<Fr, FormatFrLsb>(mb14);
        let m32 = option::extract(&mut mopt14);
        let mb15 = vector::borrow(m, 15);
        let mopt15 = algebra::deserialize<Fr, FormatFrLsb>(mb15);
        let m33 = option::extract(&mut mopt15);

        // ---- Initial state[i] += C[i] (4 lanes) ----
        let cb0 = vector::borrow(c, 0);
        let kopt0 = algebra::deserialize<Fr, FormatFrLsb>(cb0);
        let k0 = option::extract(&mut kopt0);
        let cb1 = vector::borrow(c, 1);
        let kopt1 = algebra::deserialize<Fr, FormatFrLsb>(cb1);
        let k1 = option::extract(&mut kopt1);
        let cb2 = vector::borrow(c, 2);
        let kopt2 = algebra::deserialize<Fr, FormatFrLsb>(cb2);
        let k2 = option::extract(&mut kopt2);
        let cb3 = vector::borrow(c, 3);
        let kopt3 = algebra::deserialize<Fr, FormatFrLsb>(cb3);
        let k3 = option::extract(&mut kopt3);
        s0 = algebra::add<Fr>(&s0, &k0);
        s1 = algebra::add<Fr>(&s1, &k1);
        s2 = algebra::add<Fr>(&s2, &k2);
        s3 = algebra::add<Fr>(&s3, &k3);

        // ---- First half: Rf/2 - 1 = 3 full rounds ----
        let half_minus_1 = RF / 2 - 1;
        let r = 0;
        while (r < half_minus_1) {
            let cb = (r + 1) * 4;
            // pow5 on all 4 lanes.
            let s0_2 = algebra::sqr<Fr>(&s0);
            let s0_4 = algebra::sqr<Fr>(&s0_2);
            let p0 = algebra::mul<Fr>(&s0_4, &s0);
            let s1_2 = algebra::sqr<Fr>(&s1);
            let s1_4 = algebra::sqr<Fr>(&s1_2);
            let p1 = algebra::mul<Fr>(&s1_4, &s1);
            let s2_2 = algebra::sqr<Fr>(&s2);
            let s2_4 = algebra::sqr<Fr>(&s2_2);
            let p2 = algebra::mul<Fr>(&s2_4, &s2);
            let s3_2 = algebra::sqr<Fr>(&s3);
            let s3_4 = algebra::sqr<Fr>(&s3_2);
            let p3 = algebra::mul<Fr>(&s3_4, &s3);
            // C[cb..cb+4]
            let kb0 = vector::borrow(c, cb);
            let kop0 = algebra::deserialize<Fr, FormatFrLsb>(kb0);
            let kk0 = option::extract(&mut kop0);
            let kb1 = vector::borrow(c, cb + 1);
            let kop1 = algebra::deserialize<Fr, FormatFrLsb>(kb1);
            let kk1 = option::extract(&mut kop1);
            let kb2 = vector::borrow(c, cb + 2);
            let kop2 = algebra::deserialize<Fr, FormatFrLsb>(kb2);
            let kk2 = option::extract(&mut kop2);
            let kb3 = vector::borrow(c, cb + 3);
            let kop3 = algebra::deserialize<Fr, FormatFrLsb>(kb3);
            let kk3 = option::extract(&mut kop3);
            let a0 = algebra::add<Fr>(&p0, &kk0);
            let a1 = algebra::add<Fr>(&p1, &kk1);
            let a2 = algebra::add<Fr>(&p2, &kk2);
            let a3 = algebra::add<Fr>(&p3, &kk3);
            // Dense 4x4 M·state (first-product accumulator).
            let q00 = algebra::mul<Fr>(&m00, &a0);
            let q01 = algebra::mul<Fr>(&m01, &a1);
            let r01 = algebra::add<Fr>(&q00, &q01);
            let q02 = algebra::mul<Fr>(&m02, &a2);
            let r012 = algebra::add<Fr>(&r01, &q02);
            let q03 = algebra::mul<Fr>(&m03, &a3);
            s0 = algebra::add<Fr>(&r012, &q03);
            let q10 = algebra::mul<Fr>(&m10, &a0);
            let q11 = algebra::mul<Fr>(&m11, &a1);
            let r11 = algebra::add<Fr>(&q10, &q11);
            let q12 = algebra::mul<Fr>(&m12, &a2);
            let r112 = algebra::add<Fr>(&r11, &q12);
            let q13 = algebra::mul<Fr>(&m13, &a3);
            s1 = algebra::add<Fr>(&r112, &q13);
            let q20 = algebra::mul<Fr>(&m20, &a0);
            let q21 = algebra::mul<Fr>(&m21, &a1);
            let r21 = algebra::add<Fr>(&q20, &q21);
            let q22 = algebra::mul<Fr>(&m22, &a2);
            let r212 = algebra::add<Fr>(&r21, &q22);
            let q23 = algebra::mul<Fr>(&m23, &a3);
            s2 = algebra::add<Fr>(&r212, &q23);
            let q30 = algebra::mul<Fr>(&m30, &a0);
            let q31 = algebra::mul<Fr>(&m31, &a1);
            let r31 = algebra::add<Fr>(&q30, &q31);
            let q32 = algebra::mul<Fr>(&m32, &a2);
            let r312 = algebra::add<Fr>(&r31, &q32);
            let q33 = algebra::mul<Fr>(&m33, &a3);
            s3 = algebra::add<Fr>(&r312, &q33);
            r = r + 1;
        };

        // ---- Bridge: pow5(state) + C[(Rf/2)*t + i] + P·state ----
        let half = RF / 2;
        let bridge_cb = half * 4;
        let bs0_2 = algebra::sqr<Fr>(&s0);
        let bs0_4 = algebra::sqr<Fr>(&bs0_2);
        let bp0 = algebra::mul<Fr>(&bs0_4, &s0);
        let bs1_2 = algebra::sqr<Fr>(&s1);
        let bs1_4 = algebra::sqr<Fr>(&bs1_2);
        let bp1 = algebra::mul<Fr>(&bs1_4, &s1);
        let bs2_2 = algebra::sqr<Fr>(&s2);
        let bs2_4 = algebra::sqr<Fr>(&bs2_2);
        let bp2 = algebra::mul<Fr>(&bs2_4, &s2);
        let bs3_2 = algebra::sqr<Fr>(&s3);
        let bs3_4 = algebra::sqr<Fr>(&bs3_2);
        let bp3 = algebra::mul<Fr>(&bs3_4, &s3);
        let bkb0 = vector::borrow(c, bridge_cb);
        let bkop0 = algebra::deserialize<Fr, FormatFrLsb>(bkb0);
        let bk0 = option::extract(&mut bkop0);
        let bkb1 = vector::borrow(c, bridge_cb + 1);
        let bkop1 = algebra::deserialize<Fr, FormatFrLsb>(bkb1);
        let bk1 = option::extract(&mut bkop1);
        let bkb2 = vector::borrow(c, bridge_cb + 2);
        let bkop2 = algebra::deserialize<Fr, FormatFrLsb>(bkb2);
        let bk2 = option::extract(&mut bkop2);
        let bkb3 = vector::borrow(c, bridge_cb + 3);
        let bkop3 = algebra::deserialize<Fr, FormatFrLsb>(bkb3);
        let bk3 = option::extract(&mut bkop3);
        let ba0 = algebra::add<Fr>(&bp0, &bk0);
        let ba1 = algebra::add<Fr>(&bp1, &bk1);
        let ba2 = algebra::add<Fr>(&bp2, &bk2);
        let ba3 = algebra::add<Fr>(&bp3, &bk3);
        // Compute P·state via helper (P inlined-deserialize there to keep
        // local count of this function under Move's 255 cap).
        let (ns0, ns1, ns2, ns3) = bridge_p_apply_t4(p, &ba0, &ba1, &ba2, &ba3);
        s0 = ns0;
        s1 = ns1;
        s2 = ns2;
        s3 = ns3;

        // ---- Rp = 56 partial rounds, TRUE-SPARSE (7 muls per round = 2t-1 for t=4) ----
        // Partial-round C base: (Rf/2 + 1)*t = 5*4 = 20.
        let part_c_base = (half + 1) * 4;
        // S_packed[r] occupies indices r*7 .. r*7 + 7 (7 entries per round, t=4).
        let pr = 0;
        while (pr < RP_T4) {
            // Partial S-box: pow5 only on s0.
            let q0_2 = algebra::sqr<Fr>(&s0);
            let q0_4 = algebra::sqr<Fr>(&q0_2);
            let q0 = algebra::mul<Fr>(&q0_4, &s0);
            // Add partial-round constant.
            let pcb = vector::borrow(c, part_c_base + pr);
            let pcopt = algebra::deserialize<Fr, FormatFrLsb>(pcb);
            let pc = option::extract(&mut pcopt);
            let qa0 = algebra::add<Fr>(&q0, &pc);
            // Sparse S_packed[pr] = 7 entries:
            //   row0[0..3]: 4 entries (sb_base+0..3)
            //   col_below: 3 entries (sb_base+4..6) — col_1[0], col_2[0], col_3[0]
            let sb_base = pr * 7;
            let sb0 = vector::borrow(s_packed, sb_base);
            let sopt0 = algebra::deserialize<Fr, FormatFrLsb>(sb0);
            let sr0 = option::extract(&mut sopt0);
            let sb1 = vector::borrow(s_packed, sb_base + 1);
            let sopt1 = algebra::deserialize<Fr, FormatFrLsb>(sb1);
            let sr1 = option::extract(&mut sopt1);
            let sb2 = vector::borrow(s_packed, sb_base + 2);
            let sopt2 = algebra::deserialize<Fr, FormatFrLsb>(sb2);
            let sr2 = option::extract(&mut sopt2);
            let sb3 = vector::borrow(s_packed, sb_base + 3);
            let sopt3 = algebra::deserialize<Fr, FormatFrLsb>(sb3);
            let sr3 = option::extract(&mut sopt3);
            let sb4 = vector::borrow(s_packed, sb_base + 4);
            let sopt4 = algebra::deserialize<Fr, FormatFrLsb>(sb4);
            let sc1 = option::extract(&mut sopt4);
            let sb5 = vector::borrow(s_packed, sb_base + 5);
            let sopt5 = algebra::deserialize<Fr, FormatFrLsb>(sb5);
            let sc2 = option::extract(&mut sopt5);
            let sb6 = vector::borrow(s_packed, sb_base + 6);
            let sopt6 = algebra::deserialize<Fr, FormatFrLsb>(sb6);
            let sc3 = option::extract(&mut sopt6);
            // new[0] = row0[0]*qa0 + row0[1]*s1 + row0[2]*s2 + row0[3]*s3   (4 muls = t)
            let n00 = algebra::mul<Fr>(&sr0, &qa0);
            let n01 = algebra::mul<Fr>(&sr1, &s1);
            let n012 = algebra::add<Fr>(&n00, &n01);
            let n02 = algebra::mul<Fr>(&sr2, &s2);
            let n0123 = algebra::add<Fr>(&n012, &n02);
            let n03 = algebra::mul<Fr>(&sr3, &s3);
            let new_s0 = algebra::add<Fr>(&n0123, &n03);
            // new[i] = s[i] + col_i_0 * qa0  for i = 1, 2, 3   (3 muls = t-1)
            let m1 = algebra::mul<Fr>(&sc1, &qa0);
            let new_s1 = algebra::add<Fr>(&s1, &m1);
            let m2 = algebra::mul<Fr>(&sc2, &qa0);
            let new_s2 = algebra::add<Fr>(&s2, &m2);
            let m3 = algebra::mul<Fr>(&sc3, &qa0);
            let new_s3 = algebra::add<Fr>(&s3, &m3);
            // Total muls: 4 (row0) + 1 + 1 + 1 = 7 = 2t-1 for t=4.
            s0 = new_s0;
            s1 = new_s1;
            s2 = new_s2;
            s3 = new_s3;
            pr = pr + 1;
        };

        // ---- Second half: Rf/2 - 1 = 3 full rounds ----
        // C-base: (Rf/2+1)*t + RP = 20 + 56 = 76.
        let post_c_base = (half + 1) * 4 + RP_T4;
        let r2 = 0;
        while (r2 < half_minus_1) {
            let cb2 = post_c_base + r2 * 4;
            let s0_2b = algebra::sqr<Fr>(&s0);
            let s0_4b = algebra::sqr<Fr>(&s0_2b);
            let pp0 = algebra::mul<Fr>(&s0_4b, &s0);
            let s1_2b = algebra::sqr<Fr>(&s1);
            let s1_4b = algebra::sqr<Fr>(&s1_2b);
            let pp1 = algebra::mul<Fr>(&s1_4b, &s1);
            let s2_2b = algebra::sqr<Fr>(&s2);
            let s2_4b = algebra::sqr<Fr>(&s2_2b);
            let pp2 = algebra::mul<Fr>(&s2_4b, &s2);
            let s3_2b = algebra::sqr<Fr>(&s3);
            let s3_4b = algebra::sqr<Fr>(&s3_2b);
            let pp3 = algebra::mul<Fr>(&s3_4b, &s3);
            let kkb0 = vector::borrow(c, cb2);
            let kkop0 = algebra::deserialize<Fr, FormatFrLsb>(kkb0);
            let nk0 = option::extract(&mut kkop0);
            let kkb1 = vector::borrow(c, cb2 + 1);
            let kkop1 = algebra::deserialize<Fr, FormatFrLsb>(kkb1);
            let nk1 = option::extract(&mut kkop1);
            let kkb2 = vector::borrow(c, cb2 + 2);
            let kkop2 = algebra::deserialize<Fr, FormatFrLsb>(kkb2);
            let nk2 = option::extract(&mut kkop2);
            let kkb3 = vector::borrow(c, cb2 + 3);
            let kkop3 = algebra::deserialize<Fr, FormatFrLsb>(kkb3);
            let nk3 = option::extract(&mut kkop3);
            let na0 = algebra::add<Fr>(&pp0, &nk0);
            let na1 = algebra::add<Fr>(&pp1, &nk1);
            let na2 = algebra::add<Fr>(&pp2, &nk2);
            let na3 = algebra::add<Fr>(&pp3, &nk3);
            // 4x4 dense MDS.
            let z00 = algebra::mul<Fr>(&m00, &na0);
            let z01 = algebra::mul<Fr>(&m01, &na1);
            let zr01 = algebra::add<Fr>(&z00, &z01);
            let z02 = algebra::mul<Fr>(&m02, &na2);
            let zr012 = algebra::add<Fr>(&zr01, &z02);
            let z03 = algebra::mul<Fr>(&m03, &na3);
            s0 = algebra::add<Fr>(&zr012, &z03);
            let y00 = algebra::mul<Fr>(&m10, &na0);
            let y01 = algebra::mul<Fr>(&m11, &na1);
            let yr01 = algebra::add<Fr>(&y00, &y01);
            let y02 = algebra::mul<Fr>(&m12, &na2);
            let yr012 = algebra::add<Fr>(&yr01, &y02);
            let y03 = algebra::mul<Fr>(&m13, &na3);
            s1 = algebra::add<Fr>(&yr012, &y03);
            let u00 = algebra::mul<Fr>(&m20, &na0);
            let u01 = algebra::mul<Fr>(&m21, &na1);
            let ur01 = algebra::add<Fr>(&u00, &u01);
            let u02 = algebra::mul<Fr>(&m22, &na2);
            let ur012 = algebra::add<Fr>(&ur01, &u02);
            let u03 = algebra::mul<Fr>(&m23, &na3);
            s2 = algebra::add<Fr>(&ur012, &u03);
            let t00 = algebra::mul<Fr>(&m30, &na0);
            let t01 = algebra::mul<Fr>(&m31, &na1);
            let tr01 = algebra::add<Fr>(&t00, &t01);
            let t02 = algebra::mul<Fr>(&m32, &na2);
            let tr012 = algebra::add<Fr>(&tr01, &t02);
            let t03 = algebra::mul<Fr>(&m33, &na3);
            s3 = algebra::add<Fr>(&tr012, &t03);
            r2 = r2 + 1;
        };

        // ---- Final pow5 + M-mix, no C add. Last-round skip: only n0. ----
        let f0_2 = algebra::sqr<Fr>(&s0);
        let f0_4 = algebra::sqr<Fr>(&f0_2);
        let f0 = algebra::mul<Fr>(&f0_4, &s0);
        let f1_2 = algebra::sqr<Fr>(&s1);
        let f1_4 = algebra::sqr<Fr>(&f1_2);
        let f1 = algebra::mul<Fr>(&f1_4, &s1);
        let f2_2 = algebra::sqr<Fr>(&s2);
        let f2_4 = algebra::sqr<Fr>(&f2_2);
        let f2 = algebra::mul<Fr>(&f2_4, &s2);
        let f3_2 = algebra::sqr<Fr>(&s3);
        let f3_4 = algebra::sqr<Fr>(&f3_2);
        let f3 = algebra::mul<Fr>(&f3_4, &s3);
        // Last-round: only s0 = M[0][·] · state.
        let l00 = algebra::mul<Fr>(&m00, &f0);
        let l01 = algebra::mul<Fr>(&m01, &f1);
        let lr01 = algebra::add<Fr>(&l00, &l01);
        let l02 = algebra::mul<Fr>(&m02, &f2);
        let lr012 = algebra::add<Fr>(&lr01, &l02);
        let l03 = algebra::mul<Fr>(&m03, &f3);
        algebra::add<Fr>(&lr012, &l03)
    }
}

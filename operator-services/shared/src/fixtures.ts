// Authoritative Move-side fixture bytes captured from:
//
//  * Aptos framework `poseidon_bn254_vector_tests.move` test vectors
//    (source: aptos-core, vendored at /private/tmp/round5_main_postmerge_stage)
//  * Gate 4a's `circuits/generated/move_fixtures/move_constants.move` for
//    Groth16 VK + proof + public inputs.
//  * Cross-reference Aptos BCS spec
//    (https://github.com/diem/bcs) for DepositAttestationMessage +
//    CAPayloadForHash byte expectations — verified independently against
//    Move's `bcs::to_bytes` semantics:
//      - vector<u8> = ULEB128(len) || bytes
//      - vector<vector<u8>> = ULEB128(outer_len) || (each inner uleb128(len) || bytes)
//      - struct = concatenation of fields in declared order
//      - address = 32 raw bytes (no prefix)
//      - u8 = 1 raw byte; u64 = 8 raw bytes LE
//
// These are LOAD-BEARING for parity: the operator service signs over BCS
// bytes that MUST equal what Move's `bcs::to_bytes(&DepositAttestationMessage{...})`
// produces, otherwise on-chain `signature_verify_strict` fails for every deposit.

import { hexToBytes } from "./hex.js";

// ----- Poseidon hash_2 fixtures (Aptos framework test vectors) -----
//
// Format: [a_hex_le32, b_hex_le32, expected_hex_le32]
export const POSEIDON_HASH_2_FIXTURES: ReadonlyArray<{
  a: string;
  b: string;
  expected: string;
}> = [
  {
    a: "0000000000000000000000000000000000000000000000000000000000000000",
    b: "0000000000000000000000000000000000000000000000000000000000000000",
    expected:
      "6448b64684ee39a823d5fe5fd52431dc81e4817bf2c3ea3cab9e239efbf59820",
  },
  {
    a: "0100000000000000000000000000000000000000000000000000000000000000",
    b: "0000000000000000000000000000000000000000000000000000000000000000",
    expected:
      "7f3bc41c4a989182fb77c1ca3b9797d198428d32c77d176a896e56c7a228bb28",
  },
  {
    a: "0000000000000000000000000000000000000000000000000000000000000000",
    b: "0100000000000000000000000000000000000000000000000000000000000000",
    expected:
      "5ee65399c487bf756dd383c09a8b3c36a1a3882e8a7743c63098def53408d21b",
  },
  {
    a: "0100000000000000000000000000000000000000000000000000000000000000",
    b: "0100000000000000000000000000000000000000000000000000000000000000",
    expected:
      "811e40ad7ce2af903fe770cb8aa79412773f02f3a9e0799e2704d3e246f37a00",
  },
];

// ----- Poseidon hash_3 fixtures (Aptos framework test vectors) -----
export const POSEIDON_HASH_3_FIXTURES: ReadonlyArray<{
  a: string;
  b: string;
  c: string;
  expected: string;
}> = [
  {
    a: "0000000000000000000000000000000000000000000000000000000000000000",
    b: "0000000000000000000000000000000000000000000000000000000000000000",
    c: "0000000000000000000000000000000000000000000000000000000000000000",
    expected:
      "aa99a51bb36dee7caec596ecec4e86e28ff07a0aafb6cf1ddceacc7dd288c10b",
  },
  {
    a: "0100000000000000000000000000000000000000000000000000000000000000",
    b: "0000000000000000000000000000000000000000000000000000000000000000",
    c: "0000000000000000000000000000000000000000000000000000000000000000",
    expected:
      "1583a926f7364fa62182176b70c3ee8e3f4fd700cecd7cda810e037ae33a1424",
  },
  {
    a: "0000000000000000000000000000000000000000000000000000000000000000",
    b: "0100000000000000000000000000000000000000000000000000000000000000",
    c: "0000000000000000000000000000000000000000000000000000000000000000",
    expected:
      "6df1b5d73b2b7f05559a20634476dea480b385d16d169e7c57ce2350d79dce12",
  },
  {
    a: "0000000000000000000000000000000000000000000000000000000000000000",
    b: "0000000000000000000000000000000000000000000000000000000000000000",
    c: "0100000000000000000000000000000000000000000000000000000000000000",
    expected:
      "7b062539bde2d80749746986cf8f0001fd2cdbf9a89fcbf981a769daef49df06",
  },
  {
    a: "0100000000000000000000000000000000000000000000000000000000000000",
    b: "0100000000000000000000000000000000000000000000000000000000000000",
    c: "0100000000000000000000000000000000000000000000000000000000000000",
    expected:
      "4325bf7386b102c223cd6109e3b6b1bc813ecb14b2c3332bbd2aa7106e06c002",
  },
];

// ----- Gate 4a circuit fixture (placeholder asset_id + vault_addr_hash) -----
//
// These are the public inputs that Gate 4a's circuit accepts: amount=2,
// chain_id=2, pool_id=0, asset_id=7, vault_addr_hash=0xedaff..., commitment
// computed from the Compose5 recipe.
export const GATE_4A_FIXTURE = {
  // public_valid_2 (asset_id placeholder, Fr=7)
  asset_id_le32:
    "0700000000000000000000000000000000000000000000000000000000000000",
  // public_valid_3 (vault_addr_hash placeholder)
  vault_addr_hash_le32:
    "edaffceedbeaedaffceedbeaedaffceedbeaedaffceedbeaedaffcee0befbe00",
  // public_valid_4 (chain_id Fr=2)
  chain_id_le32:
    "0200000000000000000000000000000000000000000000000000000000000000",
  // public_valid_5 (pool_id Fr=0)
  pool_id_le32:
    "0000000000000000000000000000000000000000000000000000000000000000",
  // public_valid_0 (commitment)
  commitment_le32:
    "942a57ac99245f1b86c292b9f835bc920a801db326a996b945c0bdbc48194613",
  // public_valid_1 (amount_tag)
  amount_tag_le32:
    "02ba8cc71dad30d608b7a18018136fd36c83275b39c4a394de57060eeb368d2b",
  // Captured from circuits/inputs/valid_input.json — the actual private input
  // used to generate proof_valid.json + public_valid.json:
  amount: 1000000000n, // u64
  chain_id: 2,
  // deposit_blind as decimal string (not necessarily fitting in 32 bytes LE
  // canonically; convert via BigInt → 32-byte LE in test).
  deposit_blind_decimal: "11111111111111111111111111111111111111111111111111",
};

// ----- Gate 4a Groth16 fixtures -----
export const GATE_4A_GROTH16 = {
  vk_alpha_g1:
    "12c16beca06688485d74f21688948e77dedd9a4ad68b28b0eeb6293252e56826ae44c5727d76b62d79f2923c1c1bc5f58e778c4b03a3c58903cc6a1efc189109",
  vk_beta_g2:
    "1ca4e89cceb6a9b7caabcd83980fcd69ef6df2b9d5f7b45d082e247807493c0ce21e5e7224aab40a95a0434fe84af514f9f81a5a4884abccad4fb8ec072a620d688459b1d0c167b809117b8cd25eb18b191f1a6f1406d4873ce49d06439c9e0fc8226b4a8f6578991eade15e60729cd6854e7160ae4b5d9640993c13184cb80b",
  proof_a:
    "563a82d087123e7ed6cb052d4ef2dfb1bbcaf5608aa3eed453961f1cff28ce0808bfdaf65db51237a8b6ac7ae850d2c71c8d163917878b720b7a28a7fa9b0a04",
  proof_b:
    "af85308ab54987eea77378e1c08431e95d426246a82aef98126e469b5e948a09a694e5e3c948af54389765ef6cb314f4dc948e98789413bc59605dabb60a0c30513c5cb1dd31dccac277ea09ff7f3ab872b529ba538b0efa3ccfda19dac8ab12db23b1910b2dc1b727df4fb98b3fa9f608aaa1de6024f4a67b0486710cba3a0c",
  proof_c:
    "7ed6521e6bfacd5706f729a3274b59d6ea5197c33ce78a525fec47c784da6b131cc036b931eb3aabaae11cb4958d84e4ab6fd82d018e1a1d8cfccd4b1413b219",
};

// ----- BCS parity fixtures: DepositAttestationMessage -----
//
// 3 fixtures spanning empty/short/long byte-vector cases, each with
// independently-computed expected BCS bytes verified against Aptos BCS spec.
// (See test parity_bcs.test.ts for cross-check vs aptos-ts-sdk Serializer.)
export const BCS_DEPOSIT_ATTESTATION_FIXTURES = [
  {
    name: "fixture_0_minimal_empty_bytes",
    msg: {
      domain: hexToBytes("00"),
      chain_id: 2,
      pool_id: hexToBytes("0000000000000000"),
      operator_set_version: 1n,
      threshold: 4n,
      vault_addr: hexToBytes(
        "0000000000000000000000000000000000000000000000000000000000000001",
      ),
      asset_type: hexToBytes(
        "0000000000000000000000000000000000000000000000000000000000000002",
      ),
      commitment: new Uint8Array(),
      amount_tag: new Uint8Array(),
      ca_payload_hash: new Uint8Array(),
      deposit_nonce: new Uint8Array(),
      expiry_secs: 0n,
    },
    // Computed by hand:
    //   vec(0x00) = 01 00
    //   chain_id u8 = 02
    //   vec(8x00) = 08 0000000000000000
    //   u64(1) LE = 0100000000000000
    //   u64(4) LE = 0400000000000000
    //   addr1 = 32 bytes
    //   addr2 = 32 bytes
    //   vec()*4 = 00 each (4 empty vectors)
    //   u64(0) = 0000000000000000
    expected_bcs_hex:
      "0100" + // domain vec
      "02" + // chain_id
      "080000000000000000" + // pool_id vec
      "0100000000000000" + // op_set_version
      "0400000000000000" + // threshold
      "0000000000000000000000000000000000000000000000000000000000000001" + // vault_addr
      "0000000000000000000000000000000000000000000000000000000000000002" + // asset_type
      "00" + // commitment vec(empty)
      "00" + // amount_tag vec(empty)
      "00" + // ca_payload_hash vec(empty)
      "00" + // deposit_nonce vec(empty)
      "0000000000000000", // expiry_secs
  },
  {
    name: "fixture_1_realistic_32B_bytes",
    msg: {
      domain: new TextEncoder().encode("APTOSHIELD_DEPOSIT_OK_V1"), // 24 bytes
      chain_id: 2,
      pool_id: hexToBytes("0000000000000000"),
      operator_set_version: 1n,
      threshold: 4n,
      vault_addr: hexToBytes(
        "1111111111111111111111111111111111111111111111111111111111111111",
      ),
      asset_type: hexToBytes(
        "2222222222222222222222222222222222222222222222222222222222222222",
      ),
      commitment: hexToBytes(
        "942a57ac99245f1b86c292b9f835bc920a801db326a996b945c0bdbc48194613",
      ),
      amount_tag: hexToBytes(
        "02ba8cc71dad30d608b7a18018136fd36c83275b39c4a394de57060eeb368d2b",
      ),
      ca_payload_hash: hexToBytes(
        "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef",
      ),
      deposit_nonce: hexToBytes("01020304"),
      expiry_secs: 1735689600n, // 2025-01-01 UTC
    },
    // domain "APTOSHIELD_DEPOSIT_OK_V1" = 24 bytes; uleb128(24)=18.
    expected_bcs_hex:
      "18" +
      "415054 4f53 4849 454c 445f 4445 504f 5349 545f 4f4b 5f56 31".replace(/\s+/g, "") +
      "02" +
      "080000000000000000" +
      "0100000000000000" +
      "0400000000000000" +
      "1111111111111111111111111111111111111111111111111111111111111111" +
      "2222222222222222222222222222222222222222222222222222222222222222" +
      "20942a57ac99245f1b86c292b9f835bc920a801db326a996b945c0bdbc48194613" +
      "2002ba8cc71dad30d608b7a18018136fd36c83275b39c4a394de57060eeb368d2b" +
      "20deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef" +
      "0401020304" +
      // u64(1735689600) LE: 1735689600 = 0x67748580 -> LE bytes 80 85 74 67 00 00 00 00
      "8085746700000000",
  },
  {
    name: "fixture_2_max_threshold_high_chain_id",
    msg: {
      domain: hexToBytes("ff"),
      chain_id: 0xff,
      pool_id: hexToBytes("ffffffffffffffff"),
      operator_set_version: 18446744073709551615n, // u64::MAX
      threshold: 7n,
      vault_addr: hexToBytes(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      ),
      asset_type: hexToBytes(
        "ababababababababababababababababababababababababababababababab00",
      ),
      commitment: hexToBytes("aa"),
      amount_tag: hexToBytes("bb"),
      ca_payload_hash: hexToBytes("cc"),
      deposit_nonce: hexToBytes("dd"),
      expiry_secs: 18446744073709551615n,
    },
    expected_bcs_hex:
      "01ff" +
      "ff" +
      "08ffffffffffffffff" +
      "ffffffffffffffff" +
      "0700000000000000" +
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
      "ababababababababababababababababababababababababababababababab00" +
      "01aa" +
      "01bb" +
      "01cc" +
      "01dd" +
      "ffffffffffffffff",
  },
];

// ----- BCS parity fixtures: CAPayloadForHash -----
export const BCS_CA_PAYLOAD_FIXTURES = [
  {
    name: "fixture_0_all_empty",
    payload: {
      asset_type: hexToBytes(
        "0000000000000000000000000000000000000000000000000000000000000002",
      ),
      vault_addr: hexToBytes(
        "0000000000000000000000000000000000000000000000000000000000000001",
      ),
      new_balance_p: [],
      new_balance_r: [],
      new_balance_r_eff_aud: [],
      amount_p: [],
      amount_r_sender: [],
      amount_r_recip: [],
      amount_r_eff_aud: [],
      ek_volun_auds: [],
      amount_r_volun_auds: [],
      zkrp_new_balance: new Uint8Array(),
      zkrp_amount: new Uint8Array(),
      sigma_proto_comm: [],
      sigma_proto_resp: [],
      memo: new Uint8Array(),
    },
    // 32B asset_type || 32B vault_addr || 11x 0x00 (empty vectors) || 0x00 memo
    expected_bcs_hex:
      "0000000000000000000000000000000000000000000000000000000000000002" +
      "0000000000000000000000000000000000000000000000000000000000000001" +
      // 14 empty vector lengths (uleb128 0 = 0x00):
      //   8 × vec<vec<u8>> (new_balance_p..ek_volun_auds), 1 × vec<vec<vec<u8>>>
      //   (amount_r_volun_auds), 2 × vec<u8> (zkrp_new_balance, zkrp_amount),
      //   2 × vec<vec<u8>> (sigma_proto_comm, sigma_proto_resp), 1 × vec<u8> (memo).
      "00".repeat(14),
  },
  {
    name: "fixture_1_one_inner_per_vec",
    payload: {
      asset_type: hexToBytes(
        "1111111111111111111111111111111111111111111111111111111111111111",
      ),
      vault_addr: hexToBytes(
        "2222222222222222222222222222222222222222222222222222222222222222",
      ),
      new_balance_p: [hexToBytes("aa")],
      new_balance_r: [hexToBytes("bb")],
      new_balance_r_eff_aud: [hexToBytes("cc")],
      amount_p: [hexToBytes("dd")],
      amount_r_sender: [hexToBytes("ee")],
      amount_r_recip: [hexToBytes("ff")],
      amount_r_eff_aud: [hexToBytes("00")],
      ek_volun_auds: [hexToBytes("11")],
      amount_r_volun_auds: [[hexToBytes("22")]],
      zkrp_new_balance: hexToBytes("33"),
      zkrp_amount: hexToBytes("44"),
      sigma_proto_comm: [hexToBytes("55")],
      sigma_proto_resp: [hexToBytes("66")],
      memo: hexToBytes("77"),
    },
    expected_bcs_hex:
      "1111111111111111111111111111111111111111111111111111111111111111" +
      "2222222222222222222222222222222222222222222222222222222222222222" +
      "0101aa" + // new_balance_p: outer=1, inner=[1 byte 0xaa]
      "0101bb" +
      "0101cc" +
      "0101dd" +
      "0101ee" +
      "0101ff" +
      "010100" +
      "010111" +
      "01" + "01" + "0122" + // amount_r_volun_auds: outer=1, middle=1, inner=[1 byte 0x22]
      "0133" + // zkrp_new_balance vec<u8> len=1
      "0144" + // zkrp_amount
      "010155" + // sigma_proto_comm
      "010166" +
      "0177", // memo
  },
  {
    name: "fixture_2_multi_inner",
    payload: {
      asset_type: hexToBytes(
        "abababababababababababababababababababababababababababababababab",
      ),
      vault_addr: hexToBytes(
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      ),
      new_balance_p: [hexToBytes("01"), hexToBytes("0203")],
      new_balance_r: [],
      new_balance_r_eff_aud: [],
      amount_p: [],
      amount_r_sender: [],
      amount_r_recip: [],
      amount_r_eff_aud: [],
      ek_volun_auds: [],
      amount_r_volun_auds: [
        [hexToBytes("aa"), hexToBytes("bbcc")],
        [],
      ],
      zkrp_new_balance: hexToBytes("aabb"),
      zkrp_amount: new Uint8Array(),
      sigma_proto_comm: [hexToBytes("dead")],
      sigma_proto_resp: [],
      memo: new TextEncoder().encode("hello"),
    },
    expected_bcs_hex:
      "abababababababababababababababababababababababababababababababab" +
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
      "020101020203" + // new_balance_p: 2 inners [01], [02 03]
      "00".repeat(7) + // 7 empty vec<vec<u8>>
      "02" + "0201aa02bbcc" + "00" + // amount_r_volun_auds: 2 middles, first has 2 inners, second empty
      "02aabb" + // zkrp_new_balance vec<u8> len=2
      "00" + // zkrp_amount empty
      "0102dead" + // sigma_proto_comm
      "00" + // sigma_proto_resp empty
      "0568656c6c6f", // memo "hello"
  },
];

// ----- keccak parity fixtures (compute via hash_confidential_transfer_payload) -----
//
// These are computed as keccak256(bcs(CAPayloadForHash{...})) where the BCS
// bytes are the verified `expected_bcs_hex` from BCS_CA_PAYLOAD_FIXTURES.
// Independently computed using a reference Keccak-256 implementation
// (https://emn178.github.io/online-tools/keccak_256.html / Node `crypto`).
//
// Rather than embed a hex digest the operator can't independently verify, we
// compute these AT TEST RUN TIME by feeding `expected_bcs_hex` (the
// authoritative byte string) through `keccak256` and asserting that the
// result equals `hashConfidentialTransferPayload(payload)` (the operator-side
// implementation, which BCS-encodes the payload itself and then keccaks).
// If both reach the same digest by independent paths, parity holds.
//
// See `tests/parity_keccak.test.ts` for the runtime computation.

export {};

import { describe, expect, it } from "vitest";
import {
  bcsEncodeDepositAttestationV2,
  bcsEncodeWithdrawAttestationV2,
  caPayloadHashFrV2,
  caPayloadHashRawV2,
} from "../src/index.js";

const h32 = (byte: string) => byte.repeat(64);
const point = (byte: string) => byte.repeat(64);

describe("withdraw attestation BCS", () => {
  it("encodes deterministically", () => {
    const bytes = bcsEncodeWithdrawAttestationV2({
      chainId: 2,
      bridge: h32("1"),
      vault: h32("2"),
      assetType: h32("3"),
      operatorSetVersion: "1",
      dkgEpoch: "2",
      rosterHash: h32("4"),
      frostGroupPubkey: h32("5"),
      root: h32("6"),
      nullifierHash: h32("7"),
      recipient: h32("8"),
      recipientHash: h32("9"),
      amountTag: h32("a"),
      caPayloadHash: h32("b"),
      requestHash: h32("c"),
      vaultSequence: "3",
      expirySecs: "4",
      circuitVersionsHash: h32("d"),
    });
    expect(Buffer.from(bytes).toString("hex")).toMatchInlineSnapshot(
      `"1e45554e4f4d415f57495448445241575f4154544553544154494f4e5f56320211111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333301000000000000000200000000000000204444444444444444444444444444444444444444444444444444444444444444205555555555555555555555555555555555555555555555555555555555555555206666666666666666666666666666666666666666666666666666666666666666207777777777777777777777777777777777777777777777777777777777777777888888888888888888888888888888888888888888888888888888888888888820999999999999999999999999999999999999999999999999999999999999999920aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb20cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0300000000000000040000000000000020dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"`,
    );
  });
});

describe("deposit attestation BCS", () => {
  it("encodes with the testnet chain id and typed payload hash", () => {
    const bytes = bcsEncodeDepositAttestationV2({
      chainId: 2,
      bridge: h32("1"),
      vault: h32("2"),
      assetType: h32("3"),
      operatorSetVersion: "1",
      dkgEpoch: "2",
      rosterHash: h32("4"),
      frostGroupPubkey: h32("5"),
      commitment: h32("6"),
      amountTag: h32("7"),
      caPayloadHash: h32("8"),
      depositNonce: "99",
      expirySecs: "3",
      circuitVersionsHash: h32("9"),
      userAddr: h32("a"),
    });
    // (B) domain bumped V2→V3 — the deposit attestation now binds user_addr.
    expect(Buffer.from(bytes.subarray(0, 23)).toString("hex")).toBe(
      "1645554e4f4d415f4445504f5349545f42494e445f5633",
    );
    expect(bytes[23]).toBe(2);
  });

  it("is byte-identical to the Move serializer with user_addr (golden cross-check)", () => {
    // Golden = the exact bytes asserted by the Move byte-identity test
    // (move/tests/deposit_attestation_user_addr_test.move). Same inputs; user_addr (0x..eeeeeee4)
    // appended as raw 32B. This is the Move↔TS deposit-attestation byte contract — if either side
    // changes field order/encoding, this fails.
    const addr = (suffix: string) => "0".repeat(64 - suffix.length) + suffix;
    const bytes = bcsEncodeDepositAttestationV2({
      chainId: 2,
      bridge: addr("eeeeeee1"),
      vault: addr("eeeeeee2"),
      assetType: addr("eeeeeee3"),
      operatorSetVersion: "1",
      dkgEpoch: "9",
      rosterHash: h32("a"),
      frostGroupPubkey:
        "0e09035c98f5370bd5f1213272984e7390e1ddf21066a44bdf9fd7bb2fc668fa",
      commitment: h32("b"),
      amountTag: h32("c"),
      caPayloadHash: h32("d"),
      depositNonce: h32("e"),
      expirySecs: "1800000000",
      circuitVersionsHash: h32("1"),
      userAddr: addr("eeeeeee4"),
    });
    expect(Buffer.from(bytes).toString("hex")).toBe(
      "1645554e4f4d415f4445504f5349545f42494e445f56330200000000000000000000000000000000000000000000000000000000eeeeeee100000000000000000000000000000000000000000000000000000000eeeeeee200000000000000000000000000000000000000000000000000000000eeeeeee30100000000000000090000000000000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa200e09035c98f5370bd5f1213272984e7390e1ddf21066a44bdf9fd7bb2fc668fa20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb20cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc20dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd20eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee00d2496b0000000020111111111111111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000eeeeeee4",
    );
  });
});

describe("CA payload hash V2", () => {
  it("hashes BCS payload bytes and zeroes the high byte for Fr public inputs", () => {
    const payload = {
      assetType: h32("1"),
      to: h32("2"),
      newBalanceP: [point("3")],
      newBalanceR: [point("4")],
      newBalanceREffAud: [],
      amountP: [point("5")],
      amountRSender: [point("6")],
      amountRRecip: [point("7")],
      amountREffAud: [],
      ekVolunAuds: [],
      amountRVolunAuds: [],
      zkrpNewBalance: "aa",
      zkrpAmount: "bb",
      sigmaProtoComm: ["cc"],
      sigmaProtoResp: ["dd"],
      memo: "",
    };
    const raw = caPayloadHashRawV2(payload);
    const fr = caPayloadHashFrV2(payload);
    expect(raw).toHaveLength(64);
    expect(fr).toHaveLength(64);
    expect(fr.slice(0, 62)).toBe(raw.slice(0, 62));
    expect(fr.slice(62)).toBe("00");
  });
});

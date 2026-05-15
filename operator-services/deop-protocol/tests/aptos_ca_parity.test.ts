import { describe, expect, it } from "vitest";
import {
  TwistedEd25519PrivateKey,
  bcsSerializeRegistrationSession,
  proveRegistration,
  verifyRegistration,
} from "@aptos-labs/confidential-asset";
import {
  APTOS_CA_REGISTRATION_PROTOCOL_ID,
  APTOS_CA_REGISTRATION_TYPE_NAME,
  bcsEncodeAptosCaRegistrationSession,
} from "../src/index.js";

const hex = (byte: string) => byte.repeat(64);

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("Aptos CA registration parity", () => {
  it("matches the SDK registration session BCS and proof verifier", () => {
    const senderAddress = Uint8Array.from(Buffer.from(hex("1"), "hex"));
    const assetType = Uint8Array.from(Buffer.from(hex("2"), "hex"));
    const localSession = bcsEncodeAptosCaRegistrationSession(hex("1"), hex("2"));
    const sdkSession = bcsSerializeRegistrationSession(senderAddress, assetType);
    expect(bytesToHex(localSession)).toBe(bytesToHex(sdkSession));

    const dk = new TwistedEd25519PrivateKey(hex("3"));
    const proof = proveRegistration({
      dk,
      senderAddress,
      tokenAddress: assetType,
      chainId: 2,
    });
    expect(proof.commitment).toHaveLength(1);
    expect(proof.response).toHaveLength(1);
    expect(
      verifyRegistration({
        ek: dk.publicKey().toUint8Array(),
        senderAddress,
        tokenAddress: assetType,
        chainId: 2,
        proof,
      }),
    ).toBe(true);
  });

  it("locks the Move domain and type names used by registration sigma", () => {
    expect(APTOS_CA_REGISTRATION_PROTOCOL_ID).toBe("AptosConfidentialAsset/RegistrationV1");
    expect(APTOS_CA_REGISTRATION_TYPE_NAME).toBe(
      "0x1::sigma_protocol_registration::Registration",
    );
  });
});

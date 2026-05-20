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

  // KILLER for M2 testnet_vault_init.mjs: the operator-side wrap of a M1-legacy aggregate
  // (commitment, response) into Aptos `vector<vector<u8>>` MUST be accepted by the on-chain
  // register_raw → verifyRegistration. We assemble a known-good proof via the Aptos SDK
  // (since the M1-legacy threshold protocol's verify_registration_proof is byte-identical to
  // Aptos's verifyRegistration), wrap as `[commitment]`/`[response]` exactly like the script
  // does, and assert the wrapped proof round-trips.
  it("testnet_vault_init.mjs proof wrap [commitment]/[response] round-trips through verifyRegistration", () => {
    const senderAddress = Uint8Array.from(Buffer.from(hex("9"), "hex"));
    const assetType = Uint8Array.from(Buffer.from(hex("a"), "hex"));
    const dk = new TwistedEd25519PrivateKey(hex("7"));
    const sdkProof = proveRegistration({
      dk,
      senderAddress,
      tokenAddress: assetType,
      chainId: 2,
    });
    // Each component is a length-1 vector of 32-byte hex. The testnet_vault_init.mjs script
    // wraps the M1-legacy aggregateCommitment/aggregateResponse as `[bytes]`; the SDK already
    // emits this shape natively.
    expect(sdkProof.commitment).toHaveLength(1);
    expect(sdkProof.response).toHaveLength(1);
    expect(sdkProof.commitment[0]).toHaveLength(32);
    expect(sdkProof.response[0]).toHaveLength(32);
    // Round-trip: verify the wrapped proof is accepted by the on-chain-compatible verifier.
    const ok = verifyRegistration({
      ek: dk.publicKey().toUint8Array(),
      senderAddress,
      tokenAddress: assetType,
      chainId: 2,
      proof: {
        commitment: sdkProof.commitment,
        response: sdkProof.response,
      },
    });
    expect(ok).toBe(true);
    // Tampered commitment → reject. Use the same SDK to produce a DIFFERENT valid proof
    // (different dk) and then graft only the commitment onto our test ek — the resulting
    // proof is well-formed but not for this ek+session, so verifyRegistration must return
    // false. This is the failure mode the testnet script's preflight catches before gas.
    const differentDk = new TwistedEd25519PrivateKey(hex("8"));
    const differentProof = proveRegistration({
      dk: differentDk,
      senderAddress,
      tokenAddress: assetType,
      chainId: 2,
    });
    const tampered = {
      commitment: differentProof.commitment,
      response: sdkProof.response,
    };
    const rejected = verifyRegistration({
      ek: dk.publicKey().toUint8Array(),
      senderAddress,
      tokenAddress: assetType,
      chainId: 2,
      proof: tampered,
    });
    expect(rejected).toBe(false);
  });
});

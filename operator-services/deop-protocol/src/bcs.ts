import { bytesToHex, hexToBytes, keccak256 } from "@eunoma/shared";
import {
  DOMAIN_DEPOSIT_BIND_V2,
  DOMAIN_WITHDRAW_ATTESTATION_V2,
} from "./constants.js";
import type {
  ConfidentialTransferRawPayloadV2,
  DepositAttestationV2Message,
  WithdrawAttestationV2Message,
} from "./types.js";

class Writer {
  private readonly parts: number[] = [];

  writeBytesRaw(bytes: Uint8Array): void {
    for (const byte of bytes) this.parts.push(byte);
  }

  writeU8(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) {
      throw new Error(`u8 out of range: ${value}`);
    }
    this.parts.push(value);
  }

  writeU64(value: bigint): void {
    if (value < 0n || value >= 1n << 64n) {
      throw new Error(`u64 out of range: ${value.toString()}`);
    }
    let remaining = value;
    for (let i = 0; i < 8; i += 1) {
      this.parts.push(Number(remaining & 0xffn));
      remaining >>= 8n;
    }
  }

  writeUleb128(value: number): void {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`uleb128 out of range: ${value}`);
    }
    let remaining = value;
    while (remaining >= 0x80) {
      this.parts.push((remaining & 0x7f) | 0x80);
      remaining >>>= 7;
    }
    this.parts.push(remaining);
  }

  writeVector(bytes: Uint8Array): void {
    this.writeUleb128(bytes.length);
    this.writeBytesRaw(bytes);
  }

  writeString(value: string): void {
    this.writeVector(new TextEncoder().encode(value));
  }

  writeHexVector(hex: string): void {
    this.writeVector(hexToBytes(hex));
  }

  writeHexVectorVector(hexes: string[]): void {
    this.writeUleb128(hexes.length);
    for (const hex of hexes) this.writeHexVector(hex);
  }

  writeHexVectorVectorVector(hexes: string[][]): void {
    this.writeUleb128(hexes.length);
    for (const item of hexes) this.writeHexVectorVector(item);
  }

  writeAddress(hex: string): void {
    const bytes = hexToBytes(hex);
    if (bytes.length !== 32) {
      throw new Error(`address must be 32 bytes, got ${bytes.length}`);
    }
    this.writeBytesRaw(bytes);
  }

  finish(): Uint8Array {
    return new Uint8Array(this.parts);
  }
}

export function bcsEncodeWithdrawAttestationV2(
  msg: WithdrawAttestationV2Message,
): Uint8Array {
  const w = new Writer();
  w.writeVector(new TextEncoder().encode(DOMAIN_WITHDRAW_ATTESTATION_V2));
  w.writeU8(msg.chainId);
  w.writeAddress(msg.bridge);
  w.writeAddress(msg.vault);
  w.writeAddress(msg.assetType);
  w.writeU64(BigInt(msg.operatorSetVersion));
  w.writeU64(BigInt(msg.dkgEpoch));
  w.writeHexVector(msg.rosterHash);
  w.writeHexVector(msg.frostGroupPubkey);
  w.writeHexVector(msg.root);
  w.writeHexVector(msg.nullifierHash);
  w.writeAddress(msg.recipient);
  w.writeHexVector(msg.recipientHash);
  w.writeHexVector(msg.amountTag);
  w.writeHexVector(msg.caPayloadHash);
  w.writeHexVector(msg.requestHash);
  w.writeU64(BigInt(msg.vaultSequence));
  w.writeU64(BigInt(msg.expirySecs));
  w.writeHexVector(msg.circuitVersionsHash);
  return w.finish();
}

export function bcsEncodeDepositAttestationV2(
  msg: DepositAttestationV2Message,
): Uint8Array {
  const w = new Writer();
  w.writeString(DOMAIN_DEPOSIT_BIND_V2);
  w.writeU8(msg.chainId);
  w.writeAddress(msg.bridge);
  w.writeAddress(msg.vault);
  w.writeAddress(msg.assetType);
  w.writeU64(BigInt(msg.operatorSetVersion));
  w.writeU64(BigInt(msg.dkgEpoch));
  w.writeHexVector(msg.rosterHash);
  w.writeHexVector(msg.frostGroupPubkey);
  w.writeHexVector(msg.commitment);
  w.writeHexVector(msg.amountTag);
  w.writeHexVector(msg.caPayloadHash);
  w.writeHexVector(msg.depositNonce);
  w.writeU64(BigInt(msg.expirySecs));
  w.writeHexVector(msg.circuitVersionsHash);
  return w.finish();
}

export function bcsEncodeCAPayloadForHashV2(
  payload: ConfidentialTransferRawPayloadV2,
): Uint8Array {
  const w = new Writer();
  w.writeAddress(payload.assetType);
  w.writeAddress(payload.to);
  w.writeHexVectorVector(payload.newBalanceP);
  w.writeHexVectorVector(payload.newBalanceR);
  w.writeHexVectorVector(payload.newBalanceREffAud);
  w.writeHexVectorVector(payload.amountP);
  w.writeHexVectorVector(payload.amountRSender);
  w.writeHexVectorVector(payload.amountRRecip);
  w.writeHexVectorVector(payload.amountREffAud);
  w.writeHexVectorVector(payload.ekVolunAuds);
  w.writeHexVectorVectorVector(payload.amountRVolunAuds);
  w.writeHexVector(payload.zkrpNewBalance);
  w.writeHexVector(payload.zkrpAmount);
  w.writeHexVectorVector(payload.sigmaProtoComm);
  w.writeHexVectorVector(payload.sigmaProtoResp);
  w.writeHexVector(payload.memo);
  return w.finish();
}

export function bcsEncodeAptosCaRegistrationSession(
  senderAddress: string,
  assetType: string,
): Uint8Array {
  const w = new Writer();
  w.writeAddress(senderAddress);
  w.writeAddress(assetType);
  return w.finish();
}

export function caPayloadHashRawV2(payload: ConfidentialTransferRawPayloadV2): string {
  return bytesToHex(keccak256(bcsEncodeCAPayloadForHashV2(payload)));
}

export function caPayloadHashFrV2(payload: ConfidentialTransferRawPayloadV2): string {
  return caPayloadHashRawToFrV2(caPayloadHashRawV2(payload));
}

export function caPayloadHashRawToFrV2(rawHash: string): string {
  const bytes = hexToBytes(rawHash);
  if (bytes.length !== 32) {
    throw new Error(`raw CA payload hash must be 32 bytes, got ${bytes.length}`);
  }
  const out = new Uint8Array(bytes);
  out[31] = 0;
  return bytesToHex(out);
}

export { Writer };

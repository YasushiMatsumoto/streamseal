import { describe, it, expect } from "vitest";
import {
  wrapDek,
  unwrapDek,
  encodeRsaOaepHeaderBody,
  decodeRsaOaepHeaderBody,
} from "../../src/algorithms/rsa-oaep.js";
import { InvalidHeaderError } from "../../src/errors.js";
import { generateDataKey, encryptChunk, decryptChunk, generateIv } from "../../src/crypto-utils.js";
import { buildAad } from "../../src/chunk.js";
import { generateRsaKeyPair } from "../helpers.js";

describe("algorithms/rsa-oaep", () => {
  it("wrapDek / unwrapDek round-trips the DEK", async () => {
    const keyPair = await generateRsaKeyPair();
    const dek = await generateDataKey();

    const wrapped = await wrapDek(dek, keyPair.publicKey);
    expect(wrapped.byteLength).toBeGreaterThan(0);

    // unwrapDek produces a non-extractable key (by design).
    // Verify equivalence: data encrypted with original DEK must decrypt with the unwrapped DEK.
    const unwrapped = await unwrapDek(wrapped, keyPair.privateKey);
    const iv = generateIv();
    const aad = buildAad(0);
    const plaintext = new TextEncoder().encode("rsa dek round-trip");
    const ciphertext = await encryptChunk(dek, iv, plaintext, aad);
    const decrypted = await decryptChunk(unwrapped, iv, ciphertext, aad);
    expect(decrypted).toEqual(plaintext);
  });

  it("unwrapDek throws with the wrong private key", async () => {
    const keyPair1 = await generateRsaKeyPair();
    const keyPair2 = await generateRsaKeyPair();
    const dek = await generateDataKey();

    const wrapped = await wrapDek(dek, keyPair1.publicKey);
    await expect(unwrapDek(wrapped, keyPair2.privateKey)).rejects.toThrow();
  });

  it("encodeRsaOaepHeaderBody / decodeRsaOaepHeaderBody round-trips", () => {
    const fakeWrapped = new Uint8Array(256).fill(0xab); // typical RSA-2048 size
    const body = encodeRsaOaepHeaderBody(fakeWrapped);
    const { wrappedDek } = decodeRsaOaepHeaderBody(body);
    expect(wrappedDek).toEqual(fakeWrapped);
  });

  it("decodeRsaOaepHeaderBody throws on truncated input", () => {
    expect(() => decodeRsaOaepHeaderBody(new Uint8Array(1))).toThrow(InvalidHeaderError);
  });
});

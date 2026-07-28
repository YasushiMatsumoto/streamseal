import { describe, it, expect } from "vitest";
import {
  deriveDekSender,
  deriveDekRecipient,
  encodeEcdhHeaderBody,
  decodeEcdhHeaderBody,
} from "../../src/algorithms/ecdh.js";
import { InvalidHeaderError } from "../../src/errors.js";
import { encryptChunk, decryptChunk, generateIv } from "../../src/crypto-utils.js";
import { buildAad } from "../../src/chunk.js";
import { generateEcdhKeyPair } from "../helpers.js";
import { HKDF_SALT_LENGTH } from "../../src/constants.js";

describe("algorithms/ecdh", () => {
  it("deriveDekSender / deriveDekRecipient produce the same DEK", async () => {
    const recipientKeyPair = await generateEcdhKeyPair();

    const {
      dek: senderDek,
      ephemeralPublicKeyRaw,
      salt,
    } = await deriveDekSender(recipientKeyPair.publicKey);

    const recipientDek = await deriveDekRecipient(
      ephemeralPublicKeyRaw,
      recipientKeyPair.privateKey,
      salt,
    );

    // Both DEKs are non-extractable (by design). Verify equivalence:
    // data encrypted with senderDek must decrypt correctly with recipientDek.
    const iv = generateIv();
    const aad = buildAad(0);
    const plaintext = new TextEncoder().encode("ecdh dek equivalence");
    const ciphertext = await encryptChunk(senderDek, iv, plaintext, aad);
    const decrypted = await decryptChunk(recipientDek, iv, ciphertext, aad);
    expect(decrypted).toEqual(plaintext);
  });

  it("ephemeral public key is 65 bytes (P-256 uncompressed)", async () => {
    const recipientKeyPair = await generateEcdhKeyPair();
    const { ephemeralPublicKeyRaw } = await deriveDekSender(recipientKeyPair.publicKey);
    expect(ephemeralPublicKeyRaw.byteLength).toBe(65);
  });

  it("salt is 32 bytes and random each call", async () => {
    const recipientKeyPair = await generateEcdhKeyPair();
    const { salt: salt1 } = await deriveDekSender(recipientKeyPair.publicKey);
    const { salt: salt2 } = await deriveDekSender(recipientKeyPair.publicKey);
    expect(salt1.byteLength).toBe(HKDF_SALT_LENGTH);
    expect(salt1).not.toEqual(salt2);
  });

  it("uses a fresh ephemeral key each time (different DEKs)", async () => {
    const recipientKeyPair = await generateEcdhKeyPair();

    const {
      dek: dek1,
      ephemeralPublicKeyRaw: eph1,
      salt: salt1,
    } = await deriveDekSender(recipientKeyPair.publicKey);
    const { dek: dek2, ephemeralPublicKeyRaw: eph2 } = await deriveDekSender(
      recipientKeyPair.publicKey,
    );

    // Ephemeral public keys must differ → different shared secrets → different DEKs.
    expect(eph1).not.toEqual(eph2);

    // Confirm DEKs are different: data encrypted with dek1 must *fail* when decrypted with dek2.
    const iv = generateIv();
    const aad = buildAad(0);
    const plaintext = new TextEncoder().encode("freshness check");
    const ciphertext = await encryptChunk(dek1, iv, plaintext, aad);
    // dek2 was derived with a different salt too, so decryption must fail
    const wrongDek = await deriveDekRecipient(eph1, recipientKeyPair.privateKey, salt1);
    await expect(decryptChunk(dek2, iv, ciphertext, aad)).rejects.toThrow();
    // Sanity: correct dek1 succeeds
    const correctDek = await deriveDekRecipient(eph1, recipientKeyPair.privateKey, salt1);
    await expect(decryptChunk(correctDek, iv, ciphertext, aad)).resolves.toEqual(plaintext);
    void wrongDek;
  });

  it("deriveDekRecipient with the wrong private key produces a different DEK", async () => {
    const recipientKeyPair1 = await generateEcdhKeyPair();
    const recipientKeyPair2 = await generateEcdhKeyPair();

    const {
      dek: senderDek,
      ephemeralPublicKeyRaw,
      salt,
    } = await deriveDekSender(recipientKeyPair1.publicKey);

    // Recipient 2 derives a different DEK (ECDH with wrong private key never throws,
    // but the resulting DEK will be different — confirmed by failed decryption).
    const wrongDek = await deriveDekRecipient(
      ephemeralPublicKeyRaw,
      recipientKeyPair2.privateKey,
      salt,
    );
    const iv = generateIv();
    const aad = buildAad(0);
    const plaintext = new TextEncoder().encode("wrong key check");
    const ciphertext = await encryptChunk(senderDek, iv, plaintext, aad);
    await expect(decryptChunk(wrongDek, iv, ciphertext, aad)).rejects.toThrow();
  });

  it("encodeEcdhHeaderBody / decodeEcdhHeaderBody round-trips", () => {
    const fakeEphPub = new Uint8Array(65).fill(0x04) as Uint8Array<ArrayBuffer>;
    const fakeSalt = new Uint8Array(HKDF_SALT_LENGTH).fill(0xab) as Uint8Array<ArrayBuffer>;
    const body = encodeEcdhHeaderBody(fakeEphPub, fakeSalt);
    const { ephemeralPublicKeyRaw, salt } = decodeEcdhHeaderBody(body);
    expect(ephemeralPublicKeyRaw).toEqual(fakeEphPub);
    expect(salt).toEqual(fakeSalt);
  });

  it("decodeEcdhHeaderBody throws on truncated input", () => {
    expect(() => decodeEcdhHeaderBody(new Uint8Array(1) as Uint8Array<ArrayBuffer>)).toThrow(
      InvalidHeaderError,
    );
  });
});

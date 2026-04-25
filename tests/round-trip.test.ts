import { describe, it, expect } from "vitest";
import { EncryptingStream } from "../src/EncryptingStream.js";
import { DecryptingStream } from "../src/DecryptingStream.js";
import { Algorithm } from "../src/constants.js";
import { generateRsaKeyPair, generateEcdhKeyPair, collectStream, toStream } from "./helpers.js";

async function roundTrip(
  plaintext: Uint8Array,
  publicKey: CryptoKey,
  privateKey: CryptoKey,
  algorithm: Algorithm,
  chunkSize?: number,
): Promise<Uint8Array> {
  const encStream = await EncryptingStream.create(publicKey, {
    algorithm,
    chunkSize,
  });
  const decStream = DecryptingStream.create(privateKey);
  return collectStream(toStream(plaintext).pipeThrough(encStream).pipeThrough(decStream));
}

describe("round-trip", () => {
  describe("RSA-OAEP", () => {
    it("encrypts and decrypts an empty payload", async () => {
      const { publicKey, privateKey } = await generateRsaKeyPair();
      const result = await roundTrip(new Uint8Array(0), publicKey, privateKey, Algorithm.RSA_OAEP);
      expect(result).toEqual(new Uint8Array(0));
    });

    it("encrypts and decrypts a small payload (< 1 chunk)", async () => {
      const { publicKey, privateKey } = await generateRsaKeyPair();
      const plaintext = new TextEncoder().encode("Hello, streamseal!");
      const result = await roundTrip(plaintext, publicKey, privateKey, Algorithm.RSA_OAEP);
      expect(result).toEqual(plaintext);
    });

    it("encrypts and decrypts a payload spanning multiple chunks", async () => {
      const { publicKey, privateKey } = await generateRsaKeyPair();
      const plaintext = crypto.getRandomValues(new Uint8Array(300));
      // Use a tiny chunk size to force multiple chunks
      const result = await roundTrip(plaintext, publicKey, privateKey, Algorithm.RSA_OAEP, 64);
      expect(result).toEqual(plaintext);
    });

    it("encrypts and decrypts exactly one full chunk", async () => {
      const { publicKey, privateKey } = await generateRsaKeyPair();
      const chunkSize = 128;
      const plaintext = crypto.getRandomValues(new Uint8Array(chunkSize));
      const result = await roundTrip(
        plaintext,
        publicKey,
        privateKey,
        Algorithm.RSA_OAEP,
        chunkSize,
      );
      expect(result).toEqual(plaintext);
    });
  });

  describe("ECDH", () => {
    it("encrypts and decrypts a small payload", async () => {
      const { publicKey, privateKey } = await generateEcdhKeyPair();
      const plaintext = new TextEncoder().encode("ECDH streamseal test");
      const result = await roundTrip(plaintext, publicKey, privateKey, Algorithm.ECDH);
      expect(result).toEqual(plaintext);
    });

    it("encrypts and decrypts a large payload across many chunks", async () => {
      const { publicKey, privateKey } = await generateEcdhKeyPair();
      const plaintext = crypto.getRandomValues(new Uint8Array(1024));
      const result = await roundTrip(plaintext, publicKey, privateKey, Algorithm.ECDH, 100);
      expect(result).toEqual(plaintext);
    });

    it("each encryption produces a different ciphertext (ephemeral key)", async () => {
      const { publicKey, privateKey: _privateKey } = await generateEcdhKeyPair();
      const plaintext = new TextEncoder().encode("same plaintext");

      const encStream1 = await EncryptingStream.create(publicKey, {
        algorithm: Algorithm.ECDH,
      });
      const encStream2 = await EncryptingStream.create(publicKey, {
        algorithm: Algorithm.ECDH,
      });

      const ct1 = await collectStream(toStream(plaintext).pipeThrough(encStream1));
      const ct2 = await collectStream(toStream(plaintext).pipeThrough(encStream2));

      // Ciphertexts must differ (ephemeral keys are fresh each time)
      expect(ct1).not.toEqual(ct2);
    });
  });

  describe("onProgress callback", () => {
    it("reports progress monotonically and ends at total plaintext bytes", async () => {
      const { publicKey, privateKey: _privateKey } = await generateRsaKeyPair();
      const plaintext = crypto.getRandomValues(new Uint8Array(500));
      const reported: number[] = [];

      const encStream = await EncryptingStream.create(publicKey, {
        algorithm: Algorithm.RSA_OAEP,
        chunkSize: 100,
        onProgress: (n) => reported.push(n),
      });

      await collectStream(toStream(plaintext).pipeThrough(encStream));

      expect(reported.length).toBeGreaterThan(0);
      // Monotonically increasing
      for (let i = 1; i < reported.length; i++) {
        expect(reported[i]).toBeGreaterThanOrEqual(reported[i - 1]);
      }
      // Final value equals total plaintext size
      expect(reported[reported.length - 1]).toBe(plaintext.byteLength);
    });
  });
});

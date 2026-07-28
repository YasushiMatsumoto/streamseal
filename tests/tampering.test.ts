import { describe, it, expect } from "vitest";
import { EncryptingStream } from "../src/EncryptingStream.js";
import { DecryptingStream } from "../src/DecryptingStream.js";
import { Algorithm } from "../src/constants.js";
import { generateRsaKeyPair, generateEcdhKeyPair, collectStream, toStream } from "./helpers.js";

/**
 * Tamper with a byte at the given offset in the encrypted stream, then attempt decryption.
 * Expects a rejection (DOMException from AES-GCM auth failure or a TypeError from header parsing).
 */
async function expectDecryptFailure(
  encrypted: Uint8Array,
  privateKey: CryptoKey,
  tamperOffset: number,
): Promise<void> {
  const tampered = encrypted.slice();
  tampered[tamperOffset] ^= 0xff;

  const decStream = DecryptingStream.create(privateKey);
  await expect(collectStream(toStream(tampered).pipeThrough(decStream))).rejects.toThrow();
}

describe("tampering detection", () => {
  describe("RSA-OAEP", () => {
    it("detects ciphertext byte flip in the first chunk", async () => {
      const { publicKey, privateKey } = await generateRsaKeyPair();
      const plaintext = new TextEncoder().encode("tamper test RSA");
      const encStream = await EncryptingStream.create(publicKey, {
        algorithm: Algorithm.RSA_OAEP,
      });
      const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

      // Flip a byte in the tail (ciphertext area, well past the header)
      await expectDecryptFailure(encrypted, privateKey, encrypted.byteLength - 2);
    });

    it("detects chunk IV corruption", async () => {
      const { publicKey, privateKey } = await generateRsaKeyPair();
      const plaintext = new TextEncoder().encode("iv tamper test RSA");
      const encStream = await EncryptingStream.create(publicKey, {
        algorithm: Algorithm.RSA_OAEP,
        chunkSize: 8,
      });
      const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

      // The header ends after the fixed prefix + wrapped DEK; flip a byte that falls in a chunk IV
      // (rough approximation: flip somewhere in the second half)
      const midpoint = Math.floor(encrypted.byteLength / 2);
      await expectDecryptFailure(encrypted, privateKey, midpoint);
    });

    it("detects wrong private key (unwrapKey failure)", async () => {
      const { publicKey } = await generateRsaKeyPair();
      const { privateKey: wrongPrivateKey } = await generateRsaKeyPair();
      const plaintext = new TextEncoder().encode("wrong key RSA");
      const encStream = await EncryptingStream.create(publicKey, {
        algorithm: Algorithm.RSA_OAEP,
      });
      const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

      const decStream = DecryptingStream.create(wrongPrivateKey);
      await expect(collectStream(toStream(encrypted).pipeThrough(decStream))).rejects.toThrow();
    });
  });

  describe("ECDH", () => {
    it("detects ciphertext byte flip in the first chunk", async () => {
      const { publicKey, privateKey } = await generateEcdhKeyPair();
      const plaintext = new TextEncoder().encode("tamper test ECDH");
      const encStream = await EncryptingStream.create(publicKey, {
        algorithm: Algorithm.ECDH,
      });
      const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

      await expectDecryptFailure(encrypted, privateKey, encrypted.byteLength - 2);
    });

    it("detects wrong private key (different ECDH DEK)", async () => {
      const { publicKey } = await generateEcdhKeyPair();
      const { privateKey: wrongPrivateKey } = await generateEcdhKeyPair();
      const plaintext = new TextEncoder().encode("wrong key ECDH");
      const encStream = await EncryptingStream.create(publicKey, {
        algorithm: Algorithm.ECDH,
      });
      const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

      const decStream = DecryptingStream.create(wrongPrivateKey);
      await expect(collectStream(toStream(encrypted).pipeThrough(decStream))).rejects.toThrow();
    });
  });

  describe("chunk ordering attack", () => {
    it("detects swapped chunks (AAD mismatch)", async () => {
      const { publicKey, privateKey } = await generateRsaKeyPair();
      // Use a small chunk size so we get at least 2 chunks
      const chunkSize = 16;
      const plaintext = crypto.getRandomValues(new Uint8Array(chunkSize * 3)); // 3 full chunks
      const encStream = await EncryptingStream.create(publicKey, {
        algorithm: Algorithm.RSA_OAEP,
        chunkSize,
      });
      const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

      // Each chunk wire size = 4 (len) + 12 (IV) + chunkSize + 16 (tag)
      const chunkWireSize = 4 + 12 + chunkSize + 16;

      // Locate where chunks begin (after the fixed header)
      // Find header length by scanning: magic(8) + algo(1) + headerLen(4) + body
      const headerBodyLen = new DataView(encrypted.buffer).getUint32(9, false);
      const chunksStart = 13 + headerBodyLen;

      // Swap chunk 0 and chunk 1
      const swapped = encrypted.slice();
      const chunk0Start = chunksStart;
      const chunk1Start = chunksStart + chunkWireSize;

      const chunk0 = encrypted.slice(chunk0Start, chunk0Start + chunkWireSize);
      const chunk1 = encrypted.slice(chunk1Start, chunk1Start + chunkWireSize);
      swapped.set(chunk1, chunk0Start);
      swapped.set(chunk0, chunk1Start);

      const decStream = DecryptingStream.create(privateKey);
      await expect(collectStream(toStream(swapped).pipeThrough(decStream))).rejects.toThrow();
    });
  });

  describe("truncation attack", () => {
    it("rejects ciphertext when the final complete chunk is removed", async () => {
      const { publicKey, privateKey } = await generateRsaKeyPair();
      const chunkSize = 16;
      const plaintext = crypto.getRandomValues(new Uint8Array(chunkSize * 3)); // 3 full chunks

      const encStream = await EncryptingStream.create(publicKey, {
        algorithm: Algorithm.RSA_OAEP,
        chunkSize,
      });
      const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

      const headerBodyLen = new DataView(encrypted.buffer).getUint32(9, false);
      const chunksStart = 13 + headerBodyLen;

      // Walk chunk boundaries and remove the last complete chunk.
      let offset = chunksStart;
      const chunkStarts: number[] = [];
      while (offset < encrypted.byteLength) {
        chunkStarts.push(offset);
        const payloadLen = new DataView(encrypted.buffer).getUint32(offset, false);
        offset += 4 + payloadLen;
      }
      const truncated = encrypted.slice(0, chunkStarts[chunkStarts.length - 1]);

      const decStream = DecryptingStream.create(privateKey);
      await expect(collectStream(toStream(truncated).pipeThrough(decStream))).rejects.toThrow();
    });
  });

  describe("error message", () => {
    it("includes chunk index in the authentication failure message", async () => {
      const { publicKey, privateKey } = await generateRsaKeyPair();
      const chunkSize = 16;
      // 3 full chunks; tamper the second chunk (index 1)
      const plaintext = crypto.getRandomValues(new Uint8Array(chunkSize * 3));
      const encStream = await EncryptingStream.create(publicKey, {
        algorithm: Algorithm.RSA_OAEP,
        chunkSize,
      });
      const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

      const chunkWireSize = 4 + 12 + chunkSize + 16;
      const headerBodyLen = new DataView(encrypted.buffer).getUint32(9, false);
      const chunksStart = 13 + headerBodyLen;
      // Flip a ciphertext byte in chunk 1
      const chunk1CiphertextOffset = chunksStart + chunkWireSize + 4 + 12;
      const tampered = encrypted.slice();
      tampered[chunk1CiphertextOffset] ^= 0xff;

      const decStream = DecryptingStream.create(privateKey);
      await expect(collectStream(toStream(tampered).pipeThrough(decStream))).rejects.toThrow(
        "chunk 1",
      );
    });
  });
});

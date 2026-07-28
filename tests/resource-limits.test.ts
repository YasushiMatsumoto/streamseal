import { describe, it, expect } from "vitest";
import { EncryptingStream } from "../src/EncryptingStream.js";
import { DecryptingStream } from "../src/DecryptingStream.js";
import { Algorithm } from "../src/constants.js";
import { collectStream, generateRsaKeyPair, toStream } from "./helpers.js";

describe("resource limits", () => {
  it("rejects when header exceeds maxHeaderSize", async () => {
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const plaintext = crypto.getRandomValues(new Uint8Array(64));
    const encStream = await EncryptingStream.create(publicKey, {
      algorithm: Algorithm.RSA_OAEP,
      chunkSize: 32,
    });
    const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

    const decStream = DecryptingStream.create(privateKey, { maxHeaderSize: 64 });
    await expect(collectStream(toStream(encrypted).pipeThrough(decStream))).rejects.toThrow(
      /maxHeaderSize/i,
    );
  });

  it("rejects when chunk payload exceeds maxChunkSize", async () => {
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const plaintext = crypto.getRandomValues(new Uint8Array(128));
    const encStream = await EncryptingStream.create(publicKey, {
      algorithm: Algorithm.RSA_OAEP,
      chunkSize: 64,
    });
    const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

    const decStream = DecryptingStream.create(privateKey, { maxChunkSize: 64 });
    await expect(collectStream(toStream(encrypted).pipeThrough(decStream))).rejects.toThrow(
      /maxChunkSize/i,
    );
  });

  it("rejects when total plaintext exceeds maxPlaintextSize", async () => {
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const plaintext = crypto.getRandomValues(new Uint8Array(128));
    const encStream = await EncryptingStream.create(publicKey, {
      algorithm: Algorithm.RSA_OAEP,
      chunkSize: 32,
    });
    const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

    const decStream = DecryptingStream.create(privateKey, { maxPlaintextSize: 64 });
    await expect(collectStream(toStream(encrypted).pipeThrough(decStream))).rejects.toThrow(
      /maxPlaintextSize/i,
    );
  });

  it("rejects when chunk count exceeds maxChunks", async () => {
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const plaintext = crypto.getRandomValues(new Uint8Array(96));
    const encStream = await EncryptingStream.create(publicKey, {
      algorithm: Algorithm.RSA_OAEP,
      chunkSize: 32,
    });
    const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

    // 96 bytes at 32-byte chunks => 3 data chunks + 1 terminal marker = 4 chunks.
    const decStream = DecryptingStream.create(privateKey, { maxChunks: 3 });
    await expect(collectStream(toStream(encrypted).pipeThrough(decStream))).rejects.toThrow(
      /maxChunks/i,
    );
  });
});

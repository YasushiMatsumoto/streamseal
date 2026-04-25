import { describe, it, expect } from "vitest";
import { createEncryptor, Algorithm } from "../src/client/index.js";
import { generateRsaKeyPair, generateEcdhKeyPair, toStream } from "./helpers.js";

/** Export a CryptoKey (SPKI) to PEM string — test-only helper. */
async function toSpkiPem(key: CryptoKey): Promise<string> {
  const buf = await crypto.subtle.exportKey("spki", key);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
  const lines = b64.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

async function rsaPublicKeyPem(): Promise<string> {
  const { publicKey } = await generateRsaKeyPair();
  return toSpkiPem(publicKey);
}

async function ecdhPublicKeyPem(): Promise<string> {
  const { publicKey } = await generateEcdhKeyPair();
  return toSpkiPem(publicKey);
}

/** Drain a ReadableStream, collecting all chunks until done or error. */
async function drain(stream: ReadableStream<Uint8Array>): Promise<Uint8Array[]> {
  const chunks: Uint8Array[] = [];
  const reader = stream.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return chunks;
}

describe("AbortSignal", () => {
  describe("already-aborted signal", () => {
    it("errors the stream immediately (RSA-OAEP)", async () => {
      const pem = await rsaPublicKeyPem();
      const controller = new AbortController();
      controller.abort(new DOMException("cancelled", "AbortError"));

      const encryptor = await createEncryptor(pem, { algorithm: Algorithm.RSA_OAEP });
      const plaintext = crypto.getRandomValues(new Uint8Array(1024));
      const stream = encryptor.encryptStream(toStream(plaintext), controller.signal);

      await expect(drain(stream)).rejects.toThrow("cancelled");
    });

    it("errors the stream immediately (ECDH)", async () => {
      const pem = await ecdhPublicKeyPem();
      const controller = new AbortController();
      controller.abort(new DOMException("cancelled", "AbortError"));

      const encryptor = await createEncryptor(pem, { algorithm: Algorithm.ECDH });
      const plaintext = crypto.getRandomValues(new Uint8Array(1024));
      const stream = encryptor.encryptStream(toStream(plaintext), controller.signal);

      await expect(drain(stream)).rejects.toThrow("cancelled");
    });
  });

  describe("abort during streaming", () => {
    it("errors the stream mid-flight (RSA-OAEP)", async () => {
      const pem = await rsaPublicKeyPem();
      const controller = new AbortController();

      const encryptor = await createEncryptor(pem, {
        algorithm: Algorithm.RSA_OAEP,
        chunkSize: 64,
      });

      // Large enough to produce many chunks
      const plaintext = crypto.getRandomValues(new Uint8Array(4096));
      const stream = encryptor.encryptStream(toStream(plaintext), controller.signal);
      const reader = stream.getReader();

      // Read the first chunk successfully, then abort
      const first = await reader.read();
      expect(first.done).toBe(false);

      controller.abort(new DOMException("user cancelled", "AbortError"));

      await expect(reader.read()).rejects.toThrow("user cancelled");
    });
  });

  describe("no signal — normal behaviour", () => {
    it("completes successfully when no signal is provided", async () => {
      const pem = await rsaPublicKeyPem();
      const encryptor = await createEncryptor(pem, {
        algorithm: Algorithm.RSA_OAEP,
        chunkSize: 64,
      });

      const plaintext = crypto.getRandomValues(new Uint8Array(256));
      const stream = encryptor.encryptStream(toStream(plaintext));

      const chunks = await drain(stream);
      expect(chunks.length).toBeGreaterThan(0);
    });
  });
});

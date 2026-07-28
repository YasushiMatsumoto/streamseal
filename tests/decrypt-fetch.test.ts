/**
 * Tests for createDecryptor (browser) and decryptFetch.
 *
 * decryptFetch calls fetch() internally, so we mock globalThis.fetch
 * to return a synthetic Response backed by an encrypted stream.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { createEncryptor, createDecryptor, decryptFetch, Algorithm } from "../src/client/index.js";
import { generateRsaKeyPair, generateEcdhKeyPair, collectStream } from "./helpers.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Export a CryptoKey (SPKI) to PEM — test-only. */
async function toSpkiPem(key: CryptoKey): Promise<string> {
  const buf = await crypto.subtle.exportKey("spki", key);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
}

/** Export a CryptoKey (PKCS8) to PEM — test-only. */
async function toPkcs8Pem(key: CryptoKey): Promise<string> {
  const buf = await crypto.subtle.exportKey("pkcs8", key);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
  return `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----`;
}

/** Build an encrypted ReadableStream from plaintext using createEncryptor. */
async function buildEncryptedStream(
  plaintext: Uint8Array,
  publicKeyPem: string,
  algorithm: Algorithm,
): Promise<ReadableStream<Uint8Array>> {
  const encryptor = await createEncryptor(publicKeyPem, { algorithm, chunkSize: 64 });
  return encryptor.encryptFile(new Blob([plaintext]));
}

// ---------------------------------------------------------------------------
// createDecryptor (client-side)
// ---------------------------------------------------------------------------

describe("createDecryptor (client)", () => {
  it("round-trips with RSA-OAEP", async () => {
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const pubPem = await toSpkiPem(publicKey);
    const privPem = await toPkcs8Pem(privateKey);

    const plaintext = crypto.getRandomValues(new Uint8Array(300));
    const encrypted = await buildEncryptedStream(plaintext, pubPem, Algorithm.RSA_OAEP);

    const decryptor = await createDecryptor(privPem, Algorithm.RSA_OAEP);
    const result = await collectStream(decryptor.decryptStream(encrypted));

    expect(result).toEqual(plaintext);
  });

  it("round-trips with ECDH", async () => {
    const { publicKey, privateKey } = await generateEcdhKeyPair();
    const pubPem = await toSpkiPem(publicKey);
    const privPem = await toPkcs8Pem(privateKey);

    const plaintext = crypto.getRandomValues(new Uint8Array(300));
    const encrypted = await buildEncryptedStream(plaintext, pubPem, Algorithm.ECDH);

    const decryptor = await createDecryptor(privPem, Algorithm.ECDH);
    const result = await collectStream(decryptor.decryptStream(encrypted));

    expect(result).toEqual(plaintext);
  });

  it("calls onProgress with cumulative decrypted bytes", async () => {
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const pubPem = await toSpkiPem(publicKey);
    const privPem = await toPkcs8Pem(privateKey);

    const plaintext = crypto.getRandomValues(new Uint8Array(256));
    const encrypted = await buildEncryptedStream(plaintext, pubPem, Algorithm.RSA_OAEP);

    const progress: number[] = [];
    const decryptor = await createDecryptor(privPem, Algorithm.RSA_OAEP);
    await collectStream(
      decryptor.decryptStream(encrypted, { onProgress: (n) => progress.push(n) }),
    );

    expect(progress.length).toBeGreaterThan(0);
    expect(progress[progress.length - 1]).toBe(plaintext.byteLength);
  });
});

// ---------------------------------------------------------------------------
// decryptFetch
// ---------------------------------------------------------------------------

describe("decryptFetch", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("fetches and decrypts a response (RSA-OAEP)", async () => {
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const pubPem = await toSpkiPem(publicKey);
    const privPem = await toPkcs8Pem(privateKey);

    const plaintext = crypto.getRandomValues(new Uint8Array(300));
    const encryptedStream = await buildEncryptedStream(plaintext, pubPem, Algorithm.RSA_OAEP);

    // Mock fetch to return the encrypted stream as the response body
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(encryptedStream, { status: 200 })),
    );

    const decryptedStream = await decryptFetch(
      "https://example.com/file.enc",
      privPem,
      Algorithm.RSA_OAEP,
    );
    const result = await collectStream(decryptedStream);

    expect(result).toEqual(plaintext);
  });

  it("fetches and decrypts a response (ECDH)", async () => {
    const { publicKey, privateKey } = await generateEcdhKeyPair();
    const pubPem = await toSpkiPem(publicKey);
    const privPem = await toPkcs8Pem(privateKey);

    const plaintext = crypto.getRandomValues(new Uint8Array(300));
    const encryptedStream = await buildEncryptedStream(plaintext, pubPem, Algorithm.ECDH);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(encryptedStream, { status: 200 })),
    );

    const decryptedStream = await decryptFetch(
      "https://example.com/file.enc",
      privPem,
      Algorithm.ECDH,
    );
    const result = await collectStream(decryptedStream);

    expect(result).toEqual(plaintext);
  });

  it("throws on non-OK response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(null, { status: 404, statusText: "Not Found" })),
    );

    const { privateKey } = await generateRsaKeyPair();
    const privPem = await toPkcs8Pem(privateKey);

    await expect(
      decryptFetch("https://example.com/missing", privPem, Algorithm.RSA_OAEP),
    ).rejects.toThrow("404");
  });

  it("forwards fetchInit to fetch", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 404 }));
    vi.stubGlobal("fetch", fetchMock);

    const { privateKey } = await generateRsaKeyPair();
    const privPem = await toPkcs8Pem(privateKey);

    await expect(
      decryptFetch(
        "https://example.com/file.enc",
        privPem,
        Algorithm.RSA_OAEP,
        {},
        { headers: { Authorization: "Bearer token" } },
      ),
    ).rejects.toThrow();

    expect(fetchMock).toHaveBeenCalledWith(
      "https://example.com/file.enc",
      expect.objectContaining({ headers: { Authorization: "Bearer token" } }),
    );
  });
});

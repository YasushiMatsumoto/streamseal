import { describe, it, expect } from "vitest";
import {
  generateDataKey,
  exportRawKey,
  importRawAesKey,
  generateIv,
  encryptChunk,
  decryptChunk,
  getKeyFingerprint,
} from "../src/crypto-utils.js";
import { buildAad } from "../src/chunk.js";

describe("crypto-utils", () => {
  it("generateDataKey returns an AES-GCM CryptoKey", async () => {
    const key = await generateDataKey();
    expect(key.type).toBe("secret");
    expect(key.algorithm.name).toBe("AES-GCM");
  });

  it("exportRawKey / importRawAesKey round-trips the key bytes", async () => {
    const key = await generateDataKey();
    const raw = await exportRawKey(key);
    expect(raw.byteLength).toBe(32); // 256-bit

    // importRawAesKey creates a non-extractable key (by design).
    // Verify equivalence by successfully decrypting something encrypted with the original key.
    const reimported = await importRawAesKey(raw);
    const iv = generateIv();
    const aad = buildAad(0);
    const plaintext = new TextEncoder().encode("key equivalence check");
    const ciphertext = await encryptChunk(key, iv, plaintext, aad);
    const decrypted = await decryptChunk(reimported, iv, ciphertext, aad);
    expect(decrypted).toEqual(plaintext);
  });

  it("generateIv returns a 12-byte random nonce", () => {
    const iv1 = generateIv();
    const iv2 = generateIv();
    expect(iv1.byteLength).toBe(12);
    // Astronomically unlikely to be equal
    expect(iv1).not.toEqual(iv2);
  });

  it("encryptChunk / decryptChunk round-trips plaintext", async () => {
    const key = await generateDataKey();
    const iv = generateIv();
    const aad = buildAad(0);
    const plaintext = new TextEncoder().encode("Hello, streamseal!");

    const ciphertext = await encryptChunk(key, iv, plaintext, aad);
    expect(ciphertext.byteLength).toBe(plaintext.byteLength + 16); // +16 GCM tag

    const decrypted = await decryptChunk(key, iv, ciphertext, aad);
    expect(decrypted).toEqual(plaintext);
  });

  it("decryptChunk throws when IV is wrong", async () => {
    const key = await generateDataKey();
    const iv = generateIv();
    const aad = buildAad(0);
    const ciphertext = await encryptChunk(key, iv, new TextEncoder().encode("test"), aad);

    const wrongIv = generateIv();
    await expect(decryptChunk(key, wrongIv, ciphertext, aad)).rejects.toThrow();
  });

  it("decryptChunk throws when AAD is wrong (tampered chunk index)", async () => {
    const key = await generateDataKey();
    const iv = generateIv();
    const aad0 = buildAad(0);
    const aad1 = buildAad(1);
    const ciphertext = await encryptChunk(key, iv, new TextEncoder().encode("test"), aad0);

    await expect(decryptChunk(key, iv, ciphertext, aad1)).rejects.toThrow();
  });

  it("decryptChunk throws when ciphertext is tampered", async () => {
    const key = await generateDataKey();
    const iv = generateIv();
    const aad = buildAad(0);
    const ciphertext = await encryptChunk(key, iv, new TextEncoder().encode("tamper me"), aad);

    const tampered = ciphertext.slice();
    tampered[0] ^= 0xff; // flip bits
    await expect(decryptChunk(key, iv, tampered, aad)).rejects.toThrow();
  });
});

describe("getKeyFingerprint", () => {
  /** Export CryptoKey (SPKI) to PEM — test-only helper. */
  async function toSpkiPem(key: CryptoKey): Promise<string> {
    const buf = await crypto.subtle.exportKey("spki", key);
    const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
    return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
  }

  it("returns a colon-separated SHA-256 hex string (64 hex chars = 32 bytes)", async () => {
    const { publicKey } = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["wrapKey", "unwrapKey"],
    );
    const pem = await toSpkiPem(publicKey);
    const fp = await getKeyFingerprint(pem);

    // Format: 32 bytes × "xx:" minus trailing colon → "xx:xx:...:xx" = 32*3 - 1 = 95 chars
    expect(fp).toMatch(/^[0-9a-f]{2}(:[0-9a-f]{2}){31}$/);
  });

  it("returns the same fingerprint for the same key PEM", async () => {
    const { publicKey } = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    );
    const pem = await toSpkiPem(publicKey);
    const fp1 = await getKeyFingerprint(pem);
    const fp2 = await getKeyFingerprint(pem);
    expect(fp1).toBe(fp2);
  });

  it("returns different fingerprints for different keys", async () => {
    const gen = () =>
      crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["wrapKey", "unwrapKey"],
      );
    const [kp1, kp2] = await Promise.all([gen(), gen()]);
    const fp1 = await getKeyFingerprint(await toSpkiPem(kp1.publicKey));
    const fp2 = await getKeyFingerprint(await toSpkiPem(kp2.publicKey));
    expect(fp1).not.toBe(fp2);
  });
});

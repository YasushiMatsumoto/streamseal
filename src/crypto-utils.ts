import { AES_KEY_LENGTH, GCM_IV_LENGTH, GCM_TAG_LENGTH } from "./constants.js";
import { cryptoImpl, subtle } from "./webcrypto.js";

export async function generateDataKey(): Promise<CryptoKey> {
  return subtle.generateKey({ name: "AES-GCM", length: AES_KEY_LENGTH }, true, [
    "encrypt",
    "decrypt",
  ]);
}

export async function exportRawKey(key: CryptoKey): Promise<Uint8Array<ArrayBuffer>> {
  const buf = await subtle.exportKey("raw", key);
  return new Uint8Array(buf);
}

export async function importRawAesKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return subtle.importKey("raw", raw, { name: "AES-GCM", length: AES_KEY_LENGTH }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export function generateIv(): Uint8Array<ArrayBuffer> {
  const iv = new Uint8Array(GCM_IV_LENGTH);
  cryptoImpl.getRandomValues(iv);
  return iv;
}

/**
 * Encrypt a chunk with AES-GCM.
 * @param key  AES-GCM CryptoKey
 * @param iv   12-byte nonce (must be unique per chunk)
 * @param plaintext  Data to encrypt
 * @param aad  Additional authenticated data (e.g. encoded chunk index)
 * @returns Ciphertext with 16-byte GCM auth tag appended (Web Crypto default)
 */
export async function encryptChunk(
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: GCM_TAG_LENGTH, additionalData: aad },
    key,
    plaintext,
  );
  return new Uint8Array(ciphertext);
}

/**
 * Decrypt a chunk with AES-GCM.
 * Throws DOMException on auth failure (tampered data / wrong key / wrong AAD).
 */
export async function decryptChunk(
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const plaintext = await subtle.decrypt(
    { name: "AES-GCM", iv, tagLength: GCM_TAG_LENGTH, additionalData: aad },
    key,
    ciphertext,
  );
  return new Uint8Array(plaintext);
}

/**
 * Compute the SHA-256 fingerprint of a PEM-encoded public key (SPKI format).
 * Returns a lowercase hex string with bytes separated by colons, e.g.:
 *   "a3:f1:7c:..."
 *
 * Useful for verifying that the correct key is being used before encryption.
 */
export async function getKeyFingerprint(publicKeyPem: string): Promise<string> {
  const body = publicKeyPem
    .replace(/-----BEGIN .+?-----/g, "")
    .replace(/-----END .+?-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(body);
  const spkiBytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) spkiBytes[i] = binary.charCodeAt(i);

  const hashBuf = await subtle.digest("SHA-256", spkiBytes);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(":");
}

/** Compute SHA-256 of arbitrary bytes. */
export async function sha256(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const hashBuf = await subtle.digest("SHA-256", data);
  return new Uint8Array(hashBuf);
}

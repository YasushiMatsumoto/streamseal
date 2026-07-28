import { RSA_HASH } from "../constants.js";
import { InvalidHeaderError } from "../errors.js";

const subtle = globalThis.crypto.subtle;

// ---------------------------------------------------------------------------
// PEM conversion helpers
// ---------------------------------------------------------------------------

function pemToBuffer(pem: string): ArrayBuffer {
  const body = pem
    .replace(/-----BEGIN .+?-----/g, "")
    .replace(/-----END .+?-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(body);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export async function importPublicKeyPem(pem: string): Promise<CryptoKey> {
  return subtle.importKey("spki", pemToBuffer(pem), { name: "RSA-OAEP", hash: RSA_HASH }, false, [
    "wrapKey",
  ]);
}

export async function importPrivateKeyPem(pem: string): Promise<CryptoKey> {
  return subtle.importKey("pkcs8", pemToBuffer(pem), { name: "RSA-OAEP", hash: RSA_HASH }, false, [
    "unwrapKey",
  ]);
}

// ---------------------------------------------------------------------------
// DEK wrap / unwrap
// ---------------------------------------------------------------------------

/**
 * Wrap (encrypt) a DEK with the recipient's RSA-OAEP public key.
 * Returns the wrapped DEK as a Uint8Array (same size as the RSA modulus).
 */
export async function wrapDek(
  dek: CryptoKey,
  recipientPublicKey: CryptoKey,
): Promise<Uint8Array<ArrayBuffer>> {
  const wrapped = await subtle.wrapKey("raw", dek, recipientPublicKey, {
    name: "RSA-OAEP",
  });
  return new Uint8Array(wrapped);
}

/**
 * Unwrap (decrypt) the wrapped DEK bytes using the recipient's RSA-OAEP private key.
 */
export async function unwrapDek(
  wrappedDek: Uint8Array<ArrayBuffer>,
  recipientPrivateKey: CryptoKey,
): Promise<CryptoKey> {
  return subtle.unwrapKey(
    "raw",
    wrappedDek,
    recipientPrivateKey,
    { name: "RSA-OAEP" },
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// ---------------------------------------------------------------------------
// Header body encoding for RSA-OAEP
// Header body: [wrapped_dek_len: 2B big-endian] [wrapped_dek: N B]
// ---------------------------------------------------------------------------

export function encodeRsaOaepHeaderBody(
  wrappedDek: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  const body = new Uint8Array(2 + wrappedDek.byteLength);
  new DataView(body.buffer).setUint16(0, wrappedDek.byteLength, false);
  body.set(wrappedDek, 2);
  return body;
}

export interface RsaOaepHeaderFields {
  wrappedDek: Uint8Array<ArrayBuffer>;
}

export function decodeRsaOaepHeaderBody(body: Uint8Array<ArrayBuffer>): RsaOaepHeaderFields {
  if (body.byteLength < 2) throw new InvalidHeaderError("RSA-OAEP header body too short");
  const wrappedDekLen = new DataView(body.buffer, body.byteOffset).getUint16(0, false);
  if (body.byteLength < 2 + wrappedDekLen) {
    throw new InvalidHeaderError("RSA-OAEP header body truncated");
  }
  const wrappedDek = body.slice(2, 2 + wrappedDekLen);
  return { wrappedDek };
}

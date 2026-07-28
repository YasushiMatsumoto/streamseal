import {
  AES_KEY_LENGTH,
  ECDH_CURVE,
  HKDF_HASH,
  HKDF_INFO,
  HKDF_SALT_LENGTH,
} from "../constants.js";
import { importRawAesKey } from "../crypto-utils.js";
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
  return subtle.importKey(
    "spki",
    pemToBuffer(pem),
    { name: "ECDH", namedCurve: ECDH_CURVE },
    false,
    [],
  );
}

export async function importPrivateKeyPem(pem: string): Promise<CryptoKey> {
  return subtle.importKey(
    "pkcs8",
    pemToBuffer(pem),
    { name: "ECDH", namedCurve: ECDH_CURVE },
    false,
    ["deriveBits"],
  );
}

// ---------------------------------------------------------------------------
// HKDF: shared secret → DEK
// ---------------------------------------------------------------------------

async function hkdfDeriveDek(
  sharedSecret: ArrayBuffer,
  salt: Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> {
  const hkdfKey = await subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
  const infoBytes = new TextEncoder().encode(HKDF_INFO);
  const keyBits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: HKDF_HASH,
      salt,
      info: infoBytes,
    },
    hkdfKey,
    AES_KEY_LENGTH,
  );
  return importRawAesKey(new Uint8Array(keyBits));
}

// ---------------------------------------------------------------------------
// ECIES-style DEK derivation (sender side)
// ---------------------------------------------------------------------------

export interface EcdhSenderResult {
  dek: CryptoKey;
  /** Ephemeral public key in raw (uncompressed) format — 65 bytes for P-256 */
  ephemeralPublicKeyRaw: Uint8Array<ArrayBuffer>;
  /** Random 32-byte HKDF salt included in the wire format header */
  salt: Uint8Array<ArrayBuffer>;
}

export async function deriveDekSender(recipientPublicKey: CryptoKey): Promise<EcdhSenderResult> {
  // Generate a fresh ephemeral ECDH key pair
  const ephemeralKeyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: ECDH_CURVE },
    true,
    ["deriveBits"],
  );

  // ECDH: ephemeral_private × recipient_public → shared secret
  const sharedSecretBits = await subtle.deriveBits(
    { name: "ECDH", public: recipientPublicKey },
    ephemeralKeyPair.privateKey,
    256, // P-256 produces 256-bit shared secret
  );

  // Random per-session salt (RFC 5869 recommended)
  const salt = globalThis.crypto.getRandomValues(
    new Uint8Array(HKDF_SALT_LENGTH),
  ) as Uint8Array<ArrayBuffer>;

  const dek = await hkdfDeriveDek(sharedSecretBits, salt);

  const rawPub = await subtle.exportKey("raw", ephemeralKeyPair.publicKey);
  return { dek, ephemeralPublicKeyRaw: new Uint8Array(rawPub), salt };
}

// ---------------------------------------------------------------------------
// ECIES-style DEK reconstruction (recipient side)
// ---------------------------------------------------------------------------

export async function deriveDekRecipient(
  ephemeralPublicKeyRaw: Uint8Array<ArrayBuffer>,
  recipientPrivateKey: CryptoKey,
  salt: Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> {
  const ephemeralPublicKey = await subtle.importKey(
    "raw",
    ephemeralPublicKeyRaw,
    { name: "ECDH", namedCurve: ECDH_CURVE },
    false,
    [],
  );

  const sharedSecretBits = await subtle.deriveBits(
    { name: "ECDH", public: ephemeralPublicKey },
    recipientPrivateKey,
    256,
  );

  return hkdfDeriveDek(sharedSecretBits, salt);
}

// ---------------------------------------------------------------------------
// Header body encoding for ECDH
// Header body: [ephemeral_pub_len: 2B big-endian] [ephemeral_pub: N B] [salt: 32B]
// ---------------------------------------------------------------------------

export function encodeEcdhHeaderBody(
  ephemeralPublicKeyRaw: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  const body = new Uint8Array(2 + ephemeralPublicKeyRaw.byteLength + salt.byteLength);
  new DataView(body.buffer).setUint16(0, ephemeralPublicKeyRaw.byteLength, false);
  body.set(ephemeralPublicKeyRaw, 2);
  body.set(salt, 2 + ephemeralPublicKeyRaw.byteLength);
  return body;
}

export interface EcdhHeaderFields {
  ephemeralPublicKeyRaw: Uint8Array<ArrayBuffer>;
  salt: Uint8Array<ArrayBuffer>;
}

export function decodeEcdhHeaderBody(body: Uint8Array<ArrayBuffer>): EcdhHeaderFields {
  if (body.byteLength < 2) throw new InvalidHeaderError("ECDH header body too short");
  const pubLen = new DataView(body.buffer, body.byteOffset).getUint16(0, false);
  if (body.byteLength < 2 + pubLen + HKDF_SALT_LENGTH)
    throw new InvalidHeaderError("ECDH header body truncated");
  const ephemeralPublicKeyRaw = body.slice(2, 2 + pubLen) as Uint8Array<ArrayBuffer>;
  const salt = body.slice(2 + pubLen, 2 + pubLen + HKDF_SALT_LENGTH) as Uint8Array<ArrayBuffer>;
  return { ephemeralPublicKeyRaw, salt };
}

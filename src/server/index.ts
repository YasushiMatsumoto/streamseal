/**
 * streamseal — server entry point (Node.js 18+)
 *
 * Uses the same DecryptingStream core as the browser build.
 * Web Crypto access is resolved at runtime for Node/browser compatibility.
 */
export { Algorithm } from "../constants.js";
export { DecryptingStream } from "../DecryptingStream.js";
export type { DecryptingStreamOptions } from "../DecryptingStream.js";
export {
  AuthenticationFailedError,
  InvalidChunkError,
  InvalidHeaderError,
  InvalidKeyError,
  ResourceLimitError,
  StreamSealError,
  TruncatedStreamError,
  UnsupportedAlgorithmError,
  UnsupportedVersionError,
} from "../errors.js";
export type { StreamSealErrorCode } from "../errors.js";

import { Algorithm } from "../constants.js";
import { DecryptingStream } from "../DecryptingStream.js";
import { importPrivateKeyPem as importRsaPrivateKeyPem } from "../algorithms/rsa-oaep.js";
import { importPrivateKeyPem as importEcdhPrivateKeyPem } from "../algorithms/ecdh.js";
import type { DecryptingStreamOptions } from "../DecryptingStream.js";

export interface CreateDecryptorOptions {
  keyResolver?: (keyId: string | undefined, algorithm: Algorithm) => Promise<CryptoKey> | CryptoKey;
}

export interface Decryptor {
  /**
   * Wrap a ReadableStream of encrypted bytes into a decrypted ReadableStream.
   * Pass a Node.js Readable by converting it first:
   *   ReadableStream.from(nodeReadable)
   */
  decryptStream(
    encrypted: ReadableStream<Uint8Array>,
    options?: DecryptingStreamOptions,
  ): ReadableStream<Uint8Array>;
}

/**
 * Create a decryptor from a PEM-encoded private key.
 * The provided algorithm must match the key type and encrypted stream.
 *
 * @param privateKeyPem  PKCS#8 PEM-encoded private key (RSA-OAEP or ECDH P-256)
 * @param algorithm      Must match the algorithm used during encryption
 */
export async function createDecryptor(
  privateKeyPem: string,
  algorithm: Algorithm,
  options: CreateDecryptorOptions = {},
): Promise<Decryptor> {
  let privateKey: CryptoKey;
  if (algorithm === Algorithm.RSA_OAEP) {
    privateKey = await importRsaPrivateKeyPem(privateKeyPem);
  } else {
    privateKey = await importEcdhPrivateKeyPem(privateKeyPem);
  }

  return {
    decryptStream(
      encrypted: ReadableStream<Uint8Array>,
      decryptOptions: DecryptingStreamOptions = {},
    ): ReadableStream<Uint8Array> {
      return encrypted.pipeThrough(
        DecryptingStream.create(privateKey, {
          ...decryptOptions,
          keyResolver: decryptOptions.keyResolver ?? options.keyResolver,
        }),
      );
    },
  };
}

// Re-export PEM importers
export const rsaOaep = { importPrivateKeyPem: importRsaPrivateKeyPem };
export const ecdh = { importPrivateKeyPem: importEcdhPrivateKeyPem };

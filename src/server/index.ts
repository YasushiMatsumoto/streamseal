/**
 * streamseal — server entry point (Node.js 18+)
 *
 * Uses the same DecryptingStream core as the browser build.
 * Node.js 18+ exposes globalThis.crypto.subtle and TransformStream globally,
 * so no polyfills are needed.
 */
export { Algorithm } from "../constants.js";
export { DecryptingStream } from "../DecryptingStream.js";
export type { DecryptingStreamOptions } from "../DecryptingStream.js";

import { Algorithm } from "../constants.js";
import { DecryptingStream } from "../DecryptingStream.js";
import { importPrivateKeyPem as importRsaPrivateKeyPem } from "../algorithms/rsa-oaep.js";
import { importPrivateKeyPem as importEcdhPrivateKeyPem } from "../algorithms/ecdh.js";
import type { DecryptingStreamOptions } from "../DecryptingStream.js";

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
 * The algorithm is detected automatically from the stream header.
 *
 * @param privateKeyPem  PKCS#8 PEM-encoded private key (RSA-OAEP or ECDH P-256)
 * @param algorithm      Must match the algorithm used during encryption
 */
export async function createDecryptor(
  privateKeyPem: string,
  algorithm: Algorithm,
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
      options: DecryptingStreamOptions = {},
    ): ReadableStream<Uint8Array> {
      return encrypted.pipeThrough(DecryptingStream.create(privateKey, options));
    },
  };
}

// Re-export PEM importers
export const rsaOaep = { importPrivateKeyPem: importRsaPrivateKeyPem };
export const ecdh = { importPrivateKeyPem: importEcdhPrivateKeyPem };

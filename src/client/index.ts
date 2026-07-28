export { Algorithm } from "../constants.js";
export type { Algorithm as AlgorithmType } from "../constants.js";
export { EncryptingStream } from "../EncryptingStream.js";
export type { EncryptingStreamOptions } from "../EncryptingStream.js";
export { DecryptingStream } from "../DecryptingStream.js";
export type { DecryptingStreamOptions } from "../DecryptingStream.js";
export { getKeyFingerprint } from "../crypto-utils.js";
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
import { EncryptingStream } from "../EncryptingStream.js";
import { DecryptingStream } from "../DecryptingStream.js";
import type { DecryptingStreamOptions } from "../DecryptingStream.js";
import {
  importPublicKeyPem as importRsaPublicKeyPem,
  importPrivateKeyPem as importRsaPrivateKeyPem,
} from "../algorithms/rsa-oaep.js";
import {
  importPublicKeyPem as importEcdhPublicKeyPem,
  importPrivateKeyPem as importEcdhPrivateKeyPem,
} from "../algorithms/ecdh.js";

export type { AlgorithmByteValue } from "../constants.js";

export interface CreateEncryptorOptions {
  algorithm: Algorithm;
  chunkSize?: number;
  onProgress?: (encryptedBytes: number) => void;
  keyId?: string;
}

export interface Encryptor {
  encryptStream(
    readable: ReadableStream<Uint8Array>,
    signal?: AbortSignal,
  ): ReadableStream<Uint8Array>;
  encryptFile(file: File | Blob, signal?: AbortSignal): ReadableStream<Uint8Array>;
}

/**
 * Create an encryptor from a PEM-encoded public key.
 *
 * @param publicKeyPem  PEM-encoded public key (SPKI format)
 * @param options       Algorithm and optional chunk size / progress callback
 */
export async function createEncryptor(
  publicKeyPem: string,
  options: CreateEncryptorOptions,
): Promise<Encryptor> {
  const { algorithm } = options;

  let publicKey: CryptoKey;
  if (algorithm === Algorithm.RSA_OAEP) {
    publicKey = await importRsaPublicKeyPem(publicKeyPem);
  } else {
    publicKey = await importEcdhPublicKeyPem(publicKeyPem);
  }

  const encryptor: Encryptor = {
    encryptStream(
      readable: ReadableStream<Uint8Array>,
      signal?: AbortSignal,
    ): ReadableStream<Uint8Array> {
      // Use a pull-based ReadableStream so Chrome's fetch can use it as a streaming body.
      // start() only performs async key-material init (fast); data is produced lazily in pull().
      // pipeThrough() sets up backpressure: at most one 65 KiB chunk is buffered at a time.
      let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
      let aborted = false;
      return new ReadableStream<Uint8Array>({
        async start(controller) {
          if (signal?.aborted) {
            controller.error(signal.reason);
            return;
          }
          const stream = await EncryptingStream.create(publicKey, options);
          reader = readable.pipeThrough(stream).getReader();
          signal?.addEventListener(
            "abort",
            () => {
              aborted = true;
              reader?.cancel(signal!.reason).catch(() => {});
              controller.error(signal!.reason);
            },
            { once: true },
          );
        },
        async pull(controller) {
          const { done, value } = await reader!.read();
          if (aborted) return; // controller already errored by the abort handler
          if (done) controller.close();
          else controller.enqueue(value);
        },
        async cancel(reason) {
          await reader?.cancel(reason);
        },
      });
    },

    encryptFile(file: File | Blob, signal?: AbortSignal): ReadableStream<Uint8Array> {
      return encryptor.encryptStream(file.stream() as ReadableStream<Uint8Array>, signal);
    },
  };
  return encryptor;
}

/**
 * Convenience wrapper: encrypt a File/Blob and POST it to a URL.
 * Requires fetch with `duplex: 'half'` support (Chrome 105+, Safari 16.4+, Edge 105+).
 *
 * @param url          Upload endpoint
 * @param file         Source file or blob
 * @param publicKeyPem PEM-encoded recipient public key
 * @param options      Algorithm and optional settings
 * @param fetchInit    Additional RequestInit (merged with body/method/headers)
 */
export async function encryptFetch(
  url: string,
  file: File | Blob,
  publicKeyPem: string,
  options: CreateEncryptorOptions,
  fetchInit: RequestInit = {},
): Promise<Response> {
  const encryptor = await createEncryptor(publicKeyPem, options);
  // Pass the fetch signal to the stream so both abort together
  const encryptedStream = encryptor.encryptFile(file, fetchInit.signal ?? undefined);

  return fetch(url, {
    ...fetchInit,
    method: fetchInit.method ?? "POST",
    body: encryptedStream,
    headers: {
      "Content-Type": "application/octet-stream",
      ...fetchInit.headers,
    },
    duplex: "half",
  });
}

// Re-export PEM importers for advanced use (e.g. key rotation)
export const rsaOaep = {
  importPublicKeyPem: importRsaPublicKeyPem,
  importPrivateKeyPem: importRsaPrivateKeyPem,
};

export const ecdh = {
  importPublicKeyPem: importEcdhPublicKeyPem,
  importPrivateKeyPem: importEcdhPrivateKeyPem,
};

// ---------------------------------------------------------------------------
// Decryptor
// ---------------------------------------------------------------------------

export interface Decryptor {
  decryptStream(
    encrypted: ReadableStream<Uint8Array>,
    options?: DecryptingStreamOptions,
  ): ReadableStream<Uint8Array>;
}

/**
 * Create a decryptor from a PEM-encoded private key (browser or Node.js 18+).
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

/**
 * Convenience wrapper: fetch a URL and decrypt the response body as a stream.
 *
 * @param url            Resource URL returning an encrypted stream
 * @param privateKeyPem  PKCS#8 PEM-encoded private key
 * @param algorithm      Algorithm used during encryption
 * @param options        Optional progress callback
 * @param fetchInit      Additional RequestInit passed to fetch
 * @returns              ReadableStream of decrypted plaintext bytes
 */
export async function decryptFetch(
  url: string,
  privateKeyPem: string,
  algorithm: Algorithm,
  options: DecryptingStreamOptions = {},
  fetchInit: RequestInit = {},
): Promise<ReadableStream<Uint8Array>> {
  const response = await fetch(url, fetchInit);
  if (!response.ok) {
    throw new Error(
      `decryptFetch: server responded with ${response.status} ${response.statusText}`,
    );
  }
  if (!response.body) {
    throw new Error("decryptFetch: response body is null");
  }

  const decryptor = await createDecryptor(privateKeyPem, algorithm);
  return decryptor.decryptStream(response.body as ReadableStream<Uint8Array>, options);
}

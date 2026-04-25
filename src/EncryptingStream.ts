import { Algorithm, DEFAULT_CHUNK_SIZE } from "./constants.js";
import { encryptChunk, generateDataKey, generateIv } from "./crypto-utils.js";
import { buildAad, encodeChunk } from "./chunk.js";
import { encodeHeader } from "./header.js";
import { encodeRsaOaepHeaderBody, wrapDek } from "./algorithms/rsa-oaep.js";
import { deriveDekSender, encodeEcdhHeaderBody } from "./algorithms/ecdh.js";

export interface EncryptingStreamOptions {
  algorithm: Algorithm;
  chunkSize?: number;
  onProgress?: (encryptedBytes: number) => void;
}

/**
 * TransformStream that encrypts a byte stream using AES-GCM with envelope encryption.
 *
 * Usage:
 *   const stream = new EncryptingStream(publicKey, { algorithm: Algorithm.RSA_OAEP });
 *   await stream.init();
 *   plaintextReadable.pipeThrough(stream);
 */
export class EncryptingStream implements TransformStream<Uint8Array, Uint8Array> {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;

  private constructor(readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>) {
    this.readable = readable;
    this.writable = writable;
  }

  /**
   * Construct and initialise an EncryptingStream.
   * Must be awaited before use — key generation and header writing happen here.
   */
  static async create(
    recipientPublicKey: CryptoKey,
    options: EncryptingStreamOptions,
  ): Promise<EncryptingStream> {
    const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE;
    const { algorithm, onProgress } = options;

    // --- Key material ---
    let dek: CryptoKey;
    let headerBody: Uint8Array<ArrayBuffer>;

    if (algorithm === Algorithm.RSA_OAEP) {
      dek = await generateDataKey();
      const wrappedDek = await wrapDek(dek, recipientPublicKey);
      headerBody = encodeRsaOaepHeaderBody(wrappedDek);
    } else {
      // ECDH
      const result = await deriveDekSender(recipientPublicKey);
      dek = result.dek;
      headerBody = encodeEcdhHeaderBody(result.ephemeralPublicKeyRaw, result.salt);
    }

    const { bytes: headerBytes } = encodeHeader(algorithm, headerBody);

    // --- Build TransformStream ---
    let chunkIndex = 0;
    // Queue of incoming pieces — avoids re-merging the accumulation buffer on every
    // transform call. Each piece is a subarray view (no copy) or the original chunk.
    const queue: Uint8Array<ArrayBuffer>[] = [];
    let queueBytes = 0;
    let totalEncrypted = 0;
    const capturedDek = dek;

    /** Drain exactly `size` bytes from the queue into a single new allocation. */
    function drainExact(size: number): Uint8Array<ArrayBuffer> {
      const out = new Uint8Array(size);
      let filled = 0;
      while (filled < size) {
        const piece = queue[0];
        const needed = size - filled;
        if (piece.byteLength <= needed) {
          out.set(piece, filled);
          filled += piece.byteLength;
          queue.shift();
        } else {
          out.set(piece.subarray(0, needed), filled);
          // Replace head with a view — no copy of the remaining bytes
          queue[0] = piece.subarray(needed) as Uint8Array<ArrayBuffer>;
          filled = size;
        }
      }
      queueBytes -= size;
      return out;
    }

    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>({
      start(controller) {
        // Push the header as the very first bytes
        controller.enqueue(headerBytes);
      },

      async transform(chunk, controller) {
        queue.push(chunk as Uint8Array<ArrayBuffer>);
        queueBytes += chunk.byteLength;

        // Flush complete chunks — one allocation per encrypted chunk
        while (queueBytes >= chunkSize) {
          const plaintext = drainExact(chunkSize);

          const iv = generateIv();
          const aad = buildAad(chunkIndex++);
          const ciphertext = await encryptChunk(capturedDek, iv, plaintext, aad);
          controller.enqueue(encodeChunk(iv, ciphertext));

          totalEncrypted += plaintext.byteLength;
          onProgress?.(totalEncrypted);
        }
      },

      async flush(controller) {
        // Encrypt any remaining bytes as the final (possibly partial) chunk
        if (queueBytes > 0) {
          const plaintext = drainExact(queueBytes);

          const iv = generateIv();
          const aad = buildAad(chunkIndex++);
          const ciphertext = await encryptChunk(capturedDek, iv, plaintext, aad);
          controller.enqueue(encodeChunk(iv, ciphertext));

          totalEncrypted += plaintext.byteLength;
          onProgress?.(totalEncrypted);
        }
      },
    });

    return new EncryptingStream(readable, writable);
  }
}

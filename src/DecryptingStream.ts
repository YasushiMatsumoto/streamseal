import { Algorithm, CHUNK_LEN_FIELD, GCM_IV_LENGTH } from "./constants.js";
import { decryptChunk } from "./crypto-utils.js";
import { buildAad } from "./chunk.js";
import { decodeHeader } from "./header.js";
import { decodeRsaOaepHeaderBody, unwrapDek } from "./algorithms/rsa-oaep.js";
import { decodeEcdhHeaderBody, deriveDekRecipient } from "./algorithms/ecdh.js";

export interface DecryptingStreamOptions {
  onProgress?: (decryptedBytes: number) => void;
}

/**
 * TransformStream that decrypts streams produced by EncryptingStream.
 * Accepts the recipient's private key (RSA-OAEP or ECDH depending on the stream header).
 *
 * Compatible with both browser (Web Crypto) and Node.js 18+ (globalThis.crypto).
 */
export class DecryptingStream implements TransformStream<Uint8Array, Uint8Array> {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;

  private constructor(readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>) {
    this.readable = readable;
    this.writable = writable;
  }

  static create(
    recipientPrivateKey: CryptoKey,
    options: DecryptingStreamOptions = {},
  ): DecryptingStream {
    const { onProgress } = options;

    // Queue of received pieces — avoids re-merging on every transform call.
    const queue: Uint8Array<ArrayBuffer>[] = [];
    let queueBytes = 0;
    let dek: CryptoKey | null = null;
    let chunkIndex = 0;
    let totalDecrypted = 0;

    /** Consume `size` bytes from the front of the queue into a single allocation. */
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
          queue[0] = piece.subarray(needed) as Uint8Array<ArrayBuffer>;
          filled = size;
        }
      }
      queueBytes -= size;
      return out;
    }

    /** Peek at the first `size` bytes as a contiguous view (copies only if queue is fragmented). */
    function peekBytes(size: number): Uint8Array<ArrayBuffer> {
      if (queue.length > 0 && queue[0].byteLength >= size) {
        return queue[0].subarray(0, size) as Uint8Array<ArrayBuffer>;
      }
      // Fragmented: must materialise
      const out = new Uint8Array(size);
      let filled = 0;
      let qi = 0;
      let offset = 0;
      while (filled < size) {
        const piece = queue[qi];
        const avail = piece.byteLength - offset;
        const take = Math.min(avail, size - filled);
        out.set(piece.subarray(offset, offset + take), filled);
        filled += take;
        offset += take;
        if (offset >= piece.byteLength) {
          qi++;
          offset = 0;
        }
      }
      return out;
    }

    /** Materialise all queued bytes into one contiguous buffer (used once for header parsing). */
    function materializeAll(): Uint8Array<ArrayBuffer> {
      if (queue.length === 0) return new Uint8Array(0);
      if (queue.length === 1) return queue[0];
      const out = new Uint8Array(queueBytes);
      let offset = 0;
      for (const piece of queue) {
        out.set(piece, offset);
        offset += piece.byteLength;
      }
      return out;
    }

    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>({
      async transform(chunk, controller) {
        queue.push(chunk as Uint8Array<ArrayBuffer>);
        queueBytes += chunk.byteLength;

        // 1. Parse header on first call (may span multiple incoming chunks)
        if (dek === null) {
          // Materialise everything available and attempt to parse — happens at most once
          const attempt = materializeAll();
          const decoded = decodeHeader(attempt);
          if (decoded === null) return; // need more data

          const { algorithm, body, totalLength } = decoded;
          // Reset queue to hold only the post-header remainder (view, no extra copy)
          const remainder = attempt.subarray(totalLength) as Uint8Array<ArrayBuffer>;
          queue.length = 0;
          queueBytes = 0;
          if (remainder.byteLength > 0) {
            queue.push(remainder);
            queueBytes = remainder.byteLength;
          }

          if (algorithm === Algorithm.RSA_OAEP) {
            const { wrappedDek } = decodeRsaOaepHeaderBody(body);
            dek = await unwrapDek(wrappedDek, recipientPrivateKey);
          } else {
            // ECDH
            const { ephemeralPublicKeyRaw, salt } = decodeEcdhHeaderBody(body);
            dek = await deriveDekRecipient(ephemeralPublicKeyRaw, recipientPrivateKey, salt);
          }
        }

        // 2. Drain complete encrypted chunks — one allocation per chunk
        while (queueBytes >= CHUNK_LEN_FIELD) {
          // Peek at the 4-byte length prefix without consuming it
          const lenView = peekBytes(CHUNK_LEN_FIELD);
          const payloadLen = new DataView(
            lenView.buffer,
            lenView.byteOffset,
            CHUNK_LEN_FIELD,
          ).getUint32(0, false /* big-endian */);
          const totalChunkLength = CHUNK_LEN_FIELD + payloadLen;
          if (queueBytes < totalChunkLength) break; // wait for more data

          const chunkData = drainExact(totalChunkLength);
          const iv = chunkData.subarray(
            CHUNK_LEN_FIELD,
            CHUNK_LEN_FIELD + GCM_IV_LENGTH,
          ) as Uint8Array<ArrayBuffer>;
          const ciphertext = chunkData.subarray(
            CHUNK_LEN_FIELD + GCM_IV_LENGTH,
          ) as Uint8Array<ArrayBuffer>;

          const aad = buildAad(chunkIndex);
          let plaintext: Uint8Array<ArrayBuffer>;
          try {
            plaintext = await decryptChunk(dek!, iv, ciphertext, aad);
          } catch (err) {
            throw new TypeError(
              `DecryptingStream: authentication failed at chunk ${chunkIndex} — data may be tampered or corrupt`,
              { cause: err },
            );
          }
          chunkIndex++;
          controller.enqueue(plaintext);

          totalDecrypted += plaintext.byteLength;
          onProgress?.(totalDecrypted);
        }
      },

      flush() {
        if (queueBytes > 0) {
          throw new TypeError(
            `DecryptingStream: ${queueBytes} trailing bytes remain after stream ended — possibly truncated or corrupt data`,
          );
        }
      },
    });

    return new DecryptingStream(readable, writable);
  }
}

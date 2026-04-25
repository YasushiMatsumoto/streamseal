import { CHUNK_LEN_FIELD, GCM_IV_LENGTH } from "./constants.js";

/**
 * Build the AAD (Additional Authenticated Data) for a chunk.
 * Encoding the chunk index prevents chunk reordering attacks.
 */
export function buildAad(chunkIndex: number): Uint8Array<ArrayBuffer> {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, chunkIndex, false /* big-endian */);
  return buf;
}

/**
 * Encode a single encrypted chunk into wire format:
 *   [payload_len: 4B big-endian] [iv: 12B] [ciphertext: variable]
 *
 * payload_len = GCM_IV_LENGTH + ciphertext.byteLength
 */
export function encodeChunk(
  iv: Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  const payloadLen = GCM_IV_LENGTH + ciphertext.byteLength;
  const out = new Uint8Array(CHUNK_LEN_FIELD + payloadLen);
  const view = new DataView(out.buffer);
  view.setUint32(0, payloadLen, false /* big-endian */);
  out.set(iv, CHUNK_LEN_FIELD);
  out.set(ciphertext, CHUNK_LEN_FIELD + GCM_IV_LENGTH);
  return out;
}

export interface DecodedChunk {
  iv: Uint8Array<ArrayBuffer>;
  ciphertext: Uint8Array<ArrayBuffer>;
  /** Total bytes consumed from the input buffer (including the 4-byte length field) */
  totalLength: number;
}

/**
 * Attempt to decode one chunk from a byte buffer.
 * Returns null if the buffer does not yet contain a complete chunk (need more data).
 */
export function decodeChunk(buf: Uint8Array<ArrayBuffer>): DecodedChunk | null {
  if (buf.byteLength < CHUNK_LEN_FIELD) return null;

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const payloadLen = view.getUint32(0, false /* big-endian */);

  if (payloadLen < GCM_IV_LENGTH) {
    throw new RangeError(
      `Invalid chunk: payload_len ${payloadLen} < GCM_IV_LENGTH ${GCM_IV_LENGTH}`,
    );
  }

  const totalLength = CHUNK_LEN_FIELD + payloadLen;
  if (buf.byteLength < totalLength) return null; // incomplete, wait for more

  const iv = buf.slice(CHUNK_LEN_FIELD, CHUNK_LEN_FIELD + GCM_IV_LENGTH);
  const ciphertext = buf.slice(CHUNK_LEN_FIELD + GCM_IV_LENGTH, totalLength);

  return { iv, ciphertext, totalLength };
}

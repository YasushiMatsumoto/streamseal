import {
  Algorithm,
  AlgorithmByte,
  ByteToAlgorithm,
  FIXED_PREFIX_LENGTH,
  HEADER_OFFSET_ALGORITHM,
  HEADER_OFFSET_HEADER_BODY,
  HEADER_OFFSET_HEADER_LEN,
  HEADER_OFFSET_MAGIC,
  MAGIC,
  MAGIC_LENGTH,
} from "./constants.js";
import type { AlgorithmByteValue } from "./constants.js";

function isAlgorithmByteValue(byte: number): byte is AlgorithmByteValue {
  return byte in ByteToAlgorithm;
}

export interface EncodedHeader {
  /** Full serialised header bytes (magic + algo byte + header_len + header body) */
  bytes: Uint8Array<ArrayBuffer>;
}

export interface DecodedHeader {
  algorithm: Algorithm;
  /** Raw algorithm-specific header body (key material) */
  body: Uint8Array<ArrayBuffer>;
  /** Total bytes consumed from the input buffer */
  totalLength: number;
}

/**
 * Serialise the fixed prefix + variable header body into wire format:
 *   [MAGIC: 8B] [algorithm: 1B] [header_len: 4B big-endian] [body: N B]
 */
export function encodeHeader(algorithm: Algorithm, body: Uint8Array<ArrayBuffer>): EncodedHeader {
  const totalLen = FIXED_PREFIX_LENGTH + body.byteLength;
  const bytes = new Uint8Array(totalLen);
  bytes.set(MAGIC, HEADER_OFFSET_MAGIC);
  bytes[HEADER_OFFSET_ALGORITHM] = AlgorithmByte[algorithm];
  new DataView(bytes.buffer).setUint32(HEADER_OFFSET_HEADER_LEN, body.byteLength, false);
  bytes.set(body, HEADER_OFFSET_HEADER_BODY);
  return { bytes };
}

/**
 * Parse the wire-format header from a buffer.
 * Returns null when the buffer does not yet contain a complete header.
 * Throws on magic mismatch or unknown algorithm byte.
 */
export function decodeHeader(buf: Uint8Array<ArrayBuffer>): DecodedHeader | null {
  if (buf.byteLength < FIXED_PREFIX_LENGTH) return null;

  // Validate magic
  for (let i = 0; i < MAGIC_LENGTH; i++) {
    if (buf[HEADER_OFFSET_MAGIC + i] !== MAGIC[i]) {
      throw new TypeError(`Invalid magic bytes at offset ${i}`);
    }
  }

  const algoByte = buf[HEADER_OFFSET_ALGORITHM];
  if (!isAlgorithmByteValue(algoByte)) {
    throw new TypeError(`Unknown algorithm byte: 0x${algoByte.toString(16).padStart(2, "0")}`);
  }
  const algorithm = ByteToAlgorithm[algoByte];

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const headerBodyLen = view.getUint32(HEADER_OFFSET_HEADER_LEN, false);

  const totalLength = FIXED_PREFIX_LENGTH + headerBodyLen;
  if (buf.byteLength < totalLength) return null; // incomplete

  const body = buf.slice(HEADER_OFFSET_HEADER_BODY, totalLength);
  return { algorithm, body, totalLength };
}

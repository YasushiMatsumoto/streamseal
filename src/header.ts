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
import {
  InvalidHeaderError,
  UnsupportedAlgorithmError,
  UnsupportedVersionError,
} from "./errors.js";
import type { AlgorithmByteValue } from "./constants.js";
function isAlgorithmByteValue(byte: number): byte is AlgorithmByteValue {
  return byte in ByteToAlgorithm;
}

export interface EncodedHeader {
  /** Full serialised header bytes (magic + algo byte + header_len + header body) */
  bytes: Uint8Array<ArrayBuffer>;
}

export interface HeaderEncodingOptions {
  keyId?: string;
}

export interface DecodedHeader {
  algorithm: Algorithm;
  /** Raw algorithm-specific header body (key material) */
  body: Uint8Array<ArrayBuffer>;
  /** Optional key identifier embedded in the header envelope */
  keyId?: string;
  /** Total bytes consumed from the input buffer */
  totalLength: number;
}

const KEY_ID_ENVELOPE_MARKER = new Uint8Array([0x4b, 0x49, 0x44, 0x01]);

function encodeHeaderBodyWithKeyId(
  body: Uint8Array<ArrayBuffer>,
  options: HeaderEncodingOptions = {},
): Uint8Array<ArrayBuffer> {
  if (!options.keyId) return body;

  const keyIdBytes = new TextEncoder().encode(options.keyId);
  const out = new Uint8Array(
    KEY_ID_ENVELOPE_MARKER.byteLength + 2 + keyIdBytes.byteLength + body.byteLength,
  );
  out.set(KEY_ID_ENVELOPE_MARKER, 0);
  new DataView(out.buffer).setUint16(
    KEY_ID_ENVELOPE_MARKER.byteLength,
    keyIdBytes.byteLength,
    false,
  );
  out.set(keyIdBytes, KEY_ID_ENVELOPE_MARKER.byteLength + 2);
  out.set(body, KEY_ID_ENVELOPE_MARKER.byteLength + 2 + keyIdBytes.byteLength);
  return out;
}

function decodeHeaderBodyWithKeyId(body: Uint8Array<ArrayBuffer>): {
  keyId?: string;
  body: Uint8Array<ArrayBuffer>;
} {
  if (
    body.byteLength < KEY_ID_ENVELOPE_MARKER.byteLength + 2 ||
    !body
      .subarray(0, KEY_ID_ENVELOPE_MARKER.byteLength)
      .every((value, index) => value === KEY_ID_ENVELOPE_MARKER[index])
  ) {
    return { body };
  }

  const keyIdLen = new DataView(body.buffer, body.byteOffset, body.byteLength).getUint16(
    KEY_ID_ENVELOPE_MARKER.byteLength,
    false,
  );
  const headerOffset = KEY_ID_ENVELOPE_MARKER.byteLength + 2;
  if (body.byteLength < headerOffset + keyIdLen) {
    return { body };
  }

  const keyIdBytes = body.slice(headerOffset, headerOffset + keyIdLen);
  const encodedBody = body.slice(headerOffset + keyIdLen);
  return {
    keyId: new TextDecoder().decode(keyIdBytes),
    body: encodedBody,
  };
}

/**
 * Serialise the fixed prefix + variable header body into wire format:
 *   [MAGIC: 8B] [algorithm: 1B] [header_len: 4B big-endian] [body: N B]
 */
export function encodeHeader(
  algorithm: Algorithm,
  body: Uint8Array<ArrayBuffer>,
  options: HeaderEncodingOptions = {},
): EncodedHeader {
  const encodedBody = encodeHeaderBodyWithKeyId(body, options);
  const totalLen = FIXED_PREFIX_LENGTH + encodedBody.byteLength;
  const bytes = new Uint8Array(totalLen);
  bytes.set(MAGIC, HEADER_OFFSET_MAGIC);
  bytes[HEADER_OFFSET_ALGORITHM] = AlgorithmByte[algorithm];
  new DataView(bytes.buffer).setUint32(HEADER_OFFSET_HEADER_LEN, encodedBody.byteLength, false);
  bytes.set(encodedBody, HEADER_OFFSET_HEADER_BODY);
  return { bytes };
}

/**
 * Parse the wire-format header from a buffer.
 * Returns null when the buffer does not yet contain a complete header.
 * Throws on magic mismatch or unknown algorithm byte.
 */
export function decodeHeader(buf: Uint8Array<ArrayBuffer>): DecodedHeader | null {
  if (buf.byteLength < FIXED_PREFIX_LENGTH) return null;

  // Validate magic / version tag.
  for (let i = 0; i < MAGIC_LENGTH; i++) {
    if (buf[HEADER_OFFSET_MAGIC + i] !== MAGIC[i]) {
      const maybeVersioned =
        buf[0] === 0x53 && // S
        buf[1] === 0x54 && // T
        buf[2] === 0x52 && // R
        buf[3] === 0x45 && // E
        buf[4] === 0x4e && // N
        buf[5] === 0x43; // C
      if (maybeVersioned) {
        throw new UnsupportedVersionError(
          `Unsupported wire format version tag: ${String.fromCharCode(...buf.slice(0, MAGIC_LENGTH))}`,
        );
      }
      throw new InvalidHeaderError(`Invalid magic bytes at offset ${i}`);
    }
  }

  const algoByte = buf[HEADER_OFFSET_ALGORITHM];
  if (!isAlgorithmByteValue(algoByte)) {
    throw new UnsupportedAlgorithmError(
      `Unknown algorithm byte: 0x${algoByte.toString(16).padStart(2, "0")}`,
    );
  }
  const algorithm = ByteToAlgorithm[algoByte];

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const headerBodyLen = view.getUint32(HEADER_OFFSET_HEADER_LEN, false);

  const totalLength = FIXED_PREFIX_LENGTH + headerBodyLen;
  if (buf.byteLength < totalLength) return null; // incomplete

  const body = buf.slice(HEADER_OFFSET_HEADER_BODY, totalLength);
  const { keyId, body: algorithmBody } = decodeHeaderBodyWithKeyId(body);
  return { algorithm, body: algorithmBody, keyId, totalLength };
}

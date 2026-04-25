// Wire format magic bytes: "STRENC01"
export const MAGIC: Readonly<Uint8Array<ArrayBuffer>> = new Uint8Array([
  0x53, 0x54, 0x52, 0x45, 0x4e, 0x43, 0x30, 0x31,
]);

export const MAGIC_LENGTH = 8 as const;

// Algorithm identifiers (human-readable)
export const Algorithm = {
  RSA_OAEP: "RSA-OAEP",
  ECDH: "ECDH",
} as const;
export type Algorithm = (typeof Algorithm)[keyof typeof Algorithm];

// Algorithm wire bytes (1 byte in header)
export const AlgorithmByte = {
  [Algorithm.RSA_OAEP]: 0x01,
  [Algorithm.ECDH]: 0x02,
} as const satisfies Record<Algorithm, number>;

// Reverse mapping: wire byte → Algorithm
/** @internal */
export const ByteToAlgorithm = {
  0x01: Algorithm.RSA_OAEP,
  0x02: Algorithm.ECDH,
} as const;
/** @internal */
export type AlgorithmByteValue = 0x01 | 0x02;

// AES-GCM parameters
export const AES_KEY_LENGTH = 256 as const; // bits
export const GCM_IV_LENGTH = 12 as const; // bytes (96-bit nonce)
export const GCM_TAG_LENGTH = 128 as const; // bits (16 bytes)

// RSA parameters
export const RSA_KEY_SIZE = 2048 as const; // bits (minimum recommended)
export const RSA_HASH = "SHA-256" as const;

// ECDH parameters
export const ECDH_CURVE = "P-256" as const;

// HKDF parameters
export const HKDF_HASH = "SHA-256" as const;
export const HKDF_INFO = "stream-enc-v1" as const;
export const HKDF_SALT_LENGTH = 32 as const; // bytes

// Streaming parameters
export const DEFAULT_CHUNK_SIZE = 65536 as const; // 64 KiB

// Header layout offsets
export const HEADER_OFFSET_MAGIC = 0 as const;
export const HEADER_OFFSET_ALGORITHM = 8 as const;
export const HEADER_OFFSET_HEADER_LEN = 9 as const;
export const HEADER_OFFSET_HEADER_BODY = 13 as const;
export const FIXED_PREFIX_LENGTH = HEADER_OFFSET_HEADER_BODY; // 13 bytes before variable header

// Chunk layout: [payload_len(4)] [iv(12)] [ciphertext(variable, includes 16B GCM tag)]
export const CHUNK_LEN_FIELD = 4 as const; // bytes
export const CHUNK_OVERHEAD = CHUNK_LEN_FIELD + GCM_IV_LENGTH; // 16 bytes before ciphertext

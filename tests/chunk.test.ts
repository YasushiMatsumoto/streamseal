import { describe, it, expect } from "vitest";
import { buildAad, encodeChunk, decodeChunk } from "../src/chunk.js";
import { GCM_IV_LENGTH } from "../src/constants.js";

const FAKE_IV = new Uint8Array(GCM_IV_LENGTH).fill(0xab);
const FAKE_CIPHERTEXT = new Uint8Array(32).fill(0xcd); // 32 B (simulates AES-GCM output)

describe("chunk", () => {
  describe("buildAad", () => {
    it("returns a 4-byte big-endian encoding of the chunk index", () => {
      const aad0 = buildAad(0);
      expect(aad0).toEqual(new Uint8Array([0, 0, 0, 0]));

      const aad1 = buildAad(1);
      expect(aad1).toEqual(new Uint8Array([0, 0, 0, 1]));

      const aad256 = buildAad(256);
      expect(aad256).toEqual(new Uint8Array([0, 0, 1, 0]));
    });

    it("produces different bytes for different indices", () => {
      expect(buildAad(0)).not.toEqual(buildAad(1));
    });

    it("appends header hash bytes when provided", () => {
      const headerHash = new Uint8Array([0xaa, 0xbb, 0xcc]);
      const aad = buildAad(1, headerHash as Uint8Array<ArrayBuffer>);
      expect(aad).toEqual(new Uint8Array([0, 0, 0, 1, 0xaa, 0xbb, 0xcc]));
    });
  });

  describe("encodeChunk / decodeChunk round-trip", () => {
    it("encodes and decodes correctly", () => {
      const encoded = encodeChunk(FAKE_IV, FAKE_CIPHERTEXT);
      // payload_len = 12 + 32 = 44, wire = 4 + 44 = 48
      expect(encoded.byteLength).toBe(4 + GCM_IV_LENGTH + FAKE_CIPHERTEXT.byteLength);

      const decoded = decodeChunk(encoded);
      expect(decoded).not.toBeNull();
      expect(decoded!.iv).toEqual(FAKE_IV);
      expect(decoded!.ciphertext).toEqual(FAKE_CIPHERTEXT);
      expect(decoded!.totalLength).toBe(encoded.byteLength);
    });

    it("returns null when the buffer is too short (incomplete chunk)", () => {
      const encoded = encodeChunk(FAKE_IV, FAKE_CIPHERTEXT);
      const partial = encoded.slice(0, encoded.byteLength - 1);
      expect(decodeChunk(partial)).toBeNull();
    });

    it("returns null when even the length field is incomplete", () => {
      expect(decodeChunk(new Uint8Array(2))).toBeNull();
    });

    it("decodes only one chunk and reports correct totalLength", () => {
      const encoded = encodeChunk(FAKE_IV, FAKE_CIPHERTEXT);
      const extra = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const combined = new Uint8Array([...encoded, ...extra]);

      const decoded = decodeChunk(combined);
      expect(decoded!.totalLength).toBe(encoded.byteLength);
      // Remaining bytes are untouched
      const remaining = combined.slice(decoded!.totalLength);
      expect(remaining).toEqual(extra);
    });
  });
});

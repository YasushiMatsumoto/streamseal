import { describe, it, expect } from "vitest";
import { encodeHeader, decodeHeader } from "../src/header.js";
import { Algorithm } from "../src/constants.js";

const BODY_RSA = new Uint8Array([0x01, 0x02, 0x03, 0x04]); // fake RSA wrapped DEK
const BODY_ECDH = new Uint8Array([0xaa, 0xbb, 0xcc]); // fake ECDH ephemeral pub

describe("header", () => {
  it("encodes and decodes RSA-OAEP header", () => {
    const { bytes } = encodeHeader(Algorithm.RSA_OAEP, BODY_RSA);
    const decoded = decodeHeader(bytes);
    expect(decoded).not.toBeNull();
    expect(decoded!.algorithm).toBe(Algorithm.RSA_OAEP);
    expect(decoded!.body).toEqual(BODY_RSA);
    expect(decoded!.totalLength).toBe(bytes.byteLength);
  });

  it("encodes and decodes ECDH header", () => {
    const { bytes } = encodeHeader(Algorithm.ECDH, BODY_ECDH);
    const decoded = decodeHeader(bytes);
    expect(decoded).not.toBeNull();
    expect(decoded!.algorithm).toBe(Algorithm.ECDH);
    expect(decoded!.body).toEqual(BODY_ECDH);
  });

  it("returns null when buffer is too short to contain the full header body", () => {
    const { bytes } = encodeHeader(Algorithm.RSA_OAEP, BODY_RSA);
    const partial = bytes.slice(0, bytes.byteLength - 1);
    expect(decodeHeader(partial)).toBeNull();
  });

  it("returns null when buffer is shorter than the fixed prefix", () => {
    expect(decodeHeader(new Uint8Array(4))).toBeNull();
  });

  it("throws on bad magic bytes", () => {
    const { bytes } = encodeHeader(Algorithm.RSA_OAEP, BODY_RSA);
    const corrupted = bytes.slice();
    corrupted[0] = 0x00; // clobber first magic byte
    expect(() => decodeHeader(corrupted)).toThrow(/magic/i);
  });

  it("throws on unknown algorithm byte", () => {
    const { bytes } = encodeHeader(Algorithm.RSA_OAEP, BODY_RSA);
    const corrupted = bytes.slice();
    corrupted[8] = 0xff; // clobber algorithm byte
    expect(() => decodeHeader(corrupted)).toThrow(/algorithm/i);
  });

  it("totalLength points exactly to the start of chunks", () => {
    const body = new Uint8Array(100);
    const { bytes } = encodeHeader(Algorithm.ECDH, body);
    const decoded = decodeHeader(bytes)!;
    // Everything after totalLength is chunk data
    expect(decoded.totalLength).toBe(bytes.byteLength);
  });
});

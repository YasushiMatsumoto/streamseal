import { describe, expect, it } from "vitest";
import { EncryptingStream } from "../src/EncryptingStream.js";
import { DecryptingStream } from "../src/DecryptingStream.js";
import { Algorithm } from "../src/constants.js";
import {
  ResourceLimitError,
  TruncatedStreamError,
  UnsupportedVersionError,
} from "../src/errors.js";
import { collectStream, generateRsaKeyPair, toStream } from "./helpers.js";

describe("typed errors", () => {
  it("throws TruncatedStreamError when final marker is missing", async () => {
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const chunkSize = 16;
    const plaintext = crypto.getRandomValues(new Uint8Array(chunkSize * 2));

    const encStream = await EncryptingStream.create(publicKey, {
      algorithm: Algorithm.RSA_OAEP,
      chunkSize,
    });
    const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

    const headerBodyLen = new DataView(encrypted.buffer).getUint32(9, false);
    const chunksStart = 13 + headerBodyLen;
    let offset = chunksStart;
    const chunkStarts: number[] = [];
    while (offset < encrypted.byteLength) {
      chunkStarts.push(offset);
      const payloadLen = new DataView(encrypted.buffer).getUint32(offset, false);
      offset += 4 + payloadLen;
    }
    const missingFinalMarker = encrypted.slice(0, chunkStarts[chunkStarts.length - 1]);

    const decStream = DecryptingStream.create(privateKey);
    await expect(
      collectStream(toStream(missingFinalMarker).pipeThrough(decStream)),
    ).rejects.toBeInstanceOf(TruncatedStreamError);
  });

  it("throws ResourceLimitError when chunk limit is exceeded", async () => {
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const plaintext = crypto.getRandomValues(new Uint8Array(96));

    const encStream = await EncryptingStream.create(publicKey, {
      algorithm: Algorithm.RSA_OAEP,
      chunkSize: 32,
    });
    const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

    const decStream = DecryptingStream.create(privateKey, { maxChunks: 3 });
    await expect(collectStream(toStream(encrypted).pipeThrough(decStream))).rejects.toBeInstanceOf(
      ResourceLimitError,
    );
  });

  it("throws UnsupportedVersionError for unsupported STRENC version tag", async () => {
    const { privateKey } = await generateRsaKeyPair();
    const bad = new Uint8Array(13);
    bad.set(new TextEncoder().encode("STRENC99"), 0);

    const decStream = DecryptingStream.create(privateKey);
    await expect(collectStream(toStream(bad).pipeThrough(decStream))).rejects.toBeInstanceOf(
      UnsupportedVersionError,
    );
  });
});

import { describe, expect, it } from "vitest";
import { EncryptingStream } from "../src/EncryptingStream.js";
import { DecryptingStream } from "../src/DecryptingStream.js";
import { Algorithm } from "../src/constants.js";
import { encodeHeader, decodeHeader } from "../src/header.js";
import { collectStream, generateRsaKeyPair, toStream } from "./helpers.js";

describe("key rotation", () => {
  it("encodes and decodes a key id in the header", () => {
    const body = new Uint8Array([1, 2, 3]);
    const { bytes } = encodeHeader(Algorithm.RSA_OAEP, body, { keyId: "key-2026-01" });
    const decoded = decodeHeader(bytes);

    expect(decoded).not.toBeNull();
    expect(decoded!.keyId).toBe("key-2026-01");
    expect(decoded!.body).toEqual(body);
  });

  it("uses a key resolver to decrypt a key-id tagged stream", async () => {
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const plaintext = new TextEncoder().encode("key rotation test");

    const encStream = await EncryptingStream.create(publicKey, {
      algorithm: Algorithm.RSA_OAEP,
      keyId: "rotation-01",
    });
    const encrypted = await collectStream(toStream(plaintext).pipeThrough(encStream));

    const decStream = DecryptingStream.create(privateKey, {
      keyResolver: async (keyId) => {
        expect(keyId).toBe("rotation-01");
        return privateKey;
      },
    });

    const decrypted = await collectStream(toStream(encrypted).pipeThrough(decStream));
    expect(decrypted).toEqual(plaintext);
  });
});

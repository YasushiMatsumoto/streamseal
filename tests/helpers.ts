/**
 * Shared test key pair generators.
 * Uses Node.js 18+ globalThis.crypto.subtle — no external dependencies.
 */

const subtle = globalThis.crypto.subtle;

export async function generateRsaKeyPair(): Promise<CryptoKeyPair> {
  return subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["wrapKey", "unwrapKey"],
  );
}

export async function generateEcdhKeyPair(): Promise<CryptoKeyPair> {
  return subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

/** Collect all bytes from a ReadableStream<Uint8Array> into a single Uint8Array. */
export async function collectStream(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  const reader = stream.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const totalLength = chunks.reduce((acc, c) => acc + c.byteLength, 0);
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/** Wrap a Uint8Array in a single-chunk ReadableStream. */
export function toStream(data: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(data);
      controller.close();
    },
  });
}

/** Pipe an encrypted stream through a DecryptingStream and collect. */
export async function encryptThenDecrypt(
  encryptedStream: ReadableStream<Uint8Array>,
  decryptStream: TransformStream<Uint8Array, Uint8Array>,
): Promise<Uint8Array> {
  return collectStream(encryptedStream.pipeThrough(decryptStream));
}

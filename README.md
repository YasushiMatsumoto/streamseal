# streamseal

<p align="center">
  <img src="example/browser/logo.png" alt="streamseal logo" width="260" />
</p>

Encrypt large files in the browser before uploading, without loading the entire file into memory.

streamseal is a zero-dependency TypeScript library for client-side streaming file encryption using Web Crypto, AES-GCM, and TransformStream.

## Features

- **Streaming** — encrypts on-the-fly as bytes pass through a `TransformStream`; no full-file buffering
- **Envelope encryption** — a random per-upload DEK is protected by the recipient's public key
- **RSA-OAEP and ECDH** — choose your key exchange algorithm
- **Tamper-evident** — AES-GCM auth tags + chunk index in AAD prevent bit-flipping, reordering, and end-truncation
- **Key rotation ready** — embed a `keyId` in the header and resolve the right private key at decrypt time
- **Zero dependencies** — only Web Crypto API and the WHATWG Streams API
- **Node.js 18.5+ compatible** — same code works server-side via `globalThis.crypto`

## Use Cases

- Encrypt files in the browser before uploading them
- Stream-encrypt large files without full-file buffering
- Decrypt uploaded files incrementally on a Node.js server
- Build client-side encrypted file-sharing or document pipelines
- Reduce plaintext exposure in transit and upload intermediaries

## Security Notice

streamseal has not undergone an independent cryptographic security audit.

It uses standard Web Crypto primitives, but the wire format and streaming
protocol are project-specific. Do not use streamseal for high-value,
safety-critical, or regulated data without an independent security review.

See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md) before production use.

---

## Browser Support

| Feature                                       |  Chrome  | Firefox |  Safari   |   Edge   |
| --------------------------------------------- | :------: | :-----: | :-------: | :------: |
| Web Crypto API (`crypto.subtle`)              |   37+    |   34+   |    11+    |   79+    |
| `TransformStream`                             |   67+    |  102+   |   14.1+   |   79+    |
| **Streaming `fetch` body** (`duplex: 'half'`) | **105+** | **❌**  | **16.4+** | **105+** |

> **Firefox note**: Firefox does not currently support streaming request bodies in `fetch`. Use the `encryptFetch` helper on Chrome 105+, Safari 16.4+, and Edge 105+. For Firefox, collect the encrypted stream into a `Blob` first and upload that instead.

---

## Installation

```bash
npm install streamseal
```

---

## Quick Start

### Client (browser / React / SPA)

```ts
import { encryptFetch, Algorithm } from "streamseal";

const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`;

async function uploadEncrypted(file: File) {
  const response = await encryptFetch("/api/upload", file, PUBLIC_KEY_PEM, {
    algorithm: Algorithm.RSA_OAEP,
  });

  if (!response.ok) throw new Error(`Upload failed: ${response.status}`);
}
```

### With progress reporting

```ts
import { createEncryptor, Algorithm } from "streamseal";

const encryptor = await createEncryptor(PUBLIC_KEY_PEM, {
  algorithm: Algorithm.RSA_OAEP,
  chunkSize: 64 * 1024, // 64 KiB (default)
  onProgress: (bytes) => console.log(`Encrypted ${bytes} bytes`),
});

const encryptedStream = encryptor.encryptFile(file);

await fetch("/api/upload", {
  method: "POST",
  body: encryptedStream,
  headers: { "Content-Type": "application/octet-stream" },
  duplex: "half", // required for streaming request bodies
});
```

### ECDH (smaller keys, modern)

```ts
import { encryptFetch, Algorithm } from "streamseal";

await encryptFetch("/api/upload", file, EC_PUBLIC_KEY_PEM, {
  algorithm: Algorithm.ECDH,
});
```

### Cancellation with AbortSignal

```ts
import { encryptFetch, Algorithm } from "streamseal";

const controller = new AbortController();

// Pass signal to encryptFetch — both the stream and the fetch request abort together
const responsePromise = encryptFetch(
  "/api/upload",
  file,
  PUBLIC_KEY_PEM,
  { algorithm: Algorithm.RSA_OAEP },
  { signal: controller.signal },
);

// Cancel at any time (e.g. user clicks "Cancel")
controller.abort();

try {
  await responsePromise;
} catch (err) {
  if (err instanceof DOMException && err.name === "AbortError") {
    console.log("Upload cancelled");
  }
}
```

You can also pass a signal directly to `encryptStream` / `encryptFile` for lower-level control:

```ts
const stream = encryptor.encryptFile(file, controller.signal);
```

### Download and decrypt (browser)

```ts
import { decryptFetch, Algorithm } from "streamseal";

const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAA...
-----END PRIVATE KEY-----`;

// Fetches the URL and returns a ReadableStream of decrypted plaintext
const plainStream = await decryptFetch(
  "/api/files/report.enc",
  PRIVATE_KEY_PEM,
  Algorithm.RSA_OAEP,
  { onProgress: (bytes) => console.log(`Decrypted ${bytes} bytes`) },
);

// Pipe to a Blob for download
const blob = await new Response(plainStream).blob();
const url = URL.createObjectURL(blob);
const a = document.createElement("a");
a.href = url;
a.download = "report.pdf";
a.click();
```

---

### Server (Node.js 18.5+)

```ts
import { createDecryptor, Algorithm } from "streamseal/server";
import { createWriteStream } from "node:fs";

const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAA...
-----END PRIVATE KEY-----`;

// Express example
app.post("/api/upload", async (req, res) => {
  const decryptor = await createDecryptor(PRIVATE_KEY_PEM, Algorithm.RSA_OAEP);

  // Convert Node.js Readable → Web ReadableStream (Node.js 18.5+)
  const webStream = ReadableStream.from(req) as ReadableStream<Uint8Array>;

  const decryptedStream = decryptor.decryptStream(webStream);

  // Pipe decrypted stream to file via backpressure-aware writer
  const out = createWriteStream("output.bin");
  const reader = decryptedStream.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!out.write(value)) await new Promise((r) => out.once("drain", r));
    }
    out.end();
    res.json({ ok: true });
  } catch (err) {
    out.destroy();
    res.status(500).json({ error: String(err) });
  }
});
```

---

## Wire Format

```
[MAGIC: 8 B "STRENC01"]
[algorithm: 1 B]  0x01 = RSA-OAEP, 0x02 = ECDH
[header_len: 4 B big-endian uint32]
[header body: header_len B]  — algorithm-specific key material (see below)
[chunks...]
```

**Header body — RSA-OAEP:**

```
[wrapped_dek_len: 2 B] [wrapped_dek: N B]
```

**Header body — ECDH:**

```
[ephemeral_pub_len: 2 B] [ephemeral_public_key: N B]  (P-256 uncompressed, 65 B)
[salt: 32 B]  (random HKDF salt, RFC 5869)
```

**Each chunk:**

```
[payload_len: 4 B big-endian]  = 12 + ciphertext_len
[iv: 12 B]
[ciphertext: variable]  (plaintext + 16 B GCM auth tag)
```

The stream ends with an **authenticated terminal marker** (an encrypted empty chunk).
Decryption requires this marker by default, so removing the final chunk is detected.

The AES-GCM **AAD** is:

```
[chunk_index: 4 B big-endian] + [sha256(serialized_header): 32 B]
```

This binds every chunk to both its position and the exact header bytes, so swapping,
reordering, or header tampering causes authentication failure.

## Wire Format Versioning

- `STRENC01` is the current supported wire format tag.
- Unknown `STRENCxx` version tags are rejected.
- Package version and wire format version are managed independently.
- Security-sensitive format changes should use a new wire format tag.
- Legacy compatibility should be opt-in and explicit at API call sites.

---

## API Reference

### `createEncryptor(publicKeyPem, options)` → `Promise<Encryptor>`

| Parameter            | Type                  | Description                                             |
| -------------------- | --------------------- | ------------------------------------------------------- |
| `publicKeyPem`       | `string`              | SPKI PEM-encoded recipient public key                   |
| `options.algorithm`  | `Algorithm`           | `Algorithm.RSA_OAEP` or `Algorithm.ECDH`                |
| `options.chunkSize`  | `number?`             | Plaintext bytes per chunk (default: 65536)              |
| `options.onProgress` | `(n: number) => void` | Called after each chunk with cumulative encrypted bytes |
| `options.keyId`      | `string?`             | Optional header key identifier for key-rotation workflows |

The returned `Encryptor` has two methods:

- **`encryptFile(file: File | Blob, signal?: AbortSignal)`** → `ReadableStream<Uint8Array>`
- **`encryptStream(readable: ReadableStream<Uint8Array>, signal?: AbortSignal)`** → `ReadableStream<Uint8Array>`

Passing an `AbortSignal` errors the output stream and cancels the underlying reader when the signal fires.

### `encryptFetch(url, file, publicKeyPem, options, fetchInit?)` → `Promise<Response>`

Convenience wrapper. Encrypts `file` and POSTs the ciphertext stream to `url`. If `fetchInit.signal` is set, both the fetch request and the encryption stream are aborted together.

### `createDecryptor(privateKeyPem, algorithm)` → `Promise<Decryptor>`

Available from both `"streamseal"` (browser) and `"streamseal/server"` (Node.js 18+).

| Parameter       | Type        | Description                                |
| --------------- | ----------- | ------------------------------------------ |
| `privateKeyPem` | `string`    | PKCS#8 PEM-encoded private key             |
| `algorithm`     | `Algorithm` | Must match what was used during encryption |

The returned `Decryptor` has one method:

**`decryptStream(encrypted, options?)`** → `ReadableStream<Uint8Array>`

| Parameter                         | Type                  | Description                                                                            |
| --------------------------------- | --------------------- | -------------------------------------------------------------------------------------- |
| `encrypted`                       | `ReadableStream`      | Ciphertext stream produced by `EncryptingStream`                                       |
| `options.onProgress`              | `(n: number) => void` | Called after each chunk with cumulative decrypted bytes                                |
| `options.keyResolver`             | `(keyId, algorithm) => CryptoKey | Promise<CryptoKey>` | Optional resolver for header-embedded `keyId` values |
| `options.requireFinalChunkMarker` | `boolean`             | Default `true`. Set `false` only to decrypt legacy ciphertexts without terminal marker |
| `options.allowLegacyChunkAad`     | `boolean`             | Default `false`. Set `true` only for old ciphertexts that used chunk-index-only AAD    |
| `options.maxHeaderSize`           | `number`              | Default `65536`. Rejects oversized headers early                                       |
| `options.maxChunkSize`            | `number`              | Default `16777216` (16 MiB). Rejects oversized encrypted chunks                        |
| `options.maxPlaintextSize`        | `number`              | Default `8589934592` (8 GiB). Caps cumulative decrypted output                         |
| `options.maxChunks`               | `number`              | Default `1000000`. Caps total encrypted chunk count (including terminal marker)        |

### `decryptFetch(url, privateKeyPem, algorithm, options?, fetchInit?)` → `Promise<ReadableStream<Uint8Array>>`

Convenience wrapper. Fetches `url` and returns the response body as a decrypted plaintext stream.
Throws if the response status is not OK.

| Parameter       | Type              | Description                                       |
| --------------- | ----------------- | ------------------------------------------------- |
| `url`           | `string`          | Resource URL returning an encrypted response body |
| `privateKeyPem` | `string`          | PKCS#8 PEM-encoded private key                    |
| `algorithm`     | `Algorithm`       | Must match what was used during encryption        |
| `options`       | `{ onProgress? }` | Optional progress callback                        |
| `fetchInit`     | `RequestInit`     | Additional options forwarded to `fetch()`         |

### `Algorithm` constants

```ts
import { Algorithm } from "streamseal";
Algorithm.RSA_OAEP; // 'RSA-OAEP'
Algorithm.ECDH; // 'ECDH'
```

### Typed errors

`streamseal` exports typed errors for robust handling without brittle string checks:

- `StreamSealError` (base class with `code`)
- `InvalidHeaderError`
- `UnsupportedVersionError`
- `UnsupportedAlgorithmError`
- `InvalidChunkError`
- `AuthenticationFailedError`
- `TruncatedStreamError`
- `ResourceLimitError`
- `InvalidKeyError`

```ts
import { AuthenticationFailedError, ResourceLimitError } from "streamseal";

try {
  // decrypt...
} catch (err) {
  if (err instanceof ResourceLimitError) {
    // input exceeded configured limits
  } else if (err instanceof AuthenticationFailedError) {
    // tampered, corrupt, or wrong key context
  }
}
```

### `getKeyFingerprint(publicKeyPem)` → `Promise<string>`

Returns the SHA-256 fingerprint of a PEM-encoded public key as a lowercase hex string with colon separators (e.g. `"a3:f1:7c:..."`). Useful for verifying that the correct key is being used before encryption.

```ts
import { getKeyFingerprint } from "streamseal";

const fingerprint = await getKeyFingerprint(PUBLIC_KEY_PEM);
console.log(fingerprint);
// a3:f1:7c:08:...

// Compare against a known-good fingerprint before uploading
if (fingerprint !== EXPECTED_FINGERPRINT) {
  throw new Error("Public key mismatch — possible key substitution attack");
}
```

---

## Development

```bash
npm install
npm test           # vitest run (Node.js 18.5+)
npm run typecheck
npm run ci         # lint + format + typecheck + test + build + npm pack --dry-run
npm run test:watch
npm run build      # tsc
npm run docs       # generate HTML docs → docs/
```

---

## Example (client ↔ server)

A working Node.js example that demonstrates real streaming with memory usage logging.

```bash
# 1. generate key pairs (RSA-OAEP + ECDH)
npm run example:keygen

# 2. start receive server (terminal A)
npm run example:server          # RSA-OAEP
npm run example:server:ecdh     # ECDH

# 3. send encrypted data (terminal B)
npm run example:client          # RSA-OAEP, 50 MiB synthetic data
npm run example:client:ecdh     # ECDH
tsx example/client.ts rsa 200   # custom size (MiB)
```

Decrypted files are saved to `example/received/`. Client embeds a 16-byte sentinel in the first chunk; server logs it to confirm correct decryption.

Expected output:

```
[client] sentinel  : 53 54 52 45 41 4d 53 45 41 4c 54 45 53 54 21 00
[client]  encrypted 50.0 MiB | heap=8.6 MiB   ← heap stays flat
[client]  heap δ : +0.6 MiB (expected << 50 MiB)
[server]  first 16B  : 53 54 52 45 41 4d 53 45 41 4c 54 45 53 54 21 00  ← matches
```

---

## Project Structure

```
src/
  constants.ts           Algorithm / AlgorithmByte / numeric constants (as const)
  crypto-utils.ts        AES-GCM chunk encrypt / decrypt
  chunk.ts               binary encode/decode, AAD generation
  header.ts              wire format read/write
  algorithms/
    rsa-oaep.ts          RSA-OAEP DEK wrap/unwrap, PEM conversion
    ecdh.ts              ECDH + HKDF → DEK, PEM conversion
  EncryptingStream.ts    TransformStream (encryption)
  DecryptingStream.ts    TransformStream (decryption, shared with Node.js)
  client/
    index.ts             createEncryptor / encryptFetch
    fetch-types.d.ts     type extension for RequestInit.duplex
  server/
    index.ts             createDecryptor (Node.js 18+)
tests/                   Vitest tests (71 tests)
example/                 working client / server / keygen demo
```

---

## Security Notes

- IVs are generated with `crypto.getRandomValues` — never reused
- Chunk indices in AAD prevent reordering attacks
- Header hash in AAD binds chunks to the parsed header (algorithm/header tampering detection)
- Authenticated terminal marker detects full-last-chunk truncation
- Decryptor resource limits reject oversized headers/chunks and excessive stream size
- AES-GCM with 128-bit auth tags provides authenticated encryption
- RSA-OAEP modulus: 2048 bits minimum
- ECDH uses P-256; shared secret is processed through HKDF-SHA-256

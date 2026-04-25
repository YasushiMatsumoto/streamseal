/**
 * streamseal — example server
 * Receives an encrypted POST body, decrypts it as a stream, and reports memory usage.
 *
 * Usage:
 *   npm run example:server          (RSA-OAEP)
 *   npm run example:server:ecdh     (ECDH)
 */
import { createServer } from "node:http";
import { createWriteStream } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";

import { createDecryptor, Algorithm } from "../src/server/index.js";

const PORT = 3001;
const algo = process.argv[2] === "ecdh" ? Algorithm.ECDH : Algorithm.RSA_OAEP;
const keyFile = algo === Algorithm.ECDH ? "ec-private.pem" : "rsa-private.pem";
const RECEIVED_DIR = new URL("./received/", import.meta.url);

// ---- memory helpers --------------------------------------------------------

function fmtMiB(bytes: number): string {
  return `${(bytes / 1048576).toFixed(1)} MiB`;
}

function memLine(): string {
  const m = process.memoryUsage();
  return `heap=${fmtMiB(m.heapUsed)} rss=${fmtMiB(m.rss)}`;
}

// ---- startup ---------------------------------------------------------------

let privateKeyPem: string;
try {
  privateKeyPem = await readFile(new URL(`./keys/${keyFile}`, import.meta.url), "utf8");
} catch {
  console.error(`[server] key not found: example/keys/${keyFile}`);
  console.error("[server] Run: npm run example:keygen");
  process.exit(1);
}

const decryptor = await createDecryptor(privateKeyPem, algo);
await mkdir(RECEIVED_DIR, { recursive: true });
console.log(`[server] algorithm : ${algo}`);
console.log(`[server] output    : example/received/`);
console.log(`[server] baseline  : ${memLine()}`);

// ---- HTTP server -----------------------------------------------------------

createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/upload") {
    res.writeHead(404);
    res.end();
    return;
  }

  console.log("\n[server] ── upload started ──────────────────────────");
  const baselineHeap = process.memoryUsage().heapUsed;
  const outName = `upload-${Date.now()}.bin`;
  const outPath = new URL(outName, RECEIVED_DIR);
  const fileStream = createWriteStream(outPath);
  console.log(`[server]  saving to: example/received/${outName}`);

  // Convert Node.js IncomingMessage (Readable) → Web ReadableStream<Uint8Array>
  // Uses ReadableStream constructor with async iterator to avoid the type conflict
  // between DOM ReadableStream and Node.js ReadableStream from @types/node.
  const iter = req[Symbol.asyncIterator]();
  const webStream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      const { done, value } = await iter.next();
      if (done) {
        controller.close();
      } else {
        controller.enqueue(value instanceof Uint8Array ? value : new Uint8Array(value));
      }
    },
    cancel() {
      req.destroy();
    },
  });

  let totalBytes = 0;
  let lastReportedMiB = 0;

  const decryptedStream = decryptor.decryptStream(webStream, {
    onProgress(n) {
      const currentMiB = Math.floor(n / 1048576);
      if (currentMiB > lastReportedMiB) {
        lastReportedMiB = currentMiB;
        console.log(`[server]  decrypted ${fmtMiB(n).padStart(8)} | ${memLine()}`);
      }
    },
  });

  // Drain and write to file simultaneously (streaming — no full buffer)
  const reader = decryptedStream.getReader();
  let firstChunk = true;
  await new Promise<void>((resolve, reject) => {
    fileStream.on("error", reject);
    fileStream.on("finish", resolve);
    (async () => {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (firstChunk) {
            const hex = [...value.subarray(0, 16)]
              .map((b) => b.toString(16).padStart(2, "0"))
              .join(" ");
            console.log(`[server]  first 16B  : ${hex}`);
            firstChunk = false;
          }
          totalBytes += value.byteLength;
          if (!fileStream.write(value)) {
            // respect backpressure
            await new Promise<void>((r) => fileStream.once("drain", r));
          }
        }
        fileStream.end();
      } catch (err) {
        fileStream.destroy(err instanceof Error ? err : new Error(String(err)));
        reject(err);
      }
    })();
  });

  const heapDelta = process.memoryUsage().heapUsed - baselineHeap;
  console.log(`[server] ── upload complete ─────────────────────────`);
  console.log(`[server]  received  : ${fmtMiB(totalBytes)}`);
  console.log(
    `[server]  heap δ    : ${heapDelta >= 0 ? "+" : ""}${fmtMiB(heapDelta)} (expected << data size)`,
  );
  console.log(`[server]  memory    : ${memLine()}`);

  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ ok: true, bytes: totalBytes }));
}).listen(PORT, () => {
  console.log(`[server] listening on http://localhost:${PORT}`);
  console.log("[server] waiting for encrypted upload (POST /upload)...\n");
});

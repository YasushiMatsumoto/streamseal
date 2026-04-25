/**
 * streamseal — example client
 * Generates synthetic data, encrypts it as a stream, and POSTs to the example server.
 * Logs memory usage at each MiB to demonstrate that data is never fully buffered.
 *
 * Usage:
 *   npm run example:client             (RSA-OAEP, 50 MiB)
 *   npm run example:client:ecdh        (ECDH, 50 MiB)
 *   tsx example/client.ts rsa 200      (RSA-OAEP, 200 MiB)
 */
import { request } from "node:http";
import { readFile } from "node:fs/promises";
import { Readable } from "node:stream";
import { createEncryptor, Algorithm } from "../src/client/index.js";

const PORT = 3001;
const algo = process.argv[2] === "ecdh" ? Algorithm.ECDH : Algorithm.RSA_OAEP;
const totalMiB = parseInt(process.argv[3] ?? "50", 10);
const totalBytes = totalMiB * 1024 * 1024;
const keyFile = algo === Algorithm.ECDH ? "ec-public.pem" : "rsa-public.pem";

// ---- memory helpers --------------------------------------------------------

function fmtMiB(bytes: number): string {
  return `${(bytes / 1048576).toFixed(1)} MiB`;
}

function memLine(): string {
  const m = process.memoryUsage();
  return `heap=${fmtMiB(m.heapUsed)} rss=${fmtMiB(m.rss)}`;
}

// ---- synthetic data stream -------------------------------------------------
//
// First chunk starts with a fixed 16-byte sentinel so we can verify the
// decrypted file begins with the same bytes. The rest is random.

const SENTINEL = new Uint8Array([
  0x53,
  0x54,
  0x52,
  0x45,
  0x41,
  0x4d,
  0x53,
  0x45,
  0x41,
  0x4c,
  0x54,
  0x45,
  0x53,
  0x54,
  0x21,
  0x00, // "STREAMSEALTEST!\0"
]);

function syntheticStream(length: number): ReadableStream<Uint8Array<ArrayBuffer>> {
  const CHUNK = 65536;
  let sent = 0;
  let first = true;
  return new ReadableStream({
    pull(controller) {
      if (sent >= length) {
        controller.close();
        return;
      }
      const size = Math.min(CHUNK, length - sent);
      const chunk = new Uint8Array(size);
      crypto.getRandomValues(chunk);
      if (first) {
        chunk.set(SENTINEL, 0); // overwrite first 16 bytes with known sentinel
        first = false;
      }
      controller.enqueue(chunk);
      sent += size;
    },
  });
}

// ---- main ------------------------------------------------------------------

let publicKeyPem: string;
try {
  publicKeyPem = await readFile(new URL(`./keys/${keyFile}`, import.meta.url), "utf8");
} catch {
  console.error(`[client] key not found: example/keys/${keyFile}`);
  console.error("[client] Run: npm run example:keygen");
  process.exit(1);
}

console.log(`[client] algorithm : ${algo}`);
console.log(`[client] data size : ${totalMiB} MiB`);
console.log(
  `[client] sentinel  : ${[...SENTINEL].map((b) => b.toString(16).padStart(2, "0")).join(" ")} (first 16 bytes)`,
);
console.log(`[client] baseline  : ${memLine()}`);

let lastReportedMiB = 0;
const encryptor = await createEncryptor(publicKeyPem, {
  algorithm: algo,
  onProgress(n) {
    const currentMiB = Math.floor(n / 1048576);
    if (currentMiB > lastReportedMiB) {
      lastReportedMiB = currentMiB;
      console.log(`[client]  encrypted ${fmtMiB(n).padStart(8)} | ${memLine()}`);
    }
  },
});

const encryptedStream = encryptor.encryptStream(syntheticStream(totalBytes));

// Convert Web ReadableStream → Node.js Readable via async iterator (avoids type conflict
// between DOM ReadableStream and Node.js ReadableStream from @types/node).
async function* streamToAsyncIterable(
  stream: ReadableStream<Uint8Array>,
): AsyncGenerator<Uint8Array> {
  const reader = stream.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      yield value;
    }
  } finally {
    reader.releaseLock();
  }
}
const nodeReadable = Readable.from(streamToAsyncIterable(encryptedStream));

console.log("\n[client] ── sending encrypted stream ───────────────");
const baselineHeap = process.memoryUsage().heapUsed;
const t0 = performance.now();

await new Promise<void>((resolve, reject) => {
  const req = request(
    {
      method: "POST",
      host: "localhost",
      port: PORT,
      path: "/upload",
      headers: {
        "Content-Type": "application/octet-stream",
        "Transfer-Encoding": "chunked",
      },
    },
    (res) => {
      let body = "";
      res.on("data", (chunk: Buffer) => {
        body += chunk.toString();
      });
      res.on("end", () => {
        const json = JSON.parse(body) as { ok: boolean; bytes: number };
        const elapsed = ((performance.now() - t0) / 1000).toFixed(2);
        const throughput = (totalMiB / parseFloat(elapsed)).toFixed(1);
        const heapDelta = process.memoryUsage().heapUsed - baselineHeap;

        console.log(`[client] ── done ──────────────────────────────────`);
        console.log(`[client]  server ack : ${JSON.stringify(json)}`);
        console.log(`[client]  time       : ${elapsed} s`);
        console.log(`[client]  throughput : ~${throughput} MiB/s (encrypt + AES-GCM + network)`);
        console.log(
          `[client]  heap δ     : ${heapDelta >= 0 ? "+" : ""}${fmtMiB(heapDelta)} (expected << ${totalMiB} MiB)`,
        );
        console.log(`[client]  memory     : ${memLine()}`);
        console.log(`\n[client]  ✓ streaming confirmed if heap δ is in the single-digit MiB range`);
        resolve();
      });
    },
  );
  req.on("error", (err) => {
    console.error(`[client] connection error: ${(err as NodeJS.ErrnoException).message}`);
    console.error("[client] Is the server running? npm run example:server");
    reject(err);
  });
  nodeReadable.pipe(req);
});

/**
 * streamseal -- browser demo server (Express + HTTP)
 *
 * Usage: npm run example:browser
 */
import { createReadStream, createWriteStream } from "node:fs";
import { fileURLToPath } from "node:url";
import { access, mkdir, readFile } from "node:fs/promises";
import { basename } from "node:path";
import { createServer } from "node:http";
import express from "express";
import { createDecryptor, Algorithm, type Decryptor } from "../src/server/index.js";

// -- Constants ----------------------------------------------------------------

const PORT = 8080;
const EXAMPLE_DIR = new URL("./", import.meta.url);
const DIST_DIR = fileURLToPath(new URL("../dist/", import.meta.url));
const BROWSER_DIR = fileURLToPath(new URL("browser/", EXAMPLE_DIR));
const RECEIVED_DIR = new URL("received/", EXAMPLE_DIR);

// -- Helpers ------------------------------------------------------------------

function fmtMiB(bytes: number): string {
  return `${(bytes / 1048576).toFixed(1)} MiB`;
}

function memLine(): string {
  const m = process.memoryUsage();
  return `heap=${fmtMiB(m.heapUsed)} rss=${fmtMiB(m.rss)}`;
}

// -- Load decryption keys -----------------------------------------------------

let rsaDecryptor: Decryptor;
try {
  const pem = await readFile(new URL("keys/rsa-private.pem", EXAMPLE_DIR), "utf8");
  rsaDecryptor = await createDecryptor(pem, Algorithm.RSA_OAEP);
} catch {
  console.error("[browser-server] RSA private key not found. Run: npm run example:keygen");
  process.exit(1);
}

let ecdhDecryptor: Decryptor | null = null;
try {
  const pem = await readFile(new URL("keys/ec-private.pem", EXAMPLE_DIR), "utf8");
  ecdhDecryptor = await createDecryptor(pem, Algorithm.ECDH);
  console.log("[browser-server] Keys: RSA-OAEP + ECDH");
} catch {
  console.log("[browser-server] Keys: RSA-OAEP only (run keygen to add ECDH)");
}

await mkdir(RECEIVED_DIR, { recursive: true });

// -- Express routes -----------------------------------------------------------

const app = express();
app.use(express.static(BROWSER_DIR));
app.use("/dist", express.static(DIST_DIR));

app.get("/api/public-key", async (req, res) => {
  const algo = req.query["algo"] === "ecdh" ? "ecdh" : "rsa";
  const keyFile = algo === "ecdh" ? "keys/ec-public.pem" : "keys/rsa-public.pem";
  try {
    const pem = await readFile(new URL(keyFile, EXAMPLE_DIR), "utf8");
    res.type("text/plain").send(pem);
  } catch {
    res.status(404).send("Key not found -- run: npm run example:keygen");
  }
});

app.post("/api/upload", async (req, res) => {
  const isEcdh = req.query["algo"] === "ecdh";
  const algo = isEcdh ? Algorithm.ECDH : Algorithm.RSA_OAEP;
  const decryptor = isEcdh ? ecdhDecryptor : rsaDecryptor;

  if (!decryptor) {
    res.status(400).json({ error: "ECDH key not available -- run: npm run example:keygen" });
    return;
  }

  const t0 = Date.now();
  const encName = `upload-${t0}.enc`;
  const decName = `upload-${t0}.dec`;
  const encPath = new URL(encName, RECEIVED_DIR);
  const decPath = new URL(decName, RECEIVED_DIR);
  console.log(`\n[server] upload started (${algo})`);
  console.log(`[server]  encrypted → example/received/${encName}`);
  console.log(`[server]  decrypted → example/received/${decName}`);

  const encFile = createWriteStream(fileURLToPath(encPath));
  let encBytes = 0;

  const iter = req[Symbol.asyncIterator]();
  const webStream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      const { done, value } = await iter.next();
      if (done) {
        controller.close();
        encFile.end();
      } else {
        const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
        encBytes += chunk.byteLength;
        encFile.write(chunk);
        controller.enqueue(chunk);
      }
    },
    cancel() {
      encFile.destroy();
      req.destroy();
    },
  });

  let lastReportedMiB = 0;
  const decryptedStream = decryptor.decryptStream(webStream, {
    onProgress(n) {
      const mib = Math.floor(n / 1048576);
      if (mib > lastReportedMiB) {
        lastReportedMiB = mib;
        console.log(`[server]  decrypted ${fmtMiB(n).padStart(8)} | ${memLine()}`);
      }
    },
  });

  const fileStream = createWriteStream(fileURLToPath(decPath));
  const reader = decryptedStream.getReader();
  let totalBytes = 0;

  try {
    await new Promise<void>((resolve, reject) => {
      fileStream.on("error", reject);
      (async () => {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            totalBytes += value.byteLength;
            if (!fileStream.write(value)) {
              await new Promise<void>((r) => fileStream.once("drain", r));
            }
          }
          fileStream.end();
          fileStream.once("finish", resolve);
        } catch (err) {
          fileStream.destroy();
          reject(err);
        }
      })();
    });

    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    console.log(
      `[server]  enc=${fmtMiB(encBytes)} dec=${fmtMiB(totalBytes)} in ${elapsed}s | ${memLine()}`,
    );
    res.json({ ok: true, encFile: encName, encBytes, decFile: decName, decBytes: totalBytes });
  } catch (err) {
    console.error("[server] decryption error:", err);
    if (!res.headersSent) res.status(400).json({ error: String(err) });
  }
});

// DEMO ONLY — never expose private keys in production
app.get("/api/private-key", async (req, res) => {
  const algo = req.query["algo"] === "ecdh" ? "ecdh" : "rsa";
  const keyFile = algo === "ecdh" ? "keys/ec-private.pem" : "keys/rsa-private.pem";
  try {
    const pem = await readFile(new URL(keyFile, EXAMPLE_DIR), "utf8");
    res.type("text/plain").send(pem);
  } catch {
    res.status(404).send("Key not found -- run: npm run example:keygen");
  }
});

app.get("/api/download/:encFile", async (req, res) => {
  const name = basename(req.params["encFile"]);
  const filePath = fileURLToPath(new URL(name, RECEIVED_DIR));
  try {
    await access(filePath);
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${name}"`);
    createReadStream(filePath).pipe(res);
  } catch {
    res.status(404).json({ error: "File not found" });
  }
});

// -- HTTP server --------------------------------------------------------------

const server = createServer(app);

server.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EADDRINUSE") {
    console.error(`[browser-server] Port ${PORT} is in use. Ctrl+C to stop the old process.`);
    process.exit(1);
  }
  throw err;
});

process.on("SIGINT", () => server.close(() => process.exit(0)));

server.listen(PORT, () => {
  console.log(`[browser-server] http://localhost:${PORT}`);
  console.log(`[browser-server] baseline: ${memLine()}`);
});

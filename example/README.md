# streamseal — examples

Three runnable examples demonstrating streamseal in different environments.

---

## Prerequisites

```bash
# From the repo root — build the library first
npm install
npm run build
```

---

## 1. Node.js CLI (client ↔ server)

A pair of Node.js scripts that stream encrypted data over HTTP.  
`client.ts` generates synthetic data, encrypts it, and POSTs to `server.ts`.  
The server decrypts in streaming fashion and writes to `example/received/`.

### Setup

```bash
# Generate RSA-OAEP and ECDH key pairs → example/keys/
npm run example:keygen
```

### Run

```bash
# Terminal A — start the receive server
npm run example:server           # RSA-OAEP (default)
npm run example:server:ecdh      # ECDH

# Terminal B — send encrypted data
npm run example:client           # RSA-OAEP, 50 MiB synthetic data
npm run example:client:ecdh      # ECDH, 50 MiB
tsx example/client.ts rsa 200    # custom size in MiB
tsx example/client.ts ecdh 500
```

### Expected output

```
[client] sentinel  : 53 54 52 45 41 4d 53 45 41 4c 54 45 53 54 21 00
[client]  encrypted 50.0 MiB | heap=8.6 MiB   ← heap stays flat
[client]  heap δ : +0.6 MiB (expected << 50 MiB)
[server]  first 16B  : 53 54 52 45 41 4d 53 45 41 4c 54 45 53 54 21 00  ← matches sentinel
```

The heap staying flat confirms that the library never buffers the full file.

---

## 2. Browser demo

An Express server (`browser-server.ts`) that serves a browser UI for:

- **Encrypt & Upload** — client-side AES-GCM encryption streamed to the server
- **Cancel** — abort an in-progress upload with `AbortController`
- **Download & Decrypt** — fetch the encrypted file back and decrypt it in the browser
- **Memory Profiler** — detailed heap usage tracking (Chrome only)

### Run (local)

```bash
# Requires keys from step 1 (npm run example:keygen)
npm run example:browser
# → http://localhost:8080
```

### Run (Docker — HTTPS with nginx)

For testing streaming uploads over HTTPS (closer to production):

```bash
# 1. Generate a self-signed TLS cert for localhost
npm run example:gencert

# 2. Start nginx + Node container
npm run example:browser:docker
# → https://localhost (accept the self-signed cert warning)
```

> **Note**: Chrome will show a "not private" warning for the self-signed cert.  
> Click **Advanced → Proceed to localhost**, or enable `chrome://flags/#allow-insecure-localhost`.

### Browser compatibility

| Feature          | Chrome | Safari | Edge | Firefox |
| ---------------- | ------ | ------ | ---- | ------- |
| Streaming upload | 105+   | 16.4+  | 105+ | ❌      |
| Memory Profiler  | ✅     | ❌     | ❌   | ❌      |

The memory profiler uses `performance.memory` which is Chrome-only.  
Upload and decrypt work on Chrome, Safari 16.4+, and Edge.

---

## Files

| File                | Purpose                                                         |
| ------------------- | --------------------------------------------------------------- |
| `keygen.ts`         | Generates RSA-OAEP + ECDH key pairs into `keys/`                |
| `server.ts`         | Node.js HTTP receive server (decrypts and saves to `received/`) |
| `client.ts`         | Node.js streaming upload client (synthetic data)                |
| `browser-server.ts` | Express server for the browser demo                             |
| `browser/`          | Browser UI (HTML + JS)                                          |
| `gencert.ts`        | Generates a self-signed TLS cert for Docker/nginx               |
| `Dockerfile`        | Docker image for the browser demo                               |
| `nginx.conf`        | nginx reverse proxy config (HTTPS → Node.js, streaming-safe)    |

### Generated directories (git-ignored)

| Directory   | Contents                                                        |
| ----------- | --------------------------------------------------------------- |
| `keys/`     | RSA and ECDH key pairs (created by `keygen`)                    |
| `received/` | Uploaded files — both `.enc` (encrypted) and `.dec` (decrypted) |
| `certs/`    | Self-signed TLS cert (created by `gencert`)                     |

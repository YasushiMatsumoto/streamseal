/**
 * streamseal — key pair generator
 * Generates RSA-OAEP and ECDH key pairs used by the example server/client.
 *
 * Usage: npm run example:keygen
 */
import { mkdir, writeFile } from "node:fs/promises";

const subtle = globalThis.crypto.subtle;
const KEYS_DIR = new URL("./keys/", import.meta.url);

function toPem(buf: ArrayBuffer, label: string): string {
  const b64 = Buffer.from(buf).toString("base64");
  const body = (b64.match(/.{1,64}/g) ?? []).join("\n");
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

async function genRsa(): Promise<void> {
  process.stdout.write("Generating RSA-OAEP 2048-bit key pair... ");
  const { publicKey, privateKey } = await subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["wrapKey", "unwrapKey"],
  );
  const [pubDer, prvDer] = await Promise.all([
    subtle.exportKey("spki", publicKey),
    subtle.exportKey("pkcs8", privateKey),
  ]);
  await Promise.all([
    writeFile(new URL("rsa-public.pem", KEYS_DIR), toPem(pubDer, "PUBLIC KEY")),
    writeFile(new URL("rsa-private.pem", KEYS_DIR), toPem(prvDer, "PRIVATE KEY")),
  ]);
  console.log("done");
  console.log("  example/keys/rsa-public.pem");
  console.log("  example/keys/rsa-private.pem");
}

async function genEcdh(): Promise<void> {
  process.stdout.write("Generating ECDH P-256 key pair... ");
  const { publicKey, privateKey } = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const [pubDer, prvDer] = await Promise.all([
    subtle.exportKey("spki", publicKey),
    subtle.exportKey("pkcs8", privateKey),
  ]);
  await Promise.all([
    writeFile(new URL("ec-public.pem", KEYS_DIR), toPem(pubDer, "PUBLIC KEY")),
    writeFile(new URL("ec-private.pem", KEYS_DIR), toPem(prvDer, "PRIVATE KEY")),
  ]);
  console.log("done");
  console.log("  example/keys/ec-public.pem");
  console.log("  example/keys/ec-private.pem");
}

await mkdir(KEYS_DIR, { recursive: true });
await genRsa();
await genEcdh();
console.log("\nNext steps:");
console.log("  npm run example:server   (in one terminal)");
console.log("  npm run example:client   (in another terminal)");

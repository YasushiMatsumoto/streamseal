/**
 * Generate a self-signed ECDSA P-256 cert for localhost and write it to
 * example/certs/ so nginx (Docker) can use it.
 *
 * Chrome will show a one-time "not private" warning -- click Advanced →
 * Proceed to localhost (or enable chrome://flags/#allow-insecure-localhost).
 *
 * Usage: npm run example:gencert
 */
import { generateKeyPairSync, randomBytes, sign as cryptoSign } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

// -- ASN.1 / DER helpers ------------------------------------------------------

function tlv(tag: number, value: Buffer): Buffer {
  const len = value.length;
  const lb =
    len < 128
      ? Buffer.from([len])
      : len < 256
        ? Buffer.from([0x81, len])
        : Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
  return Buffer.concat([Buffer.from([tag]), lb, value]);
}
const seq = (...a: Buffer[]) => tlv(0x30, Buffer.concat(a));
const set_ = (...a: Buffer[]) => tlv(0x31, Buffer.concat(a));
const int_ = (b: Buffer) => tlv(0x02, b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b);
const bool_ = (v: boolean) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
const bitStr = (d: Buffer, u = 0) => tlv(0x03, Buffer.concat([Buffer.from([u]), d]));
const octStr = (d: Buffer) => tlv(0x04, d);
const oid = (hex: string) => tlv(0x06, Buffer.from(hex, "hex"));
const utf8 = (s: string) => tlv(0x0c, Buffer.from(s, "utf8"));
const ctx = (n: number, c: Buffer) => tlv(0xa0 + n, c);
const impl = (n: number, d: Buffer) => tlv(0x80 + n, d);

function utcTime(d: Date): Buffer {
  const p = (n: number) => String(n).padStart(2, "0");
  return tlv(
    0x17,
    Buffer.from(
      `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
        `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`,
      "ascii",
    ),
  );
}

function buildLocalhostCert(): { cert: string; key: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;

  const now = new Date();
  const expire = new Date(now.getTime() + 364 * 24 * 3600_000); // 364d < Chrome 398d limit
  const serial = randomBytes(16);
  serial[0] &= 0x7f; // must be positive

  const algId = seq(oid("2a8648ce3d040302")); // ecdsa-with-SHA256
  const name = seq(set_(seq(oid("550403"), utf8("localhost")))); // CN=localhost

  const tbs = seq(
    ctx(0, int_(Buffer.from([0x02]))), // version v3
    int_(serial), // serialNumber
    algId, // signature
    name, // issuer
    seq(utcTime(now), utcTime(expire)), // validity
    name, // subject
    spki, // subjectPublicKeyInfo
    ctx(
      3,
      seq(
        // SubjectAltName: critical, dNSName=localhost
        seq(oid("551d11"), bool_(true), octStr(seq(impl(2, Buffer.from("localhost", "ascii"))))),
        // BasicConstraints: critical, cA=FALSE
        seq(oid("551d13"), bool_(true), octStr(seq())),
        // KeyUsage: critical, digitalSignature
        seq(oid("551d0f"), bool_(true), octStr(bitStr(Buffer.from([0x80]), 7))),
        // ExtKeyUsage: serverAuth
        seq(oid("551d25"), octStr(seq(oid("2b06010505070301")))),
      ),
    ),
  );

  const sigDer = cryptoSign("SHA256", tbs, privateKey);
  const certDer = seq(tbs, algId, bitStr(sigDer));

  const toPEM = (label: string, der: Buffer) =>
    `-----BEGIN ${label}-----\n${der
      .toString("base64")
      .match(/.{1,64}/g)!
      .join("\n")}\n-----END ${label}-----\n`;

  return { cert: toPEM("CERTIFICATE", certDer), key: toPEM("PRIVATE KEY", pkcs8) };
}

// -- Write files --------------------------------------------------------------

const CERTS_DIR = new URL("certs/", new URL("./", import.meta.url));
await mkdir(fileURLToPath(CERTS_DIR), { recursive: true });

const { cert, key } = buildLocalhostCert();
await writeFile(fileURLToPath(new URL("localhost.pem", CERTS_DIR)), cert, "utf8");
await writeFile(fileURLToPath(new URL("localhost-key.pem", CERTS_DIR)), key, "utf8");

console.log("Generated example/certs/localhost.pem and localhost-key.pem");
console.log("Chrome warning: click Advanced → Proceed to localhost (unsafe)");

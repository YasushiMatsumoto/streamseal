import { webcrypto as nodeWebcrypto } from "node:crypto";

export const cryptoImpl = globalThis.crypto ?? nodeWebcrypto;
export const subtle = cryptoImpl.subtle;

if (!subtle) {
  throw new Error("Web Crypto API (subtle) is unavailable in this runtime.");
}

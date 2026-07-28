import { webcrypto as nodeWebcrypto } from "node:crypto";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: nodeWebcrypto,
    configurable: true,
  });
}

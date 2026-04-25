// `duplex: 'half'` is required by the Fetch spec for streaming request bodies
// but the TypeScript DOM lib does not yet include it.
// https://fetch.spec.whatwg.org/#dom-requestinit-duplex

declare global {
  interface RequestInit {
    duplex?: "half";
  }
}

export {};

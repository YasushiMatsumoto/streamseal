# Threat Model

## Protected Assets

- Confidentiality of plaintext file content.
- Integrity of each encrypted chunk.
- Integrity of chunk ordering.
- Integrity of serialized header binding to chunks.
- Public key identity verification inputs (for example, fingerprint checks).
- Bounded plaintext memory use during streaming operations.

## In-Scope Attackers

- Passive network observer.
- Active attacker who can modify encrypted stream bytes.
- Active attacker who can drop, reorder, duplicate, or inject chunks.
- Active attacker who can truncate ciphertext streams.
- Adversary sending malformed encrypted input to a decryptor endpoint.
- Adversary attempting algorithm/header tampering.

## Security Properties Provided

- Chunk confidentiality and integrity via AES-GCM.
- Chunk order/authentication context via AAD.
- Header-to-chunk binding via header hash in AAD.
- Truncation detection via authenticated terminal marker.
- Early rejection of oversized or malformed stream components via configurable limits.

## Out of Scope / Requires External Controls

- XSS or malicious JavaScript in the client runtime.
- Malware or full compromise of client/server hosts.
- Private key exfiltration from key stores or memory.
- Tampering of public key distribution channels.
- Post-decryption data leakage on servers.
- Hiding metadata such as file size, timing, traffic patterns.
- Supply-chain compromise in dependencies, build, CI, or deployment systems.

## Assumptions

- Web Crypto implementation is correct and uncompromised.
- Randomness source for IV/salt generation is secure.
- Callers validate public key authenticity before encrypting sensitive data.
- Decryptors are configured with limits appropriate for deployment context.

## Residual Risks

- Incorrect operational key management can nullify cryptographic protections.
- Large-scale abuse may still cause resource pressure if configured limits are too high.

## Operational Recommendations

- Pin and verify public key fingerprints before encryption.
- Keep the current authenticated format and terminal marker requirement enabled.
- Set strict `maxHeaderSize`, `maxChunkSize`, `maxPlaintextSize`, and `maxChunks` per environment.
- Monitor decryption failures and rate-limit untrusted upload endpoints.

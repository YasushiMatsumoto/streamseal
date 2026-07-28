# Security Policy

## Supported Versions

Security fixes are provided for the latest minor release line.

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |
| < 0.2.0 | No        |

## Reporting a Vulnerability

Please report vulnerabilities through GitHub Private Vulnerability Reporting for this repository.

- Do not open public issues with exploit details.
- Include reproduction steps, affected versions, and impact.
- If possible, include a minimal proof of concept.

If Private Vulnerability Reporting is not available, contact the maintainer through repository contact channels and request a private disclosure path.

## Security Scope and Guarantees

streamseal provides streaming encryption and decryption utilities based on Web Crypto primitives.

- Uses AES-GCM for chunk confidentiality/integrity.
- Uses RSA-OAEP or ECDH+HKDF for DEK establishment.
- Authenticates chunk order and binds chunk authentication to serialized header bytes.
- Uses an authenticated terminal marker to detect full-last-chunk truncation.
- Enforces decryption resource limits to reduce DoS risk.

This does not guarantee complete system security by itself. Deployment architecture, key management, endpoint security, and runtime integrity are outside library-only guarantees.

## Audit Status

streamseal has not undergone an independent cryptographic security audit.

## Key Management Responsibilities

Users of this library are responsible for:

- Secure private key storage and access control.
- Public key authenticity verification (for example, fingerprint pinning).
- Key rotation procedures and compromised key revocation.
- Transport and application integrity (TLS, CSP, supply-chain controls, etc.).

## Fix and Disclosure Process

- Triage and severity assignment after private report is received.
- Development of a patch and regression tests.
- Coordinated disclosure with a fixed release.
- Public advisory and release notes after patch availability.

## Release Provenance

Current releases are not signed with an external signature key.

Recommended direction:

- Publish from GitHub Actions with npm trusted publishing and provenance.
- Keep release tags and package versions aligned.
- Attach changelog entries to each release.

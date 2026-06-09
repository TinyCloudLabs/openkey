# Security Policy

OpenKey manages Ethereum keys, OAuth flows, passkeys, and TEE-backed signing. Please report vulnerabilities privately.

## Reporting a Vulnerability

Email security reports to security@tinycloud.xyz. Include:

- affected repository, commit, or release
- reproduction steps
- expected impact
- any proof-of-concept code or logs that help verify the issue

Do not open a public GitHub issue for suspected vulnerabilities. TinyCloud Labs will acknowledge valid reports and coordinate remediation before public disclosure.

## Scope

In scope:

- key disclosure or unauthorized signing
- OAuth, passkey, session, or token handling bugs
- attestation or TEE boundary issues
- authorization bypasses in the API or SDKs
- supply-chain or build configuration issues that affect released artifacts

Out of scope:

- social engineering
- denial-of-service without a key, token, or user-data exposure impact
- reports that require access to a user's private keys, browser profile, or device without another vulnerability

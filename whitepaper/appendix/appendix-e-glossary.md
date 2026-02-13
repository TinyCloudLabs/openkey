# Appendix E: Glossary

This appendix defines technical terms used throughout the OpenKey whitepaper and appendices.

## Core Concepts

**Transparent Custody** — A custody model where a third party holds assets but the user can cryptographically verify exactly what code manages those assets and that no party (including the custodian's operators) can access private keys. OpenKey achieves transparent custody through TEE attestation, allowing users to verify the server code before trusting it with key management.

**TEE (Trusted Execution Environment)** — An isolated compute environment where code executes with hardware-enforced confidentiality and integrity. The CPU prevents external observation or tampering, including from privileged software like hypervisors and operating systems. TEEs enable verifiable remote computation.

**TDX (Trust Domain Extensions)** — Intel's VM-level confidential computing technology. TDX creates Trust Domains (TDs) that run entire virtual machines with encrypted memory and hardware isolation. Unlike SGX which isolates individual applications, TDX isolates complete VMs, enabling unmodified workloads to run confidentially.

**dstack** — Phala Network's open-source confidential computing framework, contributed to the Linux Foundation's Confidential Computing Consortium. dstack deploys standard Docker containers into TDX enclaves and provides services for key derivation (KMS), attestation (RA-TLS), and secure configuration.

**KMS (Key Management Service)** — Within dstack, the component that provides deterministic key derivation. The KMS does not store keys; instead, it derives them on-demand using HKDF from a hardware-bound master secret combined with application identity and a derivation path. Each unique path produces a cryptographically independent key.

## Cryptographic Operations

**Sealing** — The process of encrypting data such that only a specific TEE instance can decrypt it. Sealing binds ciphertext to the TEE's code measurement and hardware identity. OpenKey seals private keys using AES-256-GCM with TEE-derived keys, ensuring keys remain encrypted at rest and accessible only within the legitimate TEE.

**Attestation** — Cryptographic proof that code runs inside a genuine TEE. The hardware generates a signed report (quote) containing code measurements, platform state, and user-provided data. Remote parties verify this quote against the hardware vendor's PKI to confirm TEE authenticity.

**HKDF (HMAC-based Key Derivation Function)** — A key derivation function defined in RFC 5869. HKDF expands input key material into multiple cryptographically independent keys using HMAC. dstack uses HKDF-SHA256 to derive application keys from its master secret.

**AES-256-GCM** — Advanced Encryption Standard with 256-bit keys in Galois/Counter Mode. GCM provides authenticated encryption, ensuring both confidentiality and integrity. OpenKey uses AES-256-GCM to seal private keys, detecting any tampering through the authentication tag.

**HPKE (Hybrid Public Key Encryption)** — A standard for public key encryption defined in RFC 9180. HPKE combines asymmetric key encapsulation with symmetric authenticated encryption. OpenKey uses HPKE with X25519 and AES-256-GCM for secure key export, encrypting extracted keys to client-generated public keys.

## Authentication Technologies

**Passkey** — A FIDO2 credential stored in hardware (TPM, Secure Enclave, security key). Passkeys replace passwords with public-key cryptography, providing phishing-resistant authentication because credentials bind to specific origins. OpenKey uses passkeys as a primary authentication factor.

**WebAuthn** — The W3C Web Authentication standard that enables passkey-based authentication in browsers. WebAuthn defines the JavaScript API for creating credentials (registration) and generating assertions (authentication). It supports both platform authenticators (built into devices) and roaming authenticators (external security keys).

**FIDO2** — The overarching standard encompassing WebAuthn (browser API) and CTAP2 (authenticator protocol). FIDO2 enables passwordless authentication using public-key cryptography with hardware-backed credentials. The FIDO Alliance maintains these specifications.

**OAuth 2.1** — The updated OAuth authorization framework that consolidates best practices. OAuth 2.1 mandates PKCE for all clients, removes insecure grant types (implicit, password), and requires exact redirect URI matching. OpenKey uses OAuth 2.1 for "Sign in with Google" integration.

**PKCE (Proof Key for Code Exchange)** — A security extension to OAuth that prevents authorization code interception. The client generates a random code verifier, sends its hash (code challenge) with the authorization request, and proves possession of the verifier during token exchange. Attackers who intercept the authorization code cannot exchange it without the verifier.

## Identity Standards

**DID (Decentralized Identifier)** — A W3C standard for globally unique identifiers that do not require centralized registration. DIDs resolve to DID Documents containing public keys and service endpoints. Various DID methods exist for different use cases (web, blockchain, key-based).

**did:pkh** — A DID method that derives identifiers from blockchain addresses (Public Key Hash). Format: `did:pkh:{chain-namespace}:{chain-id}:{address}`. The did:pkh method requires no registration since the DID exists implicitly from the address. OpenKey uses did:pkh:eip155 for Ethereum-based identities.

**EIP-191 (personal_sign)** — An Ethereum standard for signing arbitrary messages. EIP-191 prefixes messages with `\x19Ethereum Signed Message:\n{length}` before hashing and signing, preventing signed messages from being valid transactions. OpenKey supports EIP-191 signing through its API.

**EIP-712 (Typed Structured Data Signing)** — An Ethereum standard for signing structured data with type information. EIP-712 enables wallets to display human-readable signing requests and prevents cross-protocol replay attacks through domain separation. OpenKey supports EIP-712 signing for DeFi and other typed-data use cases.

## OpenKey-Specific Terms

**MANAGED key** — An Ethereum key whose private material OpenKey generated and sealed within the TEE. OpenKey can sign transactions with MANAGED keys. Users can export MANAGED keys through the export ceremony to take full custody.

**EXTERNAL key** — An Ethereum key registered with OpenKey for address association only. OpenKey does not possess the private key and cannot sign with it. EXTERNAL keys enable unified identity across managed and self-custody addresses.

**Primary key (Key 0)** — The first MANAGED key in a user's account, automatically generated during registration. The primary key has index 0 in the derivation path and typically serves as the user's main identity. OpenKey always generates exactly one primary key per account.

**Key export ceremony** — The multi-step protocol for extracting a private key from TEE custody. The ceremony requires email verification, passkey verification, and a 24-hour waiting period. This friction protects against unauthorized exports while preserving user sovereignty.

**Sealed blob** — A base64-encoded ciphertext containing an encrypted private key. Format: `base64(iv[12] || authTag[16] || ciphertext[N])`. Sealed blobs can only be decrypted by the TEE that created them, using the same code measurement and hardware.

**Derivation path** — A string that determines which key the dstack KMS derives. Format: `openkey/user/{userId}/keys/{keyIndex}`. Different paths produce cryptographically independent keys from the same master secret.

## Attestation Terms

**MRTD (Measurement of Trust Domain)** — A SHA-384 hash computed by the CPU during TDX Trust Domain initialization. MRTD captures the TD's initial memory contents, CPU state, and launching firmware. Verifiers compare MRTD against known-good values to confirm the expected code runs in the TEE.

**DCAP (Data Center Attestation Primitives)** — Intel's infrastructure for offline TDX quote verification. DCAP enables verifiers to validate quotes without contacting Intel's attestation service for each verification, using cached Intel-signed collateral (certificates, TCB info).

**Compose hash** — A hash of the docker-compose.yaml used to deploy an application in dstack. The compose hash appears in attestation evidence, allowing verifiers to confirm not just the code but the entire deployment configuration.

## Related Technologies

**QuorumOS** — A Kubernetes-based TEE orchestration system developed by TinyCloud. QuorumOS manages multi-tenant TEE deployments, handles attestation, and provides namespace isolation. OpenKey can deploy on QuorumOS for production environments.

**SSS (Shamir's Secret Sharing)** — A cryptographic technique that splits a secret into multiple shares, requiring a threshold number to reconstruct. SSS enables distributed key management where no single party holds the complete key. OpenKey does not use SSS directly but may integrate with SSS-based systems.

**MPC-TSS (Multi-Party Computation Threshold Signature Scheme)** — A cryptographic protocol where multiple parties jointly compute signatures without any party knowing the complete private key. MPC-TSS provides distributed signing capabilities. OpenKey's TEE-based approach differs from MPC-TSS by keeping the complete key within hardware isolation rather than distributing it.

**CCC (Confidential Computing Consortium)** — A Linux Foundation project advancing confidential computing technologies. Members include Intel, AMD, Microsoft, Google, and others. dstack is contributed to the CCC, ensuring open governance and broad industry support.

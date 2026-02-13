# Competitive Landscape

> How OpenKey's security model compares to Turnkey, Privy, and Para

## Why This Matters

Key management infrastructure makes a fundamental architectural choice: who can access the user's private key, and under what conditions? The answer determines whether users have real custody or just the appearance of it.

OpenKey is built on a simple premise: **user custody requires verifiable isolation**. If the operator can access keys — even theoretically — it's not user custody. TEEs enforced by open hardware specs and open source code are the most honest path to that guarantee today.

---

## The Landscape

There are three schools of thought in wallet infrastructure:

| Approach | How It Works | Who Uses It |
|----------|-------------|-------------|
| **TEE-only** | Keys live in hardware-isolated enclaves | OpenKey, Turnkey |
| **SSS + TEE hybrid** | Keys split into shares, reconstituted in enclave or browser | Privy |
| **MPC-TSS** | Key never assembled; parties co-sign | Para (formerly Capsule) |

Each involves real tradeoffs. None is zero-trust.

---

## OpenKey: Open Source TEE on dstack

OpenKey generates and seals Ethereum private keys inside a TEE powered by [Phala's dstack](https://github.com/aspect-build/dstack) — a fully open source confidential computing framework and Linux Foundation CCC project.

**How it works:**
1. Key generated inside TEE
2. Sealed with AES-256-GCM using a hardware-derived key (via `dstack.deriveKey()`)
3. Only the encrypted blob stored in Postgres
4. On sign: unseal inside TEE, sign, return signature — key never exposed

**What makes this possible:**
- **dstack** provides the TEE abstraction, attestation, and key derivation
- Runs on **Intel TDX** — an open hardware specification, commercially available, independently auditable
- The entire stack is open source: dstack, OpenKey's TEE package, the API, the SDK

**Trust model:** You trust Intel's TDX hardware and Phala's KMS infrastructure. Both are verifiable via attestation. The operator (us) cannot access keys — the TEE enforces this at the hardware level.

---

## Turnkey — Closest Comparison

Turnkey is the most architecturally similar to OpenKey. Both use TEE-only key management where private keys exist exclusively inside enclaves.

| | OpenKey | Turnkey |
|---|---|---|
| **TEE hardware** | Intel TDX (open spec) | AWS Nitro (proprietary) |
| **Architecture** | Single enclave | 5 specialized enclaves |
| **Key sealing** | AES-256-GCM via dstack | Encrypted to Quorum Key |
| **Policy engine** | Not yet | CEL-based, runs in enclave |
| **Open source** | Full stack | QuorumOS (enclave OS only) |
| **Attestation root** | Intel (open PKI) | AWS (proprietary CA) |
| **Infrastructure** | Decentralizable across operators | Single operator, AWS-only |
| **Reproducible builds** | Via dstack container hashes | QuorumOS + StageX |

**Where Turnkey leads:** Mature policy engine for fine-grained signing rules. Multi-enclave separation (Policy Engine, Signer, Notarizer, Parser, TLS Fetcher) provides defense-in-depth. Production-hardened across many integrations.

**Where OpenKey leads:**
- **Open hardware.** Intel TDX is an open specification. Anyone can inspect the hardware design. AWS Nitro's hypervisor is proprietary — its attestation PKI and implementation [have "many more avenues of attack" that are difficult to assess](https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/) (Trail of Bits).
- **Fully open source.** OpenKey's entire stack — TEE package, API, SDK — is open. dstack is a [Linux Foundation Confidential Computing Consortium project](https://confidentialcomputing.io/). Turnkey open-sourced QuorumOS but the enclave application code, API, and infrastructure remain proprietary.
- **No vendor lock-in.** dstack runs on any TDX-compatible hardware across clouds and on-prem. Turnkey is locked to AWS Nitro.
- **Decentralizable.** dstack's architecture allows multiple independent operators to run TEE workers. Turnkey is a single centralized operator.

**Sources:**
- [Turnkey Whitepaper — Architecture](https://whitepaper.turnkey.com/architecture)
- [Turnkey — Why We Built Beyond MPC](https://www.turnkey.com/blog/proven-security-turnkey-built-beyond-mpc)
- [QuorumOS (GitHub)](https://github.com/tkhq/qos)
- [Trail of Bits — Notes on AWS Nitro Enclaves Attack Surface](https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/)

---

## Privy — SSS Hybrid, Default Custodial

Privy uses Shamir's Secret Sharing to split keys into shares, with an optional TEE layer for server-side wallets.

| | OpenKey | Privy |
|---|---|---|
| **Approach** | TEE-only | SSS (2-of-3) + optional TEE |
| **Key reconstituted?** | In TEE only | In browser iframe or Nitro enclave |
| **Default custody** | Non-custodial (TEE enforced) | **Privy holds 2-of-3 shares by default** |
| **TEE hardware** | Intel TDX (open) | AWS Nitro (proprietary) |
| **Open source** | Full stack | SSS library only |
| **Verifiability** | TEE attestation | None for client-side wallets |
| **Scale** | Earlier stage | 75M+ accounts |

**The custody problem:** In Privy's default "automatic recovery" mode, Privy holds the auth share AND the recovery share — 2 of 3 shares, mathematically sufficient to reconstruct any user's private key. Users must actively opt into password-based or cloud-based recovery to get meaningful self-custody. Most don't.

This is the core difference. **OpenKey's TEE model means the operator cannot access keys, period** — it's enforced by hardware, not by policy. Privy's SSS model means the operator *chooses* not to access keys, and in the default configuration, they technically can.

**Other differences:**
- Privy's client-side wallets depend on browser iframe isolation — browser vulnerabilities break the model entirely. OpenKey's keys never touch the browser.
- Privy's infrastructure (iframe code, enclave code, API) is closed source. You cannot verify what runs. OpenKey is fully open source.
- Privy was [acquired by Stripe in June 2025](https://www.coindesk.com/business/2025/06/11/stripe-to-acquire-crypto-wallet-startup-privy-in-bid-to-expand-web3-capabilities/), raising questions about regulatory pressure on key access under a traditional fintech parent.

**Where Privy leads:** Scale (75M+ accounts, 1500+ apps), flexible client-side + server-side models, full key export UX.

**Sources:**
- [Privy — How Embedded Wallets Work](https://privy.io/blog/how-privy-embedded-wallets-work)
- [Privy — Architecture Breakdown](https://privy.io/blog/embedded-wallet-architecture-breakdown)
- [Privy — SSS Deep Dive](https://privy.io/blog/shamir-secret-sharing-deep-dive)
- [Privy Security Docs — Architecture](https://docs.privy.io/security/wallet-infrastructure/architecture)
- [a16z — Wallet Security: The Non-Custodial Fallacy](https://a16zcrypto.com/posts/article/wallet-security-non-custodial-fallacy/)

---

## Para (formerly Capsule) — MPC, Fundamentally Different

Para uses 2-of-2 MPC-TSS (threshold signatures) where the private key is never assembled — not even inside a TEE.

| | OpenKey | Para |
|---|---|---|
| **Approach** | TEE (key in enclave) | MPC-TSS (key never exists whole) |
| **Key exists?** | Yes, in TEE memory | Never assembled |
| **Hardware trust** | Intel TDX | None (pure cryptography) |
| **Provider required to sign?** | No | **Yes (2-of-2 co-signer)** |
| **Censorship resistance** | Strong (key sealed locally) | Weak (Para must co-sign) |
| **Signing latency** | Low (single TEE op) | Higher (MPC roundtrips) |
| **Open source** | Full stack | MPC library only |

**The theoretical advantage:** Para's key never exists as a complete entity, anywhere. This is the mathematically strongest guarantee against key theft. Even a compromised TEE can't leak what doesn't exist.

**The practical problem:** 2-of-2 MPC means **Para is a required co-signer for every transaction**. If Para's servers go down, user wallets freeze. If Para decides to censor a user, they can refuse to co-sign. This is a liveness and censorship dependency that directly undermines user custody.

OpenKey's model is different: your key is sealed in the TEE. The operator can't access it, but they also can't prevent you from using it while the service is running. The key exists — it's just hardware-isolated.

**Other concerns:**
- Para's [TSShock vulnerability disclosure](https://www.fireblocks.com/blog/tsshock-vulnerabilities-discovered/) (Fireblocks, 2023) showed that a cheating participant in certain MPC protocols can extract the other party's key share. Para migrated from CGGMP to DKLS19 partly in response, but the episode highlights MPC's implementation complexity.
- No published security audit for Para's core MPC implementation.
- Recovery is complex: 48-hour delays, recovery secrets, backup devices.

**Where Para leads:** The "key never assembled" property is a real and meaningful security advantage in theory. No hardware trust assumptions.

**Sources:**
- [Para (Capsule) Documentation](https://docs.usecapsule.com/)
- [Fireblocks — TSShock: MPC Vulnerabilities](https://www.fireblocks.com/blog/tsshock-vulnerabilities-discovered/)
- [Phala — dstack vs AWS Nitro](https://phala.com/compare/phala-vs-aws-nitro)

---

## Why Open Source Matters Here

Key management is a trust problem. Users are trusting infrastructure with their private keys — the most sensitive data in crypto. In this context, "trust us" is not good enough.

**What open source gives you:**
- **Audit the code that holds your keys.** OpenKey's TEE package, API server, and SDK are all open source. Anyone can verify that the sealing, unsealing, and signing logic does what it claims.
- **Verify the TEE runtime.** dstack is a Linux Foundation CCC project with public code and security audits. The TEE attestation proves the running code matches the open source repository.
- **Fork and self-host.** If OpenKey disappears tomorrow, you can deploy the same code on any TDX-compatible hardware. Your sealed keys remain decryptable by the same attested code.
- **No proprietary black boxes.** Turnkey's QuorumOS is open but their enclave apps aren't. Privy's SSS library is open but their iframe and enclave code aren't. Para's MPC library is open but their infrastructure isn't. OpenKey is open top to bottom.

This is made possible by **dstack**. Before dstack, building on TEEs meant writing SGX enclaves in C or locking into AWS Nitro's proprietary SDK. dstack lets you deploy standard containers into TDX enclaves with attestation and key derivation built in — and it's fully open source under the Linux Foundation. OpenKey is a project that couldn't exist without it.

---

## Summary

| | OpenKey | Turnkey | Privy | Para |
|---|---|---|---|---|
| **Can operator access keys?** | No (TEE) | No (TEE) | Yes (default config) | No (MPC) |
| **Key ever assembled?** | In TEE only | In TEE only | In browser/TEE | Never |
| **Hardware trust** | Intel TDX (open) | AWS Nitro (proprietary) | AWS Nitro (proprietary) | None |
| **Open source** | **Full stack** | Partial | Partial | Partial |
| **Vendor lock-in** | Low | High (AWS) | High (AWS) | Low |
| **Provider liveness required?** | No | No | Partial (2-of-3) | **Yes (2-of-2)** |
| **Decentralizable** | Yes (dstack) | No | No | No |
| **Made possible by** | **dstack (LF CCC)** | QuorumOS + Nitro | SSS + Nitro | DKLS19 protocol |

OpenKey bets that **open hardware, open source, and real TEE isolation** — made possible by dstack — is the most honest path to user custody. Not the most complex architecture, not the most theoretical guarantees, but the most verifiable.

# dstack KMS vs Turnkey's Quorum Key System

> A deep-dive comparison of the two leading TEE-based key management architectures

## The Problem Both Solve

Pure hardware sealing (CPU fuses → sealing key) locks secrets to one physical machine. If that CPU dies, keys are gone. For cloud-deployed key management, you need a way to provision keys to *any* attested enclave — not just the one that generated them.

dstack and Turnkey solve this differently.

---

## dstack: Deterministic KMS Derivation

```
Hardware fuses + Code measurement + Path
         ↓
    HKDF derivation (inside TEE)
         ↓
    Deterministic key — no storage needed
```

**How it works:**

1. App calls `dstack.deriveKey("openkey/user/123/keys")` via Unix socket (`/var/run/dstack.sock`)
2. dstack KMS (running in TEE) verifies the caller is an attested app (code hash matches)
3. KMS derives key using HKDF from: **master secret** (hardware-bound) + **app identity** (compose hash) + **path** (user-specific)
4. Returns 32-byte key. Same inputs → same output. **Nothing stored.**

**OpenKey's usage:**

```typescript
// Seal a key
const sealingKey = await dstack.deriveKey(`openkey/user/${userId}/keys`);
const sealedBlob = AES_GCM_encrypt(privateKey, sha256(sealingKey));
// Store sealedBlob in Postgres

// Unseal and sign
const sealingKey = await dstack.deriveKey(`openkey/user/${userId}/keys`);
const privateKey = AES_GCM_decrypt(sealedBlob, sha256(sealingKey));
const signature = sign(message, privateKey);
```

**Properties:**

- **Stateless** — KMS has no key database. Keys are computed on demand from inputs.
- **Deterministic** — any attested instance of the same app on any TDX hardware derives identical keys
- **Path-isolated** — different paths = cryptographically independent keys
- **Single trust boundary** — one TEE, one derivation call
- **Auto-provisioning** — no human ceremony at boot. Deploy container, dstack handles the rest.

---

## Turnkey: Quorum Key + Multi-Enclave Architecture

```
Quorum Members (humans) hold Shamir shares of Quorum Key
         ↓
    Reconstructed at boot inside enclave
         ↓
    User keys encrypted to Quorum Key
         ↓
    5 enclaves pass signed messages via untrusted Coordinator
```

**How it works:**

1. **Quorum Key creation**: Generated inside an enclave, immediately Shamir-split among N human Quorum Members (M-of-N threshold). Full key destroyed after splitting.
2. **Enclave boot**: Quorum Members provide their shares → Quorum Key reconstructed inside enclave → becomes the master encryption key
3. **Key generation**: Signer enclave generates user key using Nitro Secure Module entropy, encrypts it to the Quorum Key, returns encrypted blob for storage
4. **Signing**: Policy Engine enclave authenticates + authorizes request → produces signed Ruling → Signer enclave verifies Ruling + Notarization → decrypts key using Quorum Key → signs → returns signature
5. **Integrity**: Notarizer enclave signs all organization data with timestamps. Stale or tampered data rejected.

**Five enclaves, each with a specific role:**

| Enclave | Role | Why Separate |
|---------|------|-------------|
| **Policy Engine** | Authenticates, evaluates CEL policies, produces Rulings | Auth logic isolated from key material |
| **Signer** | Generates keys, signs transactions | Only enclave that touches private keys |
| **Notarizer** | Signs org data for integrity | Tamper detection independent of Signer |
| **Parser** | Extracts tx metadata (EVM, Solana) | Feed context into Policy Engine |
| **TLS Fetcher** | Makes verified HTTPS requests | Only enclave with network access |

Enclaves cannot communicate directly. An untrusted Coordinator routes messages. Each enclave's output is signed with its Quorum Key share and verified by recipients.

**Properties:**

- **Human-rooted** — Quorum Members (humans) hold the root secret via Shamir shares
- **Stateful** — encrypted keys stored in Postgres, Quorum Key provisioned at boot
- **Multi-enclave separation** — Signer can't act alone; needs valid Ruling from Policy Engine + Notarized org data
- **Defense in depth** — 5 trust boundaries with cryptographic message passing
- **In-enclave policy** — CEL policy engine runs inside the TEE, not outside it

---

## Side-by-Side

| Dimension | dstack KMS | Turnkey Quorum Key |
|-----------|-----------|-------------------|
| **Root of trust** | Hardware fuses (CPU silicon) | Human quorum (Shamir shares) |
| **Key derivation** | Deterministic HKDF (stateless) | Encrypt-to-Quorum-Key (stateful) |
| **Key storage in KMS** | None — derived on demand | Encrypted blobs in Postgres |
| **Boot provisioning** | Automatic (hardware-derived) | Requires quorum ceremony |
| **Hardware migration** | Automatic across any TDX hardware | Requires new quorum ceremony |
| **Enclave architecture** | Single TEE | 5 specialized enclaves |
| **Trust boundaries** | 1 (app TEE ↔ KMS TEE) | 5 (Policy, Signer, Notarizer, Parser, TLS) |
| **TEE hardware** | Intel TDX (open spec) | AWS Nitro (proprietary) |
| **Integrity protection** | TEE attestation | Notarizer signatures + attestation |
| **Policy enforcement** | Application-level (outside TEE) | CEL engine inside enclave |
| **Operational complexity** | Low (deploy container) | High (quorum ceremonies, 5 enclaves) |
| **Open source** | Full stack (dstack = LF CCC) | QuorumOS only |

---

## What Each Approach Gets Right

### dstack: Simplicity and portability

- **No human ceremony to boot.** No shares to manage, no quorum coordination. Deploy a container, dstack handles key provisioning via attestation.
- **No key database.** Deterministic derivation means nothing to sync, backup, or lose. Same app + same path = same key, anywhere.
- **Hardware-portable.** Works on any TDX-compatible hardware — AWS, GCP, Azure, on-prem. Not locked to one cloud vendor.
- **Open and verifiable.** dstack is a Linux Foundation Confidential Computing Consortium project. The full derivation path is auditable.

### Turnkey: Defense in depth

- **Multi-enclave separation.** The Signer can't unilaterally decrypt keys — it needs a valid Policy Engine ruling AND Notarized org data. Compromise one enclave and you still don't have keys.
- **Tamper detection.** The Notarizer catches database tampering that a single-enclave model wouldn't detect. A malicious DBA modifying encrypted blobs is caught by stale/invalid Notarization signatures.
- **In-enclave policy engine.** CEL-based policies (spending limits, multi-approval, destination restrictions) evaluated inside the TEE. Policy enforcement is part of the trust boundary, not just application logic.
- **Human root of trust.** The Quorum Key is rooted in human shareholders, not just hardware. Adds a social coordination layer that's independent of any single hardware vendor.

---

## The Honest Tradeoffs

### dstack's centralization risk

The trust chain: **Intel TDX hardware → Phala KMS infrastructure → OpenKey app**.

If Phala's KMS is compromised (or Phala is coerced), derived keys could be logged during the derivation call. There's no cryptographic proof that the KMS *isn't* logging. The mitigations are:

1. dstack is open source — you can audit the KMS code
2. Attestation proves what code is running in the KMS enclave
3. Phala's roadmap includes decentralizing KMS across independent operators

But today, it's a centralized trust point. This is explicitly documented in OpenKey's [TEE overview](tee-overview.md):

> *"dstack adds trust in Phala's infrastructure. The guarantee: if all parties are honest, then even Phala can't see your secrets. It's better than trusting AWS directly, but not zero trust."*

### Turnkey's proprietary hardware dependency

The trust chain: **AWS Nitro hardware → Quorum Key holders → Turnkey enclave code**.

AWS Nitro's hypervisor is proprietary. The attestation PKI, the memory isolation mechanism, and the hardware implementation cannot be independently audited. Trail of Bits [noted](https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/) the Nitro system has "many more avenues of attack" that are difficult to assess compared to Intel SGX/TDX.

Additionally, the Quorum Key is a single root secret. If the quorum members are compromised or coerced, the entire system's keys are compromised — regardless of how many enclaves sit on top.

### Shared limitation

Both architectures share the fundamental TEE caveat: **private keys exist in plaintext in enclave memory during signing.** If the TEE itself is compromised (side channel attack, hardware bug, firmware vulnerability), keys are exposed regardless of the KMS architecture above it.

---

## Architectural Implications

### For OpenKey

dstack's model is a **bet on hardware trust + open source**. The security argument is:

1. Intel TDX is an open spec — security researchers worldwide scrutinize it
2. dstack is fully open source and auditable
3. Attestation provides cryptographic proof of what's running
4. Deterministic derivation eliminates an entire class of state management bugs

The gap: no in-enclave policy engine, no multi-enclave separation, no tamper-detecting Notarizer. These are features, not architectural limitations — they can be built on top of dstack.

### For Turnkey

Turnkey's model is a **bet on defense in depth + operational sophistication**. The security argument is:

1. Five enclaves means no single point of compromise gives you keys
2. Human-rooted Quorum Key adds social coordination security
3. In-enclave policy engine makes authorization tamper-proof
4. Notarizer catches database-level attacks

The gap: proprietary hardware (AWS Nitro), vendor lock-in, quorum ceremony operational complexity, and a closed-source infrastructure beyond QuorumOS.

---

## Sources

- [Turnkey Whitepaper — Architecture](https://whitepaper.turnkey.com/architecture)
- [Turnkey Whitepaper — Foundations](https://whitepaper.turnkey.com/foundations)
- [Turnkey — Why We Built Beyond MPC](https://www.turnkey.com/blog/proven-security-turnkey-built-beyond-mpc)
- [QuorumOS (GitHub)](https://github.com/tkhq/qos)
- [Trail of Bits — Notes on AWS Nitro Enclaves Attack Surface](https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/)
- [dstack — Zero Trust Framework for Confidential Containers](https://phala.com/posts/Dstack-A-Zero-Trust-Framework-for-Confidential-Containers)
- [Phala Cloud vs AWS Nitro Enclaves](https://phala.com/compare/phala-vs-aws-nitro)
- [dstack GitHub](https://github.com/aspect-build/dstack)
- [OpenKey TEE Overview](tee-overview.md)

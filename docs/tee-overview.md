# TEE Overview

> How OpenKey uses Trusted Execution Environments to secure your keys

## What is a TEE?

A **Trusted Execution Environment (TEE)** is isolated compute where secrets can be created and used without anyone - including the server operator - being able to access them.

Key properties:
- **Isolated execution**: Code runs in an encrypted memory region
- **Inaccessible secrets**: Not even the cloud provider can read the data inside
- **Attestation**: Cryptographic proof of what code is running

## Who Can Access TEE Secrets?

| Actor | Can Access? | Why |
|-------|-------------|-----|
| Code inside TEE | Yes | It's the only thing that can |
| Cloud provider | No | Memory is encrypted, they see ciphertext |
| Developer who deployed | No | No SSH, no debug access |
| Intel/AMD (chip manufacturer) | Theoretically | They sign attestation keys |

## How Attestation Works

When a TEE proves itself to a verifier:

```
┌─────────────┐     1. "Prove yourself"      ┌─────────────┐
│   Verifier  │ ──────────────────────────►  │     TEE     │
│             │                              │   Enclave   │
│             │  2. Attestation Report       │             │
│             │ ◄──────────────────────────  │             │
└─────────────┘                              └─────────────┘
       │
       ▼
  3. Verify:
     - Signature from Intel/AMD (proves real hardware)
     - Code hash matches expected (proves right code)
     - Security version not outdated (proves patched)
```

The attestation signature uses keys embedded in the CPU during manufacturing. A VM or emulator cannot produce a valid attestation.

## Sealing: Persisting Secrets

When a TEE restarts, secrets in memory are lost. **Sealing** encrypts secrets so only that TEE can decrypt them later.

The TEE doesn't store a key - it **derives** the key deterministically from:
1. **Hardware fuses** - Unique secrets burned into the CPU
2. **Code measurement** - Hash of the running code
3. **Policy** - MRENCLAVE (exact code) or MRSIGNER (developer identity)

```
On seal:
  sealing_key = CPU_DERIVE(hardware_secret, code_identity)
  encrypted_blob = ENCRYPT(sealing_key, your_secret)
  // Save encrypted_blob to disk

On restart:
  sealing_key = CPU_DERIVE(hardware_secret, code_identity)  // Same key!
  your_secret = DECRYPT(sealing_key, encrypted_blob)
```

Same code on same CPU = same sealing key. The key is never stored anywhere.

## Migration: Running on Different Machines

Pure hardware sealing locks data to one CPU. For cloud deployments, a **Key Management Service (KMS)** provisions secrets to any attested TEE:

```
┌─────────────────────────────────────────────┐
│              Phala Network                   │
│  ┌─────────────┐    ┌─────────────────────┐ │
│  │ KMS/RA      │    │  TEE Worker Nodes   │ │
│  │ (Key        │◄──►│  (Run your code)    │ │
│  │  Authority) │    │                     │ │
│  └─────────────┘    └─────────────────────┘ │
└─────────────────────────────────────────────┘
         │
         │ Remote Attestation
         ▼
┌─────────────────┐
│  Your dstack    │  ← You deploy this
│  Application    │
└─────────────────┘
```

When your TEE starts:
1. It attests to the KMS
2. KMS verifies: "Yes, this is the right code in a real TEE"
3. KMS sends the app's secrets to the TEE
4. Works on any physical machine that passes attestation

## Trust Model

What you're trusting:

| Trust Assumption | What Could Go Wrong | Mitigation |
|-----------------|---------------------|------------|
| AMD/Intel hardware | Backdoored chips | Reputation, security research |
| Phala's KMS | Malicious operator | Attestation is verifiable |
| Phala infrastructure | Availability issues | Decentralization goal |
| Your own code | Bugs that leak secrets | Code review, minimal TCB |
| Side channels | Spectre/timing attacks | Hardware mitigations |

**The honest assessment:**
- TEEs are not "trust nobody" - you trust the hardware vendor
- dstack adds trust in Phala's infrastructure
- The guarantee: "If all parties are honest, then even Phala can't see your secrets"
- It's better than trusting AWS directly, but not zero trust

---

## How OpenKey Uses dstack

OpenKey uses Phala's `@phala/dstack-sdk` to secure Ethereum private keys.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     OpenKey API                              │
│                                                              │
│   POST /keys/generate                                        │
│   ┌──────────────────────────────────────────────────────┐  │
│   │ 1. Generate random private key (viem)                │  │
│   │ 2. sealingKey = dstack.deriveKey("openkey/user/X")   │  │
│   │ 3. sealedBlob = AES-GCM(privateKey, sealingKey)      │  │
│   │ 4. Store sealedBlob in Postgres                      │  │
│   └──────────────────────────────────────────────────────┘  │
│                                                              │
│   POST /keys/:id/sign                                        │
│   ┌──────────────────────────────────────────────────────┐  │
│   │ 1. Fetch sealedBlob from DB                          │  │
│   │ 2. sealingKey = dstack.deriveKey("openkey/user/X")   │  │
│   │ 3. privateKey = AES-GCM-decrypt(sealedBlob)          │  │
│   │ 4. Sign message, return signature                    │  │
│   └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Key Files

| File | Purpose |
|------|---------|
| `packages/tee/src/index.ts` | TEE abstraction - wraps dstack SDK |
| `apps/api/src/routes/keys.ts` | Uses TEE for key gen/signing |

### The TEE Package

```typescript
// packages/tee/src/index.ts

// Production - real dstack
function createProductionClient(): TeeClient {
  const getTappdClient = async () => {
    const { TappdClient } = await import('@phala/dstack-sdk');
    return new TappdClient();
  };

  return {
    async deriveKey(path: string): Promise<Uint8Array> {
      const client = await getTappdClient();
      const result = await client.deriveKey(path);
      return result.asUint8Array();
    },
    async getQuote(data: string): Promise<string> {
      const client = await getTappdClient();
      const result = await client.tdxQuote(data);
      return result.quote;
    },
    isInTee: () => true,
  };
}

// Development - mock with deterministic keys
function createMockClient(): TeeClient {
  const devKey = process.env.DEV_SEALING_KEY || 'openkey-dev-sealing-key-32b!';

  return {
    async deriveKey(path: string): Promise<Uint8Array> {
      // SHA256(devKey + path) - deterministic for testing
      return sha256(devKey + path);
    },
    async getQuote(_data: string): Promise<string> {
      return 'mock-tdx-quote-for-development';
    },
    isInTee: () => false,
  };
}
```

### Usage in Keys Route

```typescript
// apps/api/src/routes/keys.ts

// Generate a new key
const sealingKey = await tee.deriveKey(`openkey/user/${user.id}/keys`);
const sealedBlob = await seal(privateKeyHex, sealingKey);
// Store sealedBlob in DB

// Sign a message
const sealingKey = await tee.deriveKey(`openkey/user/${user.id}/keys`);
const privateKey = await unseal(key.sealedBlob, sealingKey);
const signature = await account.signMessage({ message });
```

### Key Insight

**dstack's `deriveKey()` is deterministic:**
- Same path → same key (across restarts, machines)
- Path includes user ID → each user gets unique sealing key
- Only code running in an attested TEE can derive the real keys
- In dev mode, uses SHA256 hash instead (not secure, but deterministic for testing)

### Attestation Endpoint

Clients can verify a key is in a real TEE:

```typescript
// GET /keys/:keyId/quote
const quote = await tee.getQuote(JSON.stringify({
  address: key.address,
  userId: user.id,
  timestamp: Date.now(),
}));

return { quote, isInTee: tee.isInTee() };
```

### Environment Configuration

| Variable | Value | Description |
|----------|-------|-------------|
| `TEE_MODE` | `production` | Use real dstack SDK |
| `TEE_MODE` | `development` | Use mock with `DEV_SEALING_KEY` |
| `DEV_SEALING_KEY` | any string | Deterministic key for local dev |

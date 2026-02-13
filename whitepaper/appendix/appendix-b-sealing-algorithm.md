# Appendix B: Sealing Algorithm

This appendix specifies the cryptographic algorithms and data formats used to seal private keys within the TEE. Sealing binds encrypted data to a specific TEE instance and code measurement, ensuring that only the legitimate OpenKey deployment can access the sealed material.

## AES-256-GCM Sealing Format

### Algorithm Selection

OpenKey uses AES-256-GCM (Galois/Counter Mode) for sealing private keys. This choice provides:

- **Authenticated encryption**: GCM mode produces an authentication tag that detects any tampering with the ciphertext.
- **Performance**: AES-GCM benefits from hardware acceleration (AES-NI) on modern CPUs.
- **Standardization**: AES-256-GCM is widely deployed and thoroughly analyzed.

### Cryptographic Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-GCM |
| Key size | 256 bits (32 bytes) |
| IV (nonce) size | 96 bits (12 bytes) |
| Authentication tag size | 128 bits (16 bytes) |

The 12-byte IV provides the recommended size for GCM mode. Each seal operation generates a fresh random IV, ensuring that identical plaintexts produce different ciphertexts.

### Sealed Blob Format

The sealed blob concatenates the IV, authentication tag, and ciphertext, then base64-encodes the result:

```
sealed = base64(iv || authTag || ciphertext)
```

Binary layout:

```
Offset  Length  Field
0       12      IV (initialization vector)
12      16      Authentication tag
28      N       Ciphertext (same length as plaintext)
```

Total overhead: 28 bytes before base64 encoding. After base64 encoding, the overhead becomes approximately 38 characters (28 * 4/3, rounded up).

For a 32-byte Ethereum private key, the sealed blob consumes approximately 80 characters of storage.

### Implementation

```typescript
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

/**
 * Seal plaintext data using AES-256-GCM.
 *
 * @param data - The plaintext string to seal
 * @param sealingKey - 32-byte key derived from TEE
 * @returns Base64-encoded sealed blob
 */
export async function seal(data: string, sealingKey: Uint8Array): Promise<string> {
  // Generate random IV for this seal operation
  const iv = randomBytes(12);

  // Create cipher with derived key
  const cipher = createCipheriv('aes-256-gcm', sealingKey, iv);

  // Encrypt the plaintext
  const encrypted = Buffer.concat([
    cipher.update(data, 'utf8'),
    cipher.final()
  ]);

  // Extract authentication tag
  const authTag = cipher.getAuthTag();

  // Concatenate: IV || authTag || ciphertext
  const sealed = Buffer.concat([iv, authTag, encrypted]);

  return sealed.toString('base64');
}

/**
 * Unseal a sealed blob using AES-256-GCM.
 *
 * @param sealedData - Base64-encoded sealed blob
 * @param sealingKey - 32-byte key derived from TEE (must match seal key)
 * @returns Original plaintext string
 * @throws Error if authentication fails (tampered or wrong key)
 */
export async function unseal(sealedData: string, sealingKey: Uint8Array): Promise<string> {
  // Decode base64 blob
  const blob = Buffer.from(sealedData, 'base64');

  // Extract components
  const iv = blob.subarray(0, 12);
  const authTag = blob.subarray(12, 28);
  const encrypted = blob.subarray(28);

  // Create decipher with derived key
  const decipher = createDecipheriv('aes-256-gcm', sealingKey, iv);
  decipher.setAuthTag(authTag);

  // Decrypt and verify authentication tag
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()  // Throws if auth tag verification fails
  ]);

  return decrypted.toString('utf8');
}
```

### Security Properties

1. **Confidentiality**: Without the sealing key, the ciphertext reveals nothing about the plaintext.

2. **Integrity**: The authentication tag detects any modification to the IV, ciphertext, or tag itself. Attempting to unseal tampered data throws an authentication error.

3. **Binding to TEE**: The sealing key derives from the TEE's hardware-bound master secret and code measurement. Only the same OpenKey deployment on the same TEE hardware can produce the same sealing key.

4. **No key reuse across seals**: Each seal operation uses a fresh random IV, ensuring that sealing the same key twice produces different ciphertexts.

## HKDF Key Derivation Parameters

### Algorithm Overview

HKDF (HMAC-based Key Derivation Function, RFC 5869) extracts and expands cryptographic keys from input key material. dstack uses HKDF internally to derive application-specific keys from its master secret.

The HKDF process has two stages:

1. **Extract**: Combines input key material with a salt to produce a pseudorandom key
2. **Expand**: Uses the pseudorandom key and info string to generate output key material

### dstack HKDF Parameters

| Parameter | Value |
|-----------|-------|
| Hash function | SHA-256 |
| Input Key Material (IKM) | dstack master secret |
| Salt | Compose hash (deployment configuration) |
| Info | Derivation path (application-specified) |
| Output length | 32 bytes (256 bits) |

### Master Secret Origin

The dstack master secret derives from:

1. **CPU fuses**: Permanent values burned into the processor during manufacturing
2. **Platform configuration**: Measurements of the firmware and TDX module
3. **TD measurement**: Hash of the Trust Domain's initial state

This derivation occurs entirely within the CPU's trusted computing base. The master secret never exists in cleartext outside the processor, and Intel cannot extract it from shipped hardware.

### Compose Hash

The compose hash binds derived keys to a specific deployment configuration:

```
compose_hash = SHA256(canonical(docker-compose.yaml))
```

The canonicalization ensures deterministic hashing regardless of YAML formatting. This binding means:

- Changing any container image changes the compose hash
- Changing environment variables changes the compose hash
- Changing exposed ports, volumes, or other configuration changes the compose hash

If an operator modifies the deployment configuration, all previously sealed data becomes inaccessible because the sealing keys change.

### Derivation Path

The derivation path provides application-level key separation. OpenKey uses structured paths:

```
openkey/user/{userId}/keys/{keyIndex}
```

Components:

| Component | Purpose |
|-----------|---------|
| `openkey` | Protocol namespace, distinguishes from other dstack apps |
| `user/{userId}` | User scope, isolates keys between users |
| `keys/{keyIndex}` | Per-key scope, enables distinct sealing keys per Ethereum key |

### Current Implementation vs Specification

The current OpenKey implementation uses a simplified path:

```
openkey/user/{userId}/keys
```

This means all keys for a user share the same sealing key. The specification recommends per-key paths for forward security, allowing future migrations without breaking existing sealed blobs.

Migration strategy:
1. New keys use per-key paths: `openkey/user/{userId}/keys/{keyIndex}`
2. Existing sealed blobs continue using the legacy path
3. A key record tracks which path version was used for sealing

### Derivation Security Properties

Different paths produce cryptographically independent keys:

```typescript
// These derive completely different 32-byte keys
await client.deriveKey('openkey/user/abc123/keys/0');  // Key A
await client.deriveKey('openkey/user/abc123/keys/1');  // Key B
await client.deriveKey('openkey/user/xyz789/keys/0');  // Key C
```

Even with knowledge of derived Key A, an attacker cannot compute Key B or Key C without access to the master secret inside the TEE.

## Per-Key Derivation Path Schema

### Path Format Specification

```
openkey/user/{userId}/keys/{keyIndex}
```

| Field | Type | Description |
|-------|------|-------------|
| userId | string | CUID generated by Prisma (e.g., `cm7gtabde0000uspr8i19sn82`) |
| keyIndex | integer | Zero-indexed key number for this user |

### Examples

```
openkey/user/cm7gtabde0000uspr8i19sn82/keys/0   # User's primary key
openkey/user/cm7gtabde0000uspr8i19sn82/keys/1   # User's second key
openkey/user/cm7gtabde0000uspr8i19sn82/keys/2   # User's third key
```

### Key Index Assignment

Key indices assign sequentially within a user's account:

1. First key created receives index 0 (the primary key)
2. Second key created receives index 1
3. Indices never reuse, even after key deletion

The database tracks the next available index per user, preventing index collisions.

### Rationale for Per-Key Paths

Using distinct derivation paths for each key provides:

1. **Isolation**: Compromise of one sealed blob's encryption does not affect others
2. **Auditability**: Each key has a unique derivation path recorded in the database
3. **Future flexibility**: Enables key-specific policies or rotation schemes

## Sealed Blob Storage

### Database Schema

Sealed blobs persist in PostgreSQL:

```sql
CREATE TABLE ethereum_keys (
  id            TEXT PRIMARY KEY,      -- CUID
  user_id       TEXT NOT NULL,         -- Foreign key to users
  address       TEXT NOT NULL,         -- Ethereum address (0x...)
  sealed_blob   TEXT,                  -- Base64-encoded sealed key (nullable for EXTERNAL)
  key_type      TEXT NOT NULL,         -- 'MANAGED' or 'EXTERNAL'
  key_index     INTEGER NOT NULL,      -- Derivation path index
  label         TEXT,                  -- User-provided label
  created_at    TIMESTAMP NOT NULL,
  updated_at    TIMESTAMP NOT NULL,

  CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE(user_id, key_index)
);
```

### Storage Considerations

**Nullable sealed_blob**: EXTERNAL keys (watch-only) have no sealed blob since OpenKey does not possess their private keys.

**No additional encryption**: The sealed blob provides all necessary protection. Database-level encryption adds defense in depth but does not strengthen the security model since the sealing key exists only inside the TEE.

**Index on user_id**: Efficient lookup of all keys belonging to a user.

**Unique constraint**: Prevents accidental key index reuse within a user's account.

### Backup and Recovery

Sealed blobs can safely back up to external storage:

- Without access to the TEE's sealing key, backed-up blobs remain encrypted
- Restoring blobs to the same OpenKey deployment (same compose hash, same hardware) restores access
- Restoring to a different deployment produces different sealing keys, making the blobs inaccessible

This property provides both data durability and security: backups are useless to attackers but valuable for disaster recovery within the same TEE environment.

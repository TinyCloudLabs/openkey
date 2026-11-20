// Read-only access to the pre-move Phala app root (root epoch 0). TC-3554, K1.
//
// DO NOT MERGE: this module exists to unseal records that were sealed before
// Phala moved this app to a new KMS root. It never seals, and it never falls
// back to the current root.
//
// Before the move every sealing key was
//   sha256(v0 GetKey(path).key) = sha256(HKDF-SHA256(salt "RATLS", ikm k256_key, info path, 32))
// where k256_key is the app's secp256k1 key under the root of that day (see
// tests/dstack-key-derivation.kat.test.ts). The KMS will still hand out that
// k256_key for root epoch 0 to an attested guest (`KMS.GetAppKey{root_epoch: 0}`).
// This module checks what comes back before any byte of it is used, and
// mirrors the node's spec (node-design-bridge.md, "The shared piece"):
//   (a) the response says root_epoch == 0 (and app_epoch == 0);
//   (b) k256_signature is a low-S signature over
//       keccak256("dstack-kms-issued" ":" app_id app_root_pub)
//       under the PINNED epoch-0 KMS root public key;
//   (c) a canary: at least one known sealed record unseals under the result.
// Any failure throws LegacyRootError. The derived root stays in this closure.
import { createHash, hkdfSync } from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256 } from 'viem';
import { unseal } from './index';

export type LegacyRootErrorCode =
  | 'config_invalid'
  | 'kms_refused'
  | 'response_invalid'
  | 'epoch_mismatch'
  | 'signature_invalid'
  | 'canary_failed';

/**
 * Carries a closed `code` and a fixed message, so a log line can say what
 * failed without carrying KMS output or key material.
 */
export class LegacyRootError extends Error {
  readonly code: LegacyRootErrorCode;
  constructor(code: LegacyRootErrorCode, message: string) {
    super(message);
    this.name = 'LegacyRootError';
    this.code = code;
  }
}

export interface LegacyRootConfig {
  /** Must be 0. Any other value is refused: this module reads the old root only. */
  rootEpoch: number;
  /** The app id, 20 bytes as hex. The KMS signs it into the app key. */
  appId: string;
  /**
   * The epoch-0 KMS root k256 public key, SEC1 hex (33 or 65 bytes), pinned
   * from outside the KMS response (the compose file).
   */
  kmsRootPubkey: string;
}

/** The fields of `KMS.GetAppKey`'s answer that this module consumes. */
export interface KmsAppKeyResponse {
  /** `undefined` when the answer carries no root_epoch: refused, not read as 0. */
  rootEpoch: number | undefined;
  /** `undefined` when the answer carries no app_epoch: refused, not read as 0. */
  appEpoch: number | undefined;
  /** The 32-byte app k256 private key of that root epoch. */
  k256Key: Uint8Array;
  /** 65 bytes: r || s || recovery id, over the issuance preimage. */
  k256Signature: Uint8Array;
}

/**
 * Asks the KMS for the app key of root epoch 0 from inside the guest. The only
 * implementation that talks to a KMS is `createRaTlsKmsTransport`.
 */
export interface LegacyKmsTransport {
  getAppKey(request: { rootEpoch: 0 }): Promise<KmsAppKeyResponse>;
}

/** One known sealed record, to prove the fetched root really opens it. */
export interface LegacyCanary {
  /** Sealing path the record was sealed under, e.g. `openkey/key/<sealingContext>`. */
  path: string;
  /** The stored sealed blob (base64, `iv12 || tag16 || ct`). */
  sealed: string;
}

export interface LegacyRoot {
  /**
   * Sealing key for `path` under the old root: sha256 of the v0 GetKey output. For
   * unseal only. A fresh copy per call: the caller zeroes it after use.
   */
  legacyKey(path: string): Uint8Array;
  /** Zeroes the root. `legacyKey` throws afterwards. */
  destroy(): void;
}

const RATLS_SALT = Buffer.from('RATLS', 'utf8');
const ISSUED_PREFIX = Buffer.from('dstack-kms-issued:', 'utf8');
const HEX_RE = /^(?:[0-9a-fA-F]{2})+$/;

function hexBytes(value: string, what: string): Uint8Array {
  const stripped = value.replace(/^0x/, '');
  if (!HEX_RE.test(stripped)) {
    throw new LegacyRootError('config_invalid', `${what} is not hex`);
  }
  return new Uint8Array(Buffer.from(stripped, 'hex'));
}

function parseConfig(config: LegacyRootConfig): { appId: Uint8Array; rootPubkey: Uint8Array } {
  if (config.rootEpoch !== 0) {
    throw new LegacyRootError('config_invalid', 'only root epoch 0 can be read');
  }
  const appId = hexBytes(config.appId, 'appId');
  if (appId.length !== 20) {
    throw new LegacyRootError('config_invalid', 'appId must be 20 bytes');
  }
  const rootPubkey = hexBytes(config.kmsRootPubkey, 'kmsRootPubkey');
  if (rootPubkey.length !== 33 && rootPubkey.length !== 65) {
    throw new LegacyRootError('config_invalid', 'kmsRootPubkey must be a SEC1 point');
  }
  try {
    secp256k1.Point.fromBytes(rootPubkey);
  } catch {
    throw new LegacyRootError('config_invalid', 'kmsRootPubkey is not a secp256k1 point');
  }
  return { appId, rootPubkey };
}

/** Names of the pins in the compose `environment:`. */
export const LEGACY_ROOT_ENV = {
  kmsUrl: 'OPENKEY_LEGACY_KMS_URL',
  rootEpoch: 'OPENKEY_LEGACY_ROOT_EPOCH',
  kmsRootPubkey: 'OPENKEY_LEGACY_KMS_ROOT_PUBKEY',
  kmsCaCert: 'OPENKEY_LEGACY_KMS_CA_CERT',
  appId: 'OPENKEY_LEGACY_APP_ID',
} as const;

export interface LegacyRootPins {
  config: LegacyRootConfig;
  /** KMS origin, https://host[:port]. */
  kmsUrl: string;
  /** The KMS RPC CA certificate, base64 of its DER. The only trust anchor for the KMS. */
  kmsCaCert: string;
}

/**
 * The pins, read from the process environment and from nowhere else: not from a
 * KMS response, not from the database, not from an argument. They protect the
 * old root in transit and decide which root is accepted, so they must come from
 * attested configuration. Deploy them as LITERAL values in the compose
 * `environment:` (covered by the compose hash), never as `${VAR}` references,
 * which resolve from the sealed environment and are not attested. All five are
 * required; a missing or malformed pin throws `config_invalid`.
 */
export function legacyRootPinsFromEnv(env: Record<string, string | undefined> = process.env): LegacyRootPins {
  const read = (name: string): string => {
    const value = env[name]?.trim();
    if (!value) {
      throw new LegacyRootError('config_invalid', `${name} is not set`);
    }
    return value;
  };
  const epoch = read(LEGACY_ROOT_ENV.rootEpoch);
  if (!/^\d+$/.test(epoch)) {
    throw new LegacyRootError('config_invalid', `${LEGACY_ROOT_ENV.rootEpoch} is not a number`);
  }
  const pins: LegacyRootPins = {
    config: {
      rootEpoch: Number(epoch),
      appId: read(LEGACY_ROOT_ENV.appId),
      kmsRootPubkey: read(LEGACY_ROOT_ENV.kmsRootPubkey),
    },
    kmsUrl: read(LEGACY_ROOT_ENV.kmsUrl),
    kmsCaCert: read(LEGACY_ROOT_ENV.kmsCaCert),
  };
  parseConfig(pins.config); // epoch 0 only, app id and root key well formed
  return pins;
}

/**
 * Fetches the epoch-0 app key through `transport`, checks it, and proves it
 * with the canary records. Throws LegacyRootError and returns nothing usable
 * on any doubt: a refusal, a wrong epoch, a signature that does not verify
 * under the pinned key, or a canary that does not unseal.
 */
export async function loadLegacyRoot(options: {
  config: LegacyRootConfig;
  transport: LegacyKmsTransport;
  /** At least one. A root that opens no known record is not trusted. */
  canaries: readonly LegacyCanary[];
}): Promise<LegacyRoot> {
  const { appId, rootPubkey } = parseConfig(options.config);
  if (options.canaries.length === 0) {
    throw new LegacyRootError('config_invalid', 'at least one canary record is required');
  }

  let response: KmsAppKeyResponse;
  try {
    response = await options.transport.getAppKey({ rootEpoch: 0 });
  } catch {
    // The cause can carry KMS output; the code is what a log may say.
    throw new LegacyRootError('kms_refused', 'the KMS did not return the epoch-0 app key');
  }

  // (a) The KMS must SAY it derived from epoch 0: an absent epoch is a refusal, never "0".
  if (response.rootEpoch !== 0 || response.appEpoch !== 0) {
    throw new LegacyRootError('epoch_mismatch', 'the KMS answered for a different epoch than 0');
  }

  const k256Key = Uint8Array.from(response.k256Key);
  try {
    if (k256Key.length !== 32 || !secp256k1.utils.isValidSecretKey(k256Key)) {
      throw new LegacyRootError('response_invalid', 'the app key is not a secp256k1 secret key');
    }
    // `v` is ignored (verification is under the pinned key); only the envelope length is checked.
    if (response.k256Signature.length !== 65) {
      throw new LegacyRootError('response_invalid', 'the app key signature is not r || s || v');
    }

    // (b) The key must carry the pinned epoch-0 root's signature for this app.
    const appRootPub = secp256k1.getPublicKey(k256Key, true);
    const digest = keccak256(Buffer.concat([ISSUED_PREFIX, appId, appRootPub]), 'bytes');
    let verified = false;
    try {
      verified = secp256k1.verify(response.k256Signature.subarray(0, 64), digest, rootPubkey, {
        prehash: false,
        lowS: true,
      });
    } catch {
      verified = false;
    }
    if (!verified) {
      throw new LegacyRootError('signature_invalid', 'the app key is not signed by the pinned epoch-0 root');
    }

    const root = makeRoot(k256Key);
    // (c) Canary: the root must open a record that was sealed before the move.
    try {
      for (const canary of options.canaries) {
        let opened = false;
        try {
          await unseal(canary.sealed, root.legacyKey(canary.path));
          opened = true;
        } catch {
          opened = false;
        }
        if (!opened) {
          throw new LegacyRootError('canary_failed', 'a known sealed record did not unseal under the fetched root');
        }
      }
    } catch (err) {
      root.destroy();
      throw err;
    }
    return root;
  } finally {
    // The closure owns its own copy; the working copy goes either way.
    k256Key.fill(0);
    response.k256Key.fill(0);
  }
}

function makeRoot(k256Key: Uint8Array): LegacyRoot {
  const ikm = Uint8Array.from(k256Key);
  let destroyed = false;
  return {
    legacyKey(path: string): Uint8Array {
      if (destroyed) {
        throw new LegacyRootError('config_invalid', 'the legacy root was destroyed');
      }
      // dstack ra-tls `derive_key`: HKDF-SHA256 under the legacy "RATLS" salt, 32 bytes.
      const dstackKey = Buffer.from(hkdfSync('sha256', ikm, RATLS_SALT, Buffer.from(path, 'utf8'), 32));
      const sealingKey = createHash('sha256').update(dstackKey).digest();
      dstackKey.fill(0);
      return new Uint8Array(sealingKey);
    },
    destroy() {
      destroyed = true;
      ikm.fill(0);
    },
  };
}

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
//
// Two ways to get the keys, exactly one configured, no fallback between them:
//   - direct: `KMS.GetAppKey{root_epoch: 0, app_epoch: 0}` over RA-TLS (legacy-root-kms.ts),
//     which returns the app root; the keys are derived here;
//   - sidecar: the dstack-key-recovery sidecar over a unix socket
//     (legacy-root-sidecar.ts), which returns GetKey(path) per path, never the root.
// The checks are the same in spirit; see loadLegacyRoot.
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

/** What the dstack-key-recovery sidecar answers for `GET /v0/key`, parsed. */
export interface SidecarKeyResponse {
  api: string | undefined;
  /** `GetKey(path)`: 32 bytes. */
  key: Uint8Array;
  /** 33-byte compressed public key of `key`. */
  publicKey: Uint8Array;
  /** Two 65-byte links, r || s || v. Link 1 is the KMS `k256_signature`. */
  signatureChain: Uint8Array[];
  /** `undefined` when the answer carries no root_epoch: refused, not read as 0. */
  rootEpoch: number | undefined;
  /** `undefined` when the answer carries no app_epoch: refused, not read as 0. */
  appEpoch: number | undefined;
}

/**
 * Asks the sidecar for the epoch-0 key of `path`. Both epochs are sent
 * explicitly: an unset app_epoch would select the app's current epoch. The only
 * implementation is `createSidecarTransport`.
 */
export interface LegacySidecarTransport {
  getKey(request: { path: string; rootEpoch: 0; appEpoch: 0 }): Promise<SidecarKeyResponse>;
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
   * unseal only. A fresh copy per call (the sidecar transport fetches and verifies
   * per call): the caller zeroes it after use.
   */
  legacyKey(path: string): Promise<Uint8Array>;
  /** Zeroes the root, if one is held. `legacyKey` rejects afterwards. */
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
  /** Selects the key-recovery sidecar transport. Mutually exclusive with the direct-KMS pair. */
  sidecarSocket: 'OPENKEY_LEGACY_SIDECAR_SOCKET',
} as const;

/** Exactly one transport is configured. */
export type LegacyTransportPins =
  | {
      kind: 'kms';
      /** KMS origin, https://host[:port]. */
      kmsUrl: string;
      /** The KMS RPC CA certificate, base64 of its DER. The only trust anchor for the KMS. */
      kmsCaCert: string;
    }
  | {
      kind: 'sidecar';
      /** Absolute path of the sidecar's unix socket. */
      socketPath: string;
    };

export interface LegacyRootPins {
  config: LegacyRootConfig;
  transport: LegacyTransportPins;
}

/**
 * The pins, read from the process environment and from nowhere else: not from a
 * KMS response, not from the database, not from an argument. They decide which
 * root is accepted (and, for the direct transport, protect the old root in
 * transit), so they must come from attested configuration. Deploy them as LITERAL
 * values in the compose `environment:` (covered by the compose hash), never as
 * `${VAR}` references, which resolve from the sealed environment and are not
 * attested.
 *
 * Always required: root epoch (0), root pubkey, app id. Then exactly ONE transport:
 * the sidecar socket, or the KMS URL together with the KMS CA cert. Both or
 * neither throws `config_invalid` before anything is called; there is no fallback
 * from one to the other. A missing or malformed pin throws `config_invalid`.
 */
export function legacyRootPinsFromEnv(env: Record<string, string | undefined> = process.env): LegacyRootPins {
  const has = (name: string): boolean => Boolean(env[name]?.trim());
  const read = (name: string): string => {
    const value = env[name]?.trim();
    if (!value) {
      throw new LegacyRootError('config_invalid', `${name} is not set`);
    }
    return value;
  };
  const viaSidecar = has(LEGACY_ROOT_ENV.sidecarSocket);
  const viaKms = has(LEGACY_ROOT_ENV.kmsUrl) || has(LEGACY_ROOT_ENV.kmsCaCert);
  if (viaSidecar === viaKms) {
    throw new LegacyRootError('config_invalid', 'exactly one legacy transport must be configured');
  }
  const epoch = read(LEGACY_ROOT_ENV.rootEpoch);
  if (!/^\d+$/.test(epoch)) {
    throw new LegacyRootError('config_invalid', `${LEGACY_ROOT_ENV.rootEpoch} is not a number`);
  }
  const config: LegacyRootConfig = {
    rootEpoch: Number(epoch),
    appId: read(LEGACY_ROOT_ENV.appId),
    kmsRootPubkey: read(LEGACY_ROOT_ENV.kmsRootPubkey),
  };
  parseConfig(config); // epoch 0 only, app id and root key well formed
  if (viaSidecar) {
    const socketPath = read(LEGACY_ROOT_ENV.sidecarSocket);
    if (!socketPath.startsWith('/')) {
      throw new LegacyRootError('config_invalid', `${LEGACY_ROOT_ENV.sidecarSocket} is not an absolute path`);
    }
    return { config, transport: { kind: 'sidecar', socketPath } };
  }
  return {
    config,
    transport: { kind: 'kms', kmsUrl: read(LEGACY_ROOT_ENV.kmsUrl), kmsCaCert: read(LEGACY_ROOT_ENV.kmsCaCert) },
  };
}

/** (b): `signature` is the KMS's low-S issuance signature for (app id, app root pub) under the pinned root. */
function issuedByPinnedRoot(appId: Uint8Array, appPub: Uint8Array, signature: Uint8Array, rootPubkey: Uint8Array): boolean {
  const digest = keccak256(Buffer.concat([ISSUED_PREFIX, appId, appPub]), 'bytes');
  try {
    return secp256k1.verify(signature.subarray(0, 64), digest, rootPubkey, { prehash: false, lowS: true });
  } catch {
    return false;
  }
}

/** The sealing key of the old CVM for a v0 GetKey(path) value. */
function sealingKeyOf(getKeyValue: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(getKeyValue).digest());
}

/**
 * Reads the old root's keys and proves them with canary records. Exactly one of
 * `transport` (the direct KMS read: one root fetch, keys derived here) or
 * `sidecar` (the dstack-key-recovery sidecar: one verified key per path) must be
 * given; both or neither is `config_invalid`, and nothing is called. There is no
 * fallback from one to the other.
 *
 * Throws LegacyRootError and returns nothing usable on any doubt: a refusal, a
 * wrong or missing epoch, a signature that does not verify under the pinned key,
 * or a canary that does not unseal. The canary is the one check that does not
 * rest on what the KMS or the sidecar says, and it is mandatory.
 */
export async function loadLegacyRoot(options: {
  config: LegacyRootConfig;
  /** Direct KMS read. */
  transport?: LegacyKmsTransport;
  /** Key-recovery sidecar. */
  sidecar?: LegacySidecarTransport;
  /** At least one. A root that opens no known record is not trusted. */
  canaries: readonly LegacyCanary[];
}): Promise<LegacyRoot> {
  const { appId, rootPubkey } = parseConfig(options.config);
  if ((options.transport === undefined) === (options.sidecar === undefined)) {
    throw new LegacyRootError('config_invalid', 'exactly one of transport and sidecar must be given');
  }
  if (options.canaries.length === 0) {
    throw new LegacyRootError('config_invalid', 'at least one canary record is required');
  }
  const keys = options.sidecar
    ? sidecarKeys(options.sidecar, appId, rootPubkey)
    : await kmsKeys(options.transport!, appId, rootPubkey);
  try {
    // The canary: the keys must open a record that was sealed before the move.
    for (const canary of options.canaries) {
      const sealingKey = await keys.legacyKey(canary.path); // verification errors keep their own code
      let opened = false;
      try {
        await unseal(canary.sealed, sealingKey);
        opened = true;
      } catch {
        opened = false;
      }
      sealingKey.fill(0);
      if (!opened) {
        throw new LegacyRootError('canary_failed', 'a known sealed record did not unseal under the old keys');
      }
    }
  } catch (err) {
    keys.destroy();
    throw err;
  }
  return keys;
}

/** Direct transport: one root fetch, checked (a), (b), then every key derived from it here. */
async function kmsKeys(transport: LegacyKmsTransport, appId: Uint8Array, rootPubkey: Uint8Array): Promise<LegacyRoot> {
  let response: KmsAppKeyResponse;
  try {
    response = await transport.getAppKey({ rootEpoch: 0 });
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
    if (!issuedByPinnedRoot(appId, secp256k1.getPublicKey(k256Key, true), response.k256Signature, rootPubkey)) {
      throw new LegacyRootError('signature_invalid', 'the app key is not signed by the pinned epoch-0 root');
    }
    return makeRoot(k256Key);
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
    async legacyKey(path: string): Promise<Uint8Array> {
      if (destroyed) {
        throw new LegacyRootError('config_invalid', 'the legacy root was destroyed');
      }
      // dstack ra-tls `derive_key`: HKDF-SHA256 under the legacy "RATLS" salt, 32 bytes.
      const dstackKey = Buffer.from(hkdfSync('sha256', ikm, RATLS_SALT, Buffer.from(path, 'utf8'), 32));
      const sealingKey = sealingKeyOf(dstackKey);
      dstackKey.fill(0);
      return sealingKey;
    },
    destroy() {
      destroyed = true;
      ikm.fill(0);
    },
  };
}

/**
 * Sidecar transport: the sidecar returns `GetKey(path)` itself, so no root is held here.
 * Each key is checked before use:
 *   (a) api "v0"; root_epoch and app_epoch present, both 0;
 *   - public_key is the compressed public key of key;
 *   - signature_chain is two 65-byte links (r || s || v); link 0 recovers the app
 *     public key from keccak256(":" || hex(public_key));
 *   (b) link 1 is the KMS issuance signature for (app id, app public key), checked
 *     under the pinned epoch-0 root exactly as in the direct transport.
 * The chain does not prove which path the key belongs to or how it was derived;
 * only the canary does.
 */
function sidecarKeys(transport: LegacySidecarTransport, appId: Uint8Array, rootPubkey: Uint8Array): LegacyRoot {
  let destroyed = false;
  return {
    async legacyKey(path: string): Promise<Uint8Array> {
      if (destroyed) {
        throw new LegacyRootError('config_invalid', 'the legacy root was destroyed');
      }
      let response: SidecarKeyResponse;
      try {
        response = await transport.getKey({ path, rootEpoch: 0, appEpoch: 0 });
      } catch {
        throw new LegacyRootError('kms_refused', 'the key-recovery sidecar did not return the key');
      }
      try {
        if (response.api !== 'v0') {
          throw new LegacyRootError('response_invalid', 'the sidecar answered for another API than v0');
        }
        // An absent epoch is a refusal, never "0".
        if (response.rootEpoch !== 0 || response.appEpoch !== 0) {
          throw new LegacyRootError('epoch_mismatch', 'the sidecar answered for a different epoch than 0');
        }
        if (response.key.length !== 32 || !secp256k1.utils.isValidSecretKey(response.key)) {
          throw new LegacyRootError('response_invalid', 'the key is not a secp256k1 secret key');
        }
        const publicKey = secp256k1.getPublicKey(response.key, true);
        if (!Buffer.from(publicKey).equals(Buffer.from(response.publicKey))) {
          throw new LegacyRootError('response_invalid', "public_key is not the key's public key");
        }
        const [link0, link1] = response.signatureChain;
        if (
          response.signatureChain.length !== 2 ||
          link0!.length !== 65 ||
          link1!.length !== 65 ||
          link0![64]! > 1
        ) {
          throw new LegacyRootError('response_invalid', 'signature_chain is not two r || s || v links');
        }
        let appPub: Uint8Array;
        try {
          // Link 0: the app key signed the derived public key (purpose empty); `v` is the recovery id.
          const digest = keccak256(Buffer.from(`:${Buffer.from(publicKey).toString('hex')}`, 'utf8'), 'bytes');
          const recovered = Buffer.concat([link0!.subarray(64), link0!.subarray(0, 64)]); // v || r || s
          appPub = secp256k1.recoverPublicKey(recovered, digest, { prehash: false });
        } catch {
          throw new LegacyRootError('signature_invalid', 'signature_chain[0] does not recover an app key');
        }
        if (!issuedByPinnedRoot(appId, appPub, link1!, rootPubkey)) {
          throw new LegacyRootError('signature_invalid', 'the app key is not signed by the pinned epoch-0 root');
        }
        return sealingKeyOf(response.key);
      } finally {
        response.key.fill(0);
      }
    },
    destroy() {
      destroyed = true;
    },
  };
}

// A software passkey for API tests (TC-3442): an ES256 key pair stored as a `passkey` row, and WebAuthn assertions
// it signs for the server's own options, exactly as a platform authenticator would answer them.
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign, type KeyObject } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';
import type { PrismaClient } from '@openkey/db';

const b64url = (bytes: Uint8Array | Buffer) => Buffer.from(bytes).toString('base64url');

export type SoftPasskey = {
  id: string;
  credentialID: string;
  /** Signs an assertion for these options. `userVerified: false` leaves the UV flag unset. */
  assert(options: PublicKeyCredentialRequestOptionsJSON, extra?: { origin?: string; userVerified?: boolean }): unknown;
};

export async function createSoftPasskey(
  db: Pick<PrismaClient, 'passkey'>, userId: string, countsForStepUp: boolean, origin: string,
): Promise<SoftPasskey> {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = new Map<number, number | Uint8Array>([
    [1, 2], [3, -7], [-1, 1],
    [-2, new Uint8Array(Buffer.from(jwk.x!, 'base64url'))],
    [-3, new Uint8Array(Buffer.from(jwk.y!, 'base64url'))],
  ]);
  const credentialID = b64url(randomBytes(16));
  const row = await db.passkey.create({ data: {
    id: randomUUID(), userId, name: 'soft', credentialID, counter: 0, deviceType: 'singleDevice', backedUp: false,
    publicKey: Buffer.from(isoCBOR.encode(cose)).toString('base64'), transports: 'internal', countsForStepUp,
  } });
  let counter = 0;
  return {
    id: row.id,
    credentialID,
    assert: (options, extra = {}) => assertion(privateKey, credentialID, ++counter, options, extra.origin ?? origin, extra.userVerified ?? true),
  };
}

function assertion(
  key: KeyObject, credentialID: string, counter: number, options: PublicKeyCredentialRequestOptionsJSON,
  origin: string, userVerified: boolean,
) {
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false }));
  const count = Buffer.alloc(4);
  count.writeUInt32BE(counter);
  const authenticatorData = Buffer.concat([
    createHash('sha256').update(options.rpId!).digest(),
    Buffer.from([0x01 | (userVerified ? 0x04 : 0)]),
    count,
  ]);
  const signature = sign('sha256', Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]), key);
  return {
    id: credentialID,
    rawId: credentialID,
    type: 'public-key',
    response: { authenticatorData: b64url(authenticatorData), clientDataJSON: b64url(clientDataJSON), signature: b64url(signature) },
    clientExtensionResults: {},
  };
}

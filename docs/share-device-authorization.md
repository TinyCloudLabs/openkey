# Share device authorization

OpenKey owns the transaction state for first-time `tc share publish` from a
remote or headless machine. The unauthenticated CLI creates a local Ed25519
session key, a 256-bit device secret, an independent PKCE verifier, and an
ephemeral P-256 relay key. It sends only the public session and relay bindings,
hashed secret, PKCE challenge, requested Share permission, Node/Share origins,
and requested expiry.

OpenKey returns a ten-minute transaction, generic verification URL, and short
user code. At `/device`, the user signs in with the existing OpenKey/passkey
flow, reviews the exact capability, can adjust the delegation lifetime, and
approves through the normal `/delegate` signing path. The default lifetime is
30 days and the maximum is 90 days.

## Security invariants

- `sessionDid` is derived from and compared with the supplied public Ed25519
  JWK; private JWK fields are rejected.
- The only accepted baseline is `tinycloud.capabilities/read` for the
  `applications` space, used to request the existing one-shot Node Share upload
  attestation. The flow adds no KV/SQL authority and no Share space.
- Node origin, Share origin, permissions, session key, and approved expiry are
  checked again when approval is relayed and when the CLI consumes it.
- Device secrets and PKCE verifiers are independently high entropy. Only their
  SHA-256 digests are stored.
- Creation and polling are rate-limited. Transactions expire after ten minutes.
- The browser derives an ECDH/HKDF key from the CLI relay public key and
  encrypts the approved delegation with AES-256-GCM before sending it to the
  device API. The relay stores only that opaque envelope and consumes it once
  with an atomic status transition; neither the relay nor its rows receive a
  plaintext delegation or CLI private key.
- Share object retention remains seven days.

The production database change is
`20260814_0001_share_device_authorization`. `DEVICE_AUTH_ENCRYPTION_SECRET`
may provide a dedicated secret for privacy-preserving request-IP rate-limit
hashes; otherwise OpenKey uses `BETTER_AUTH_SECRET`. Production refuses to
start the device route without one of those secrets.

## Public smoke

After building `@tinycloud/cli`, run:

```bash
bun scripts/share-device-auth-smoke.ts --cli /absolute/path/to/js-sdk/packages/cli/dist/index.js
```

This starts real local device, Node-attestation, and registry HTTP boundaries,
invokes the public CLI command, and verifies end-to-end relay encryption,
device prompting, cryptographic delegation persistence, one-shot-attested
uploads, seven-day retention, and the complete Share URL. It does not automate
the separate human passkey/browser approval journey.

# Escrow admin device signing

The server verifies signatures from the P-256 public keys compiled into its
measured image. The signing device keeps its private key; the HTTP requests
carry only public identifiers, descriptors and signatures. A session cookie or
shared API key cannot authorize either action.

Use ECDSA with SHA-256 over the exact UTF-8 message below, without a BOM,
whitespace or trailing newline. Pass these message bytes directly to an
ECDSA-SHA256 signer; do not prehash them before that call. Encode signatures
as unpadded canonical base64url of the 64-byte P1363 value `r32_be || s32_be`.
WebCrypto `subtle.sign({name: "ECDSA", hash: "SHA-256"}, deviceKey, message)`
returns this representation. A device returning ASN.1 DER must convert it to
P1363 before submission. Public keys use the canonical base64url encoding of
65-byte uncompressed SEC1 P-256 points.

## One-device preflight

Read `measuredConfigHash` from `/api/admin/escrow/configuration`. The device
creates a fresh CSPRNG nonce (32 bytes, canonical base64url) and a canonical
millisecond ISO `expiresAt`, at most 15 minutes ahead. Sign compact JSON:

```text
["tinycloud/escrow/preflight",1,measuredConfigHash,nonce,expiresAt,adminId]
```

Submit `POST /api/admin/escrow/preflight` with:

```text
{"approval":{"measuredConfigHash":…,"nonce":…,"expiresAt":…,"adminId":…,"signature":…},"approverId":…}
```

`adminId` is the operator. `approverId` names a different configured admin for
the subsequent export. The response contains a server-generated
`approvalDescriptor` and a public summary: app/compose/image identity, holder
ids and public-key fingerprints, purpose counts, total rows and times. Path
identities are hashes; manifest rows, owner ids, addresses and raw paths stay
inside the server's private preflight record.

## Two-device export

Both devices review the returned summary and the same unchanged descriptor:
`{policyHash, nonce, expiresAt, dryRun:false, operatorId, approverId}`. Each
signs compact JSON:

```text
["tinycloud/escrow/approve",1,policyHash,nonce,expiresAt,dryRun]
```

Submit `POST /api/admin/escrow/export` with:

```text
{"approval":{…approvalDescriptor,"signatures":[{"id":operatorId,"signature":…},{"id":approverId,"signature":…}]}}
```

The two ids and public keys must be distinct. The policy hash binds the stored
canonical preflight header, including both role ids. The server rebuilds that
policy from a newly fenced database read and refuses any mismatch. It consumes
the approval nonce and preflight record atomically with the completed export.
A rolled-back export does not consume them; an expired approval is refused.
Preflight and export signatures have different domains and cannot substitute
for one another. The preflight signature does not approve an export.

`packages/tee/tests/fixtures/escrow-approval-v1.json` pins the exact preflight
bytes, policy hash, approval-message bytes and two P1363 signatures under fixed
public test keys. The authorizer and independent Python verification accept
this vector. These fixture keys are test material.

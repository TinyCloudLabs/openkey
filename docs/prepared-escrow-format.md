# Prepared escrow format v1 (TC-2823)

The share format uses GF(2^8), polynomial 0x11b (x^8+x^4+x^3+x+1), generator
0xe5. A share is 33 bytes: 32 polynomial evaluations followed by its x byte.
The threshold is two of three. Production coefficients and distinct coordinates
are cryptographically random; x is in 1..255. Zero or duplicate coordinates,
wrong lengths and a mismatched header hash must be rejected before recovery.

HPKE suite is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
AES-256-GCM (0x0010/0x0001/0x0002). Both info and AAD bind the escrow id,
holder id, explicit x and frozen header hash. A content-key commitment must be
checked after interpolation: Shamir alone does not authenticate shares and
cannot distinguish a tampered share or a pair from different escrows.

The public synthetic fixture in packages/tee/tests/fixtures/escrow-shares-v1.json
uses secret bytes 00..1f, x=1,2,255, and SHA-256 of the stated test seed for the
32 degree-one coefficients. This deterministic entropy is for tests only.
The TS tests check all three pairs against Privy 0.0.4 and reject invalid
indices, malformed commitments, altered shares and a share from another split.

Dependency review: @hpke/core 1.9.0, @hpke/common 1.10.1 (root override),
shamir-secret-sharing 0.0.4, exact integrity values in bun.lock. No install
lifecycle scripts in these packages. Install with --frozen-lockfile
--ignore-scripts. Lock creation also reconciled five pre-existing workspace
version metadata entries against their package manifests.

## Interpolation and commitment

For each byte i, independently choose one degree-one polynomial with constant
c0 = secret[i] and uniformly random c1. Share byte i is y_i(x); reconstruct
secret byte i by Lagrange interpolation at x=0. The deterministic fixture uses
c1_i = SHA256(UTF8("tinycloud-escrow-vector-v1"))[i]. Production never uses this
fixture entropy.

Commitment encoding is SHA-256(label || uint32_be(idByteLength) || idBytes || key).
Label is UTF-8 `tinycloud/escrow/content-key/v1` followed by exactly one NUL byte;
idBytes is the exact UTF-8 escrow_id (no normalization), length 1..1024 bytes;
key is the raw 32-byte content key. Output is 64 lowercase hexadecimal digits.
The fixture records escrowId and commitmentHex for this format. For escrow id
`test-escrow-v1` and key bytes 00..1f, the commitment is
`795adb077e1fc67d47c013d3906377816fd096f91457bd0db0bdc918a4e87103`.
Header-hash authentication is enforced by the HPKE stage.

## HPKE share wrapper

Each wrapper has version=1, escrowId, holderId, x, headerHash, enc and ciphertext.
enc is the 65-byte P-256 encapsulation; ciphertext is 49 bytes (33-byte share
plus 16-byte GCM tag). Both use canonical unpadded base64url. For info encode
JSON.stringify(["tinycloud/escrow/share-info",1,escrowId,holderId,x,headerHash])
as UTF-8; AAD uses the same tuple with domain "tinycloud/escrow/share-aad".
No whitespace, tuple order fixed, JSON string escaping applies. headerHash is
64 lowercase SHA-256 hex characters. The expected binding must come from the
verified frozen header, never from the wrapper itself. Each share uses a fresh
HPKE single-shot context. Recovery rejects any binding difference before open,
and verifies the decrypted trailing x.

## Header encoding

`encodeEscrowHeader` emits UTF-8 JSON.stringify of this fixed-position tuple:

```
["tinycloud/escrow/header",1,escrowId,appId,contentKeyCommitment,createdAt,expiresAt,
 imageDigest,composeHash,codeHash,
 osVersion,agentVersion,bootReference,snapshotId,recordManifestHash,dbSnapshotHash,
 nonce,approvalReference,
 operatorId,approverId,[16,1,2,"gf256-0x11b",2,3],holders,paths]
```

Each holder tuple is `[id,x,publicKey]`; publicKey is canonical unpadded base64url
of 65-byte uncompressed P-256 SEC1 bytes with prefix 0x04. Holder ids and public
keys are distinct; exactly three holders are required. Coordinates x are distinct
integers in 1..255, bound to their holder in the header. Holder tuples sort by
id using JavaScript string comparison (UTF-16 code units). Each path tuple is
`[path,purpose,version,transform,derivedPublicKey,sourcePublicKey,signatureChain,expectedCount]`.
Path tuples sort by their JSON.stringify encoding using the same comparison.
Duplicate `(path,purpose,version)` tuples are rejected. Signature-chain order
is preserved. Header hash is SHA-256 of these bytes, lowercase hex.

Strings must be nonempty valid Unicode scalar sequences, at most 4096 UTF-8
bytes; escrowId is limited to 1024 bytes. Versions are nonnegative safe integers; counts are positive safe integers.
Negative zero is rejected. Image digest is `sha256:` plus 64 lowercase hex digits; compose/code
hashes are 64 lowercase hex digits. Operator and approver ids differ.
`freezeEscrowHeader` copies policy before asynchronous import, validates each
recipient with `deserializePublicKey`, rebuilds only named fields from the
canonical tuple, returns holders/paths in canonical order, and freezes nested objects.
The suite tuple denotes KEM=16, KDF=1, AEAD=2, GF polynomial 0x11b, threshold=2,
share count=3. createdAt/expiresAt use canonical millisecond UTC ISO timestamps,
with expiry after creation. contentKeyCommitment uses the encoding above.
Nonce is generated by a CSPRNG; the entrypoint enforces snapshotId, bootReference,
approvalReference, sourcePublicKey and signatureChain formats against their
trusted sources. App id, image/compose/code hashes bind exporter identity.

The synthetic cross-language fixture `tests/fixtures/escrow-header-v1.json`
contains the header, exact canonical UTF-8 bytes and SHA-256 hash. Its public
P-256 keys derive from test-only private scalars 1, 2 and 3. A separate Python
fixed-tuple encoder reproduces the bytes and hash. The TS test checks both.

## Material transforms

The closed v1 transform enum is `sha256-getkey` (SHA-256 of raw GetKey bytes,
exactly 32 bytes) and `dstack-getkey-raw-v1` (raw GetKey bytes, exactly 32 bytes).
Export and recovery reject unknown transforms and any other material length;
no truncation or padding is permitted. Raw material is re-derived by service
code: witness issuer uses the first 32 bytes and its subkey adapter hashes the
full raw material. Item framing is iv12 || ciphertext(materialLength) || tag16;
transform is authenticated in item AAD. Path is an opaque exact identity string; version is explicit nonnegative safe
integer metadata (including 0). Service adapters enforce their own grammar:
share-email vN uses version N; org-issuer/v1/<orgId>/<keyVersion> uses terminal
keyVersion, where v1 is a schema namespace. The shared header does not infer
version from path text.

## Empty legacy inventory

The sole zero-count identity is path literal `openkey/user/{userId}/encryption`,
purpose `legacy-user-encryption-empty`, version 0, transform `sha256-getkey`,
expectedCount 0. It occurs at most once and cannot coexist with any
`legacy-user-encryption` purpose line. Its source public key and signature chain
carry the same app evidence as real paths. It is metadata only: no material
item or derivation on the template. Export and recovery omit it from the
material set and require its validatedCount=0 result. All other counts are
positive. Positive legacy identities use the concrete per-user path and
`legacy-user-encryption` purpose; PKCS8 private keys are validated by deriving
and matching the persisted SPKI public key.

## Export source evidence

The escrow provenance client uses the explicit local dstack socket. It keeps
GetKey's two 65-byte signature-chain entries as lowercase hex, derives the
OpenKey sealing key as SHA-256(raw32), and clears the raw buffer. For guest-api
v0, the first signature covers Keccak256(UTF8(":" + compressed-derived-public-key
lowercase hex)); recovering it yields the source app public key.

Export quote REPORTDATA is SHA-256(UTF8("tinycloud/escrow/export-quote/v1") ||
NUL || UTF8(headerHash)) followed by 32 zero bytes. headerHash is its 64-character
lowercase hexadecimal representation. The client checks the echoed data and
TDX v4 quote body binding, and returns quote hex, event-log text and digest.
Guest reachability plus a successful bound GetQuote supplies the runtime gate.
The quote and event log are inputs to independent holder/recovery verification
of TDX signatures, measurement replay and the expected app/compose policy.

Each path's derivedPublicKey is the raw GetKey key's compressed secp256k1 public
key: exactly 33 bytes, lowercase hex, prefix02/03, curve-checked. It immediately
follows transform in the tuple. GetKey purpose is the empty string; chain[0]
signs Keccak256(UTF8(":" + derivedPublicKey)). Path purpose names are service
inventory labels, separate from this GetKey purpose argument.

For both v1 transforms the GetKey signed purpose is the constant empty string,
not the header's inventory/business purpose. The holder verifier checks chain[0]
over keccak256(UTF8(":" + derivedPublicKey)). A service using a nonempty signed
GetKey purpose requires a new closed transform value.

## Private record manifest and database snapshot

recordManifestHash is SHA-256 over UTF-8 compact JSON
`["tinycloud/escrow/record-manifest",1,[tuples...]]`. Each tuple is
`[table,rowId,owner|null,path,purpose,version,transform,expectedIdentity,ciphertextChecksum]`.
Sort by each tuple's compact JSON using UTF-16 code-unit comparison. Reject
duplicate `(table,rowId)` identities, unknown paths and per-path counts different
from expectedCount. The sentinel has zero tuples. The private manifest is stored
with the sealed database snapshot; holder bundles contain only its hash.

OpenKey dbSnapshotHash is SHA-256 over UTF-8 compact JSON
`["tinycloud/escrow/db-snapshot",1,[[table,rows],...]]`. Tables occur in this order,
and each row tuple uses these exact columns:

- ethereum_keys: id, userId, address, publicKey, sealedBlob, sealingContext,
  keyType, isCanonicalTinyCloud, keyIndex, label, archivedAt, createdAt.
- nostr_keys: id, userId, label, pubkeyHex, npub, sealedSecret, sealingContext,
  revokedAt, createdAt.
- user_encryption_key: id, userId, publicKey, sealedPrivateKey, createdAt.

Sort rows by id using UTF-16 code-unit comparison; reject duplicate ids.
Nullable values remain JSON null. Strings remain exact Unicode scalar sequences.
isCanonicalTinyCloud is Boolean; keyIndex is a safe integer (negative zero
rejected); timestamps become canonical UTC millisecond ISO strings. All three
tables and every listed column are required, independently of driver property
order. The snapshot reader selects all listed columns inside the table fence.

## Preflight policy and admin approval

policyHash is SHA-256 of canonical preflight header bytes. Set
contentKeyCommitment to 64 zeros; sort holders by id and assign x=1,2,3 in that
order. All other header fields are final. Export replaces only the content-key
commitment and actual Privy coordinates. snapshotId names the preflight PostgreSQL
snapshot; a later fenced read proves identical record and database hashes.

The test-only fixture `tests/fixtures/escrow-approval-v1.json` contains the fixed
preflight header, exact canonical bytes, policyHash, nonce, expiry, mode, approve
message bytes and two fixed P-256 signatures. The signatures use public test
scalars 1 and 2, ECDSA-SHA256 and 64-byte P1363 encoding, unpadded base64url.
The approve message is UTF-8 compact JSON
`["tinycloud/escrow/approve",1,policyHash,nonce,expiresAt,dryRun]`.
The TS authorizer accepts this vector; independent Python encoding and P-256
verification reproduce its bytes, hash and signatures.

Admin device signing: obtain the server's preflight descriptor, verify its
policy hash against the exact policy bytes, and sign the approve message with
the configured P-256 key on the admin's device. WebCrypto ECDSA with SHA-256
returns P1363 bytes; encode those 64 bytes as unpadded base64url and send only
admin id plus signature. The private key remains on that device. Both admins
sign the same descriptor; a dry-run signature authorizes only dry-run.

Preflight has a separate one-admin authorization message:
`["tinycloud/escrow/preflight",1,measuredConfigHash,nonce,expiresAt,adminId]`,
UTF-8 compact JSON, ECDSA-SHA256 P1363 base64url. The nonce is canonical
32-byte base64url and single-use; expiry is at most 15 minutes ahead. Preflight
and export consume the same nonce ledger and combined hourly budget, with an
explicit kind. Domain separation prevents either signature from authorizing
the other action. Real export still requires both configured admin signatures.

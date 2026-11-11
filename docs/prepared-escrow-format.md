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
 osVersion,agentVersion,bootReference,snapshotId,nonce,approvalReference,
 operatorId,approverId,[16,1,2,"gf256-0x11b",2,3],holders,paths]
```

Each holder tuple is `[id,x,publicKey]`; publicKey is canonical unpadded base64url
of 65-byte uncompressed P-256 SEC1 bytes with prefix 0x04. Holder ids and public
keys are distinct; exactly three holders are required. Coordinates x are distinct
integers in 1..255, bound to their holder in the header. Holder tuples sort by
id using JavaScript string comparison (UTF-16 code units). Each path tuple is
`[path,purpose,version,transform,sourcePublicKey,signatureChain,expectedCount]`.
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
transform is authenticated in item AAD. Version 0 denotes an unversioned path
and is rejected when the path contains a `/vN/` or trailing `/vN` segment.
Versioned service paths require version === N for every vN segment, identically
in TS and Rust.

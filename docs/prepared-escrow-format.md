# Prepared escrow format v1 (TC-2823)

Review candidate; no deployed exporter or recovery compatibility claim.

All services use GF(2^8), polynomial 0x11b (x^8+x^4+x^3+x+1), generator
0xe5. A share is 33 bytes: 32 polynomial evaluations followed by its x byte.
The threshold is two of three. Production coefficients and distinct coordinates
are cryptographically random; x is in 1..255. Zero or duplicate coordinates,
wrong lengths and a mismatched header hash must be rejected before recovery.
Sharks' 0x11d arithmetic is incompatible. Rust recovery must implement the
specified field/layout and pass the common vectors before reliance.

Freeze the canonical header before wrapping shares. Canonicalization and the
complete header schema are pending implementation/review; consumers must not
invent an encoding. HPKE suite is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
AES-256-GCM (0x0010/0x0001/0x0002). Both info and AAD bind the escrow id,
holder id, explicit x and frozen header hash. A content-key commitment must be
checked after interpolation: Shamir alone does not authenticate shares and
cannot distinguish a tampered share or a pair from different escrows.

The public synthetic fixture in packages/tee/tests/fixtures/escrow-shares-v1.json
uses secret bytes 00..1f, x=1,2,255, and SHA-256 of the stated test seed for the
32 degree-one coefficients. This deterministic entropy is for tests only.
The TS test checks all three pairs against Privy 0.0.4. Rust execution and
wrong-pair/tampered-share authenticated-envelope negatives remain required.

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
Escrow-id binding is required (Bobbie C2); this supersedes the initial unbound
implementation. The fixture records escrowId and commitmentHex for this format.
The superseded label||key vector was
`5753bf8cd8f4adcbdfbcbf993aaa135e8b84fc9eda3af4806b6e7fb0f8a463e0`;
it is not accepted as an escrow-id-bound commitment.

Privy uses data-dependent GF table lookups, exposing cache-timing information
inside the TEE; Bobbie accepts this for the one-off ceremony. Its internal
buffers are not zeroed. The caller must generate the content key with a CSPRNG
inside the TEE; entrypoint review must verify this. Header-hash authentication
is enforced by the HPKE stage, not the Shamir primitive.

## HPKE share wrapper candidate

Each wrapper has version=1, escrowId, holderId, x, headerHash, enc and ciphertext.
enc is the 65-byte P-256 encapsulation; ciphertext is 49 bytes (33-byte share
plus 16-byte GCM tag). Both use canonical unpadded base64url. For info encode
JSON.stringify(["tinycloud/escrow/share-info",1,escrowId,holderId,x,headerHash])
as UTF-8; AAD uses the same tuple with domain "tinycloud/escrow/share-aad".
No whitespace, tuple order fixed, JSON string escaping applies. headerHash is
64 lowercase SHA-256 hex characters. The expected binding must come from the
verified frozen header, never from the wrapper itself. Each share uses a fresh
HPKE single-shot context. Recovery rejects any binding difference before open,
and verifies the decrypted trailing x. Full header canonicalization is still
pending; this wrapper is not yet wired to an operational entrypoint.

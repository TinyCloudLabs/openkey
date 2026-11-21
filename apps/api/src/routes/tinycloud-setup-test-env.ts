process.env.TINYCLOUD_DEFAULT_NODE_DID ??= 'did:key:z6MkpzW1jXKtQeTNxyZtZFwVPbpyG3Yr1YtKZHcdcxMvZabc';
// Side-effect module imported first by `tinycloud-setup-routes.test.ts` so the env is set
// before hoisted imports load modules that read env at construction. This file does NO I/O
// and sets no secrets; only shapes needed for tree import succeed.
process.env.TEE_MODE ??= 'development';
process.env.WEBAUTHN_RP_ID ??= 'localhost';
process.env.WEBAUTHN_ORIGIN ??= 'http://localhost:5173';
process.env.BETTER_AUTH_URL ??= 'http://localhost:3001';
process.env.BETTER_AUTH_SECRET ??= 'tc-3657-test-secret-00000000000000';
export {};

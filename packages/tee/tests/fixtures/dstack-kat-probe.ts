// Child process for dstack-key-derivation.kat.test.ts.
//
// `@openkey/tee` reads TEE_MODE when it is first imported, so the production
// client is exercised in a fresh process whose environment matches a CVM:
// TEE_MODE=production, with the SDK's own DSTACK_SIMULATOR_ENDPOINT pointing
// at a dstack guest-agent socket instead of /var/run/dstack.sock.
//
// Usage: bun run dstack-kat-probe.ts <src|dist> <path>...
// `dist` loads the built package, which is what the API image runs.
// Prints {"<path>": "<sealing key hex>", ...} on stdout.
import type * as TeeModule from '../../src/index';

const [entry, ...paths] = process.argv.slice(2);
if (entry !== 'src' && entry !== 'dist') {
  throw new Error(`dstack-kat-probe: entry must be src or dist, got ${entry}`);
}
// Dynamic: the entry is chosen at runtime, and dist exists only after a build.
const tee: typeof TeeModule =
  entry === 'dist' ? await import('../../dist/index.js') : await import('../../src/index');

const client = tee.createTeeClient();
if (!client.isInTee()) {
  throw new Error('dstack-kat-probe requires TEE_MODE=production');
}

const sealingKeys: Record<string, string> = {};
for (const path of paths) {
  sealingKeys[path] = Buffer.from(await client.deriveKey(path)).toString('hex');
}
process.stdout.write(JSON.stringify(sealingKeys));

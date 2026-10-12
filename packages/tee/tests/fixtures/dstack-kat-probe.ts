// Child process for dstack-key-derivation.kat.test.ts.
//
// `@openkey/tee` reads TEE_MODE when it is first imported, so the production
// client is exercised in a fresh process whose environment matches a CVM:
// TEE_MODE=production, with the SDK's own DSTACK_SIMULATOR_ENDPOINT pointing
// at a dstack guest-agent socket instead of /var/run/dstack.sock.
//
// Usage: bun run dstack-kat-probe.ts <path>...
// Prints {"<path>": "<sealing key hex>", ...} on stdout.
import { createTeeClient } from '../../src/index';

const tee = createTeeClient();
if (!tee.isInTee()) {
  throw new Error('dstack-kat-probe requires TEE_MODE=production');
}

const sealingKeys: Record<string, string> = {};
for (const path of process.argv.slice(2)) {
  sealingKeys[path] = Buffer.from(await tee.deriveKey(path)).toString('hex');
}
process.stdout.write(JSON.stringify(sealingKeys));

#!/usr/bin/env bun
// TC-3837: after a deploy, save the exact app-compose the openkey-api CVM measured, so it can be
// published beside the release. sha256 of the saved file is the compose_hash in the attestation.
//
//   PHALA_CLOUD_API_KEY=… EXPECTED_API_IMAGE=<repo>@sha256:<digest> \
//     bun scripts/measured-app-compose.ts <output path>
//
// It refuses unless Phala's compose_hash, the RTMR3 `compose-hash` event and sha256 of the
// app-compose string all agree, every image in it is pinned by digest, and the api service runs
// EXPECTED_API_IMAGE. A CVM that is still restarting can report the previous compose for a short
// while, so it retries before failing. Writes `compose_hash=<hex>` to GITHUB_OUTPUT when set.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFile, writeFile } from 'node:fs/promises';
import { unpinnedImages } from './compose-image-digests';

const ATTEMPTS = 30;
const DELAY_MS = 10_000;

/** Narrows parsed JSON or YAML to an object; anything else becomes an empty object. */
function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? Object.fromEntries(Object.entries(value)) : {};
}

function phala(path: string): Record<string, unknown> {
  const result = spawnSync('phala', ['api', path, '--api-version', '2026-05-22', '--json'], {
    encoding: 'utf8',
    timeout: 60_000,
  });
  // Provider errors can include credentials. Never echo them.
  if (result.status !== 0) throw new Error(`phala api ${path} failed`);
  return record(JSON.parse(result.stdout));
}

export interface Measured {
  composeHash: string;
  appCompose: string;
}

/** Checks one reading of the CVM; returns the measured app-compose or the reason it is not ready. */
export function checkMeasurement(
  info: Record<string, unknown>,
  attestation: Record<string, unknown>,
  expectedApiImage: string,
): Measured | { problem: string } {
  const composeHash = info.compose_hash;
  if (typeof composeHash !== 'string' || !/^[0-9a-f]{64}$/.test(composeHash)) return { problem: 'no compose_hash on the CVM' };
  const rawTcb = attestation.tcb_info;
  const tcb = record(typeof rawTcb === 'string' ? JSON.parse(rawTcb) : rawTcb);
  const appCompose = tcb.app_compose;
  if (typeof appCompose !== 'string') return { problem: 'the attestation has no tcb_info.app_compose' };
  const events = Array.isArray(tcb.event_log) ? tcb.event_log.map(record) : [];
  const measured = events.filter((event) => event.event === 'compose-hash').map((event) => event.event_payload);
  if (measured.length !== 1) return { problem: `expected one compose-hash event, found ${measured.length}` };
  const appComposeSha256 = createHash('sha256').update(appCompose, 'utf8').digest('hex');
  if (appComposeSha256 !== composeHash || measured[0] !== composeHash) {
    return { problem: `compose_hash ${composeHash}, compose-hash event ${String(measured[0])} and sha256(app_compose) ${appComposeSha256} disagree` };
  }
  const dockerCompose = record(JSON.parse(appCompose)).docker_compose_file;
  if (typeof dockerCompose !== 'string') return { problem: 'app_compose has no docker_compose_file' };
  const unpinned = unpinnedImages(dockerCompose);
  if (unpinned.length > 0) return { problem: `measured compose has unpinned images: ${unpinned.join('; ')}` };
  const apiImage = record(record(record(Bun.YAML.parse(dockerCompose)).services).api).image;
  if (apiImage !== expectedApiImage) return { problem: `measured api image is ${String(apiImage)}, not ${expectedApiImage}` };
  return { composeHash, appCompose };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  const expectedApiImage = process.env.EXPECTED_API_IMAGE ?? '';
  if (!output || !/@sha256:[0-9a-f]{64}$/.test(expectedApiImage) || !process.env.PHALA_CLOUD_API_KEY) {
    throw new Error('usage: PHALA_CLOUD_API_KEY=… EXPECTED_API_IMAGE=<repo>@sha256:<digest> measured-app-compose.ts <output>');
  }
  let result: Measured | { problem: string } = { problem: 'not read' };
  for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
    const info = phala('/cvms/openkey-api');
    if (typeof info.vm_uuid !== 'string') throw new Error('the openkey-api CVM reported no vm_uuid');
    result = checkMeasurement(info, phala(`/cvms/${encodeURIComponent(info.vm_uuid)}/attestation`), expectedApiImage);
    if (!('problem' in result)) break;
    console.log(`attempt ${attempt}/${ATTEMPTS}: ${result.problem}`);
    if (attempt < ATTEMPTS) await Bun.sleep(DELAY_MS);
  }
  if ('problem' in result) {
    console.error(`::error::TC-3837: could not read a consistent measured app-compose: ${result.problem}`);
    process.exit(1);
  }
  await writeFile(output, result.appCompose);
  if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `compose_hash=${result.composeHash}\n`);
  console.log(`compose_hash ${result.composeHash} (sha256 of ${output})`);
}

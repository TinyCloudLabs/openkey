// TC-3569 (Bobbie's condition 8): the step-up ceilings OpenKey applies to the Home client, and the ones TinyCloud
// One's framed apps ask for (`frontend/src/apps/native-step-up-ceilings.json` in tinychat), must list exactly the
// same entries both ways, with app ids compared case-sensitively. An entry only One lists is something the app asks
// for and the server refuses; one only OpenKey lists is access nobody asked for.
//
//   bun scripts/step-up-ceiling-parity.ts                 # the pinned One file (see scripts/step-up-ceilings/one.pin.json)
//   bun scripts/step-up-ceiling-parity.ts --one <path>    # a local copy of One's file
//   bun scripts/step-up-ceiling-parity.ts --require-pin   # fail instead of skipping when One's file is not pinned yet
//
// Both files use the shape of the Home client's `stepUps` section (docs/native-tinycloud-delegation.md, "Step-up
// ceilings"), keyed by full app id. Each is validated by the same code the API runs on a ceiling before it is compared.
import { readFileSync } from 'node:fs';
import { validateNativeDelegationConfig } from '../apps/api/src/services/native-delegation/policy';

export type CeilingFile = Record<string, unknown>;

const HOME = {
  version: 1,
  appId: 'xyz.tinycloud.tinychat',
  tinycloudHost: 'https://tee.node.tinycloud.xyz',
  kv: { paths: ['xyz.tinycloud.tinychat/threads/'], actions: ['get', 'put'] },
  sql: null,
};
const NATIVE_CLIENT = { type: 'native', public: true, tokenEndpointAuthMethod: 'none' } as const;

type SpaceSection = { kv?: { paths: string[]; actions: string[] }; sql?: { databases: string[]; actions: string[] } };

/** Runs the API's own ceiling validation over a file and returns what it accepted. Throws on anything it refuses. */
export function validateCeilingFile(file: unknown): Record<string, Record<string, SpaceSection>> {
  const config = validateNativeDelegationConfig({ ...HOME, stepUps: file }, NATIVE_CLIENT, { allowLocalHosts: false });
  if (!config.stepUps) throw new Error('the file has no step-up ceilings');
  return config.stepUps as unknown as Record<string, Record<string, SpaceSection>>;
}

/** One line per (app, space, service, path or database, action). Case is kept: `Explorer` is not `explorer`. */
export function flattenCeilings(file: unknown): string[] {
  const entries: string[] = [];
  for (const [app, spaces] of Object.entries(validateCeilingFile(file))) {
    for (const [space, section] of Object.entries(spaces)) {
      for (const path of section.kv?.paths ?? []) for (const action of section.kv!.actions) entries.push(`${app}\t${space}\tkv\t${path}\t${action}`);
      for (const database of section.sql?.databases ?? []) for (const action of section.sql!.actions) entries.push(`${app}\t${space}\tsql\t${database}\t${action}`);
    }
  }
  return entries.sort();
}

export interface CeilingParity {
  /** In OpenKey's ceilings, not in One's. */
  onlyOpenKey: string[];
  /** In One's file, not in OpenKey's ceilings. */
  onlyOne: string[];
}

export function compareCeilings(openkey: unknown, one: unknown): CeilingParity {
  const ours = new Set(flattenCeilings(openkey));
  const theirs = new Set(flattenCeilings(one));
  return { onlyOpenKey: [...ours].filter((e) => !theirs.has(e)), onlyOne: [...theirs].filter((e) => !ours.has(e)) };
}

export interface OnePin { repo: string; path: string; ref: string | null }

export const ONE_REPO = 'TinyCloudLabs/tinychat';
// Plain segments only: no `%`, `\`, `?`, `#`, and none starting with a dot, so no `.`/`..` however it is encoded.
const PIN_PATH = /^[A-Za-z0-9_-][A-Za-z0-9._-]*(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$/;

export function parsePin(raw: unknown): OnePin {
  const pin = raw as Partial<OnePin> | null;
  if (!pin || pin.repo !== ONE_REPO || typeof pin.path !== 'string' || !PIN_PATH.test(pin.path)) {
    throw new Error(`one.pin.json needs "repo" (${ONE_REPO}) and a plain "path"`);
  }
  // A commit, never a branch: the check must read the same bytes tomorrow that it read today.
  if (pin.ref !== null && !(typeof pin.ref === 'string' && /^[0-9a-f]{40}$/.test(pin.ref))) throw new Error('one.pin.json "ref" must be null or a 40-character commit sha');
  return { repo: pin.repo, path: pin.path, ref: pin.ref ?? null };
}

/** The one place the pinned file is read from. Throws unless the URL is exactly `/<repo>/<sha>/<path>` on the raw host. */
export function pinUrl(pin: OnePin & { ref: string }): URL {
  const url = new URL(`https://raw.githubusercontent.com/${pin.repo}/${pin.ref}/${pin.path}`);
  if (url.host !== 'raw.githubusercontent.com' || url.search !== '' || url.hash !== '' || url.pathname !== `/${pin.repo}/${pin.ref}/${pin.path}`) {
    throw new Error('one.pin.json does not name a plain file path');
  }
  return url;
}

// tinychat is a public repository, so the pinned commit is read without a token or any secret.
async function fetchPinned(pin: OnePin & { ref: string }): Promise<unknown> {
  const response = await fetch(pinUrl(pin));
  if (!response.ok) throw new Error(`could not read ${pin.repo}@${pin.ref}:${pin.path} (${response.status})`);
  return response.json();
}

export function describeParity(parity: CeilingParity): string[] {
  const show = (entry: string) => entry.split('\t').join(' ');
  return [...parity.onlyOpenKey.map((e) => `only in OpenKey's ceilings: ${show(e)}`), ...parity.onlyOne.map((e) => `only in One's file: ${show(e)}`)];
}

async function main(argv: string[]): Promise<number> {
  const openkey = JSON.parse(readFileSync(new URL('./step-up-ceilings/phase1.json', import.meta.url), 'utf8')) as unknown;
  flattenCeilings(openkey);
  const flag = (name: string) => argv.indexOf(name);
  const local = flag('--one') >= 0 ? argv[flag('--one') + 1] : undefined;
  let one: unknown;
  if (local) one = JSON.parse(readFileSync(local, 'utf8'));
  else {
    const pin = parsePin(JSON.parse(readFileSync(new URL('./step-up-ceilings/one.pin.json', import.meta.url), 'utf8')));
    if (pin.ref === null) {
      const message = "One's step-up ceilings are not pinned yet (scripts/step-up-ceilings/one.pin.json has no ref): parity not checked.";
      if (argv.includes('--require-pin')) { console.error(message); return 1; }
      console.log(message);
      return 0;
    }
    one = await fetchPinned({ ...pin, ref: pin.ref });
  }
  const differences = describeParity(compareCeilings(openkey, one));
  if (differences.length) { console.error(['Step-up ceilings differ:', ...differences].join('\n')); return 1; }
  console.log('Step-up ceilings match One\'s file entry for entry.');
  return 0;
}

if (import.meta.main) process.exit(await main(process.argv.slice(2)));

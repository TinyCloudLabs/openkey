#!/usr/bin/env node
// Independent recompute of the org-space (kind 2) golden vectors.
//
// This script MUST NOT import the TypeScript parser or classifier. It re-implements the
// parse, canonical JSON, statement rendering, did:key check, and gate order from the
// spec, then compares its outcome with the expected outcome stored in vectors.json.
// Signature recovery uses viem, loaded from apps/api, so the signer check is independent too.
//
// Usage: node scripts/org-space-recompute.mjs [path/to/vectors.json]
//
// Node cross-check: the four accepted vectors were also parsed by the TinyCloud node's own
// siwe-recap parser at tinycloud-node commit 966fa5edeccf848c0846078b247e51f833e58037. The harness
// (build steps, fixtures, verify loop) lives outside this repo at
// ~/scratch/tc1437/plans/k6-rt-harness/README.md. The node parser checks recap structure and that the
// statement matches the decoded resources; it does not check signatures or the classifier's refusal rules,
// so this script remains the source of the expected outcomes.

import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { pathToFileURL, fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const apiRequire = createRequire(path.join(here, '..', 'apps', 'api', 'package.json'));
const viem = await import(pathToFileURL(apiRequire.resolve('viem')).href);

const vectorsPath =
  process.argv[2] ?? path.join(here, '..', 'apps', 'api', 'src', 'services', 'fixtures', 'org-space-v1', 'vectors.json');
const { cases } = JSON.parse(readFileSync(vectorsPath, 'utf8'));

// ---- constants (spec) -------------------------------------------------------
const MAX_BYTES = 16 * 1024;
const CHAIN_ID = 1;
const SKEW_MS = 5 * 60 * 1000;
const MAX_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
const FACT = 'org-space';
const SHARED_INDEX = 'shared-index';
const HOST = 'tinycloud.space/host';
const SCHEMA = 'tinycloud.sql/admin';
const REVOKE = 'tinycloud.delegation/revoke';
const KV_OPS = ['get', 'list', 'metadata', 'put', 'del'];
const CID_RE = /^b[a-z2-7]{50,}$/;
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
// class -> [enabled, required role]
const RULES = {
  'space-host': [true, 'OWNER'],
  'kv-delegation': [true, 'ADMIN'],
  'delegation-revoke': [true, 'OWNER'],
  'renewal-key': [false, 'ADMIN'],
  'sql-statement': [false, 'ADMIN'],
  'writer-prefix': [false, 'ADMIN'],
  hook: [false, 'ADMIN'],
  encryption: [false, 'ADMIN'],
};
const CLASSES = Object.keys(RULES);

class Refusal extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
const malformed = () => new Refusal('org_space_malformed');
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

// ---- helpers ----------------------------------------------------------------
const spaceIdFor = (addr) => `tinycloud:pkh:eip155:${CHAIN_ID}:${addr}:org`;
const adminAccountFor = (addr) => `did:pkh:eip155:${CHAIN_ID}:${addr}`;
function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  return `{${Object.keys(v)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`)
    .join(',')}}`;
}
function base58Decode(s) {
  if (s.length === 0) return null;
  let n = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) return null;
    n = n * 58n + BigInt(i);
  }
  let hex = n === 0n ? '' : n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const body = hex.match(/../g)?.map((h) => parseInt(h, 16)) ?? [];
  let leading = 0;
  for (const ch of s) {
    if (ch !== '1') break;
    leading++;
  }
  return [...Array(leading).fill(0), ...body];
}
function isEd25519DidKey(did) {
  if (!did.startsWith('did:key:z')) return false;
  const bytes = base58Decode(did.slice('did:key:z'.length));
  return bytes !== null && bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01;
}
function kvPathOf(space, resource) {
  const prefix = `${space}/kv/`;
  return resource.startsWith(prefix) ? resource.slice(prefix.length) : null;
}
// Ceiling entries are prefixes. A path must sit strictly beneath one of them.
function kvCeiling(writer) {
  return [
    ['tinycloud.kv/get', 'shared/'],
    ['tinycloud.kv/get', 'config/'],
    ['tinycloud.kv/list', 'shared/'],
    ['tinycloud.kv/list', 'config/'],
    ['tinycloud.kv/metadata', 'shared/'],
    ['tinycloud.kv/metadata', 'config/'],
    ['tinycloud.kv/put', `shared/${writer}/`],
    ['tinycloud.kv/put', 'config/'],
    ['tinycloud.kv/del', 'shared/'],
  ];
}
function abilityClass(ability, resource, space) {
  if (ability === HOST) return 'space-host';
  if (ability === SCHEMA && resource === `${space}/sql/${SHARED_INDEX}`) return 'space-host';
  if (ability === REVOKE) return 'delegation-revoke';
  if (KV_OPS.some((op) => ability === `tinycloud.kv/${op}`)) return 'kv-delegation';
  if (ability.startsWith('tinycloud.sql/')) return 'sql-statement';
  if (ability.startsWith('tinycloud.hooks/')) return 'hook';
  if (ability.startsWith('tinycloud.encryption/')) return 'encryption';
  return null;
}

// ---- parse ------------------------------------------------------------------
function parse(message) {
  if (Buffer.byteLength(message, 'utf8') > MAX_BYTES) throw new Refusal('org_space_too_large');
  const lines = message.split('\n');
  if (lines.length !== 13) throw malformed();
  const header = /^([a-z0-9.-]+) wants you to sign in with your Ethereum account:$/.exec(lines[0]);
  if (!header) throw malformed();
  const address = /^(0x[0-9a-fA-F]{40})$/.exec(lines[1])?.[1];
  if (!address) throw malformed();
  const uri = /^URI: (.+)$/.exec(lines[5])?.[1];
  if (!uri) throw malformed();
  if (lines[6] !== 'Version: 1') throw malformed();
  const chain = /^Chain ID: (\d+)$/.exec(lines[7])?.[1];
  if (chain === undefined) throw malformed();
  if (chain !== String(CHAIN_ID)) throw new Refusal('org_space_chain_refused');
  const nonce = /^Nonce: ([A-Za-z0-9]{8,})$/.exec(lines[8])?.[1];
  if (!nonce) throw malformed();
  const issuedAt = /^Issued At: (.+)$/.exec(lines[9])?.[1];
  const expirationTime = /^Expiration Time: (.+)$/.exec(lines[10])?.[1];
  if (!issuedAt || !expirationTime) throw malformed();
  if (lines[11] !== 'Resources:') throw malformed();
  const b64 = /^- urn:recap:([A-Za-z0-9_=-]+)$/.exec(lines[12])?.[1];
  if (!b64) throw malformed();

  let payload;
  try {
    payload = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
  } catch {
    throw malformed();
  }
  if (!isObj(payload)) throw malformed();
  if (Object.keys(payload).sort().join(',') !== 'att,fct,prf') throw malformed();
  // Delegation chains are not signable in v1: prf must be the empty array.
  if (!Array.isArray(payload.prf) || payload.prf.length !== 0) throw malformed();

  const fct = payload.fct;
  if (!Array.isArray(fct) || fct.length !== 1 || !isObj(fct[0])) throw malformed();
  if (Object.keys(fct[0]).join(',') !== FACT) throw malformed();
  const fv = fct[0][FACT];
  if (!isObj(fv)) throw malformed();
  if (Object.keys(fv).sort().join(',') !== 'adminAccount,class,grantId') throw malformed();
  if (typeof fv.adminAccount !== 'string' || typeof fv.class !== 'string' || typeof fv.grantId !== 'string') {
    throw malformed();
  }

  if (!isObj(payload.att)) throw malformed();
  const att = [];
  for (const [resource, abilities] of Object.entries(payload.att)) {
    if (!isObj(abilities)) throw malformed();
    for (const [ability, caveats] of Object.entries(abilities)) {
      if (!Array.isArray(caveats) || caveats.length !== 1 || !isObj(caveats[0])) throw malformed();
      if (Object.keys(caveats[0]).length !== 0) throw new Refusal('org_space_ability_refused');
      att.push({ resource, ability });
    }
  }
  if (att.length === 0) throw malformed();
  return {
    domain: header[1],
    address,
    uri,
    nonce,
    issuedAt,
    expirationTime,
    att,
    fact: { adminAccount: fv.adminAccount, class: fv.class, grantId: fv.grantId },
  };
}

// ---- render -----------------------------------------------------------------
// Human line names the org and the admin. The node's ReCap statement suffix follows it.
function humanLine(p) {
  const admin = p.fact.adminAccount;
  if (p.fact.class === 'space-host') return `Host org ${p.address} space for admin ${admin}.`;
  if (p.fact.class === 'kv-delegation') return `Grant ${p.uri} kv access in org ${p.address} space for admin ${admin}.`;
  if (p.fact.class === 'delegation-revoke') {
    const cid = p.att[0].resource.slice('urn:cid:'.length);
    return `Revoke delegation ${cid} in org ${p.address} space for admin ${admin}.`;
  }
  throw new Refusal('org_space_class_not_enabled');
}
// Node statement suffix: one clause per grant, sorted by resource then ability.
function recapClauses(att) {
  const sorted = [...att].sort((a, b) => {
    if (a.resource !== b.resource) return a.resource < b.resource ? -1 : 1;
    if (a.ability === b.ability) return 0;
    return a.ability < b.ability ? -1 : 1;
  });
  return sorted
    .map(({ resource, ability }, i) => {
      const cut = ability.lastIndexOf('/');
      return `(${i + 1}) '${ability.slice(0, cut)}': '${ability.slice(cut + 1)}' for '${resource}'.`;
    })
    .join(' ');
}
function statementOf(p) {
  return `${humanLine(p)} I further authorize the stated URI to perform the following actions on my behalf: ${recapClauses(p.att)}`;
}
function render(p) {
  const resources = {};
  for (const { resource, ability } of p.att) (resources[resource] ??= {})[ability] = [{}];
  const payload = {
    att: resources,
    fct: [{ [FACT]: { adminAccount: p.fact.adminAccount, class: p.fact.class, grantId: p.fact.grantId } }],
    prf: [],
  };
  const b64 = Buffer.from(canonical(payload), 'utf8').toString('base64url');
  const validity = null;
  return [
    `${p.domain} wants you to sign in with your Ethereum account:`,
    p.address,
    '',
    statementOf(p),
    '',
    `URI: ${p.uri}`,
    'Version: 1',
    `Chain ID: ${CHAIN_ID}`,
    `Nonce: ${p.nonce}`,
    `Issued At: ${p.issuedAt}`,
    `Expiration Time: ${p.expirationTime}`,
    'Resources:',
    `- urn:recap:${b64}`,
  ].join('\n');
}

// ---- classify (gate order mirrors the spec) ---------------------------------
function classify(message, ctx) {
  const p = parse(message);
  const declared = p.fact.class;
  if (!CLASSES.includes(declared)) throw malformed();
  if (!RULES[declared][0]) throw new Refusal('org_space_class_not_enabled');
  if (p.att.some((a) => a.ability.startsWith('tinycloud.credentials/'))) {
    throw new Refusal('credentials_capability_refused');
  }
  if (!ctx.allowedOrigins.includes(ctx.requestingOrigin)) throw new Refusal('org_space_origin_mismatch');
  if (p.domain !== new URL(ctx.requestingOrigin).host) throw new Refusal('org_space_origin_mismatch');
  if (p.address !== ctx.address) throw new Refusal('org_space_address_mismatch');
  if (p.fact.adminAccount !== adminAccountFor(ctx.adminAddress)) throw new Refusal('org_space_grant_mismatch');
  if (p.fact.grantId !== ctx.grantId) throw new Refusal('org_space_grant_mismatch');

  const space = spaceIdFor(ctx.address);
  const derived = new Set();
  for (const { resource, ability } of p.att) {
    const cls = abilityClass(ability, resource, space);
    if (cls === null) throw new Refusal('org_space_ability_refused');
    derived.add(cls);
  }
  if (derived.size !== 1) throw new Refusal('org_space_mixed_classes');
  const derivedClass = [...derived][0];
  if (!RULES[derivedClass][0]) throw new Refusal('org_space_class_not_enabled');
  if (derivedClass !== declared) throw new Refusal('org_space_class_mismatch');

  if (declared === 'space-host') {
    // Exact grant set: space host plus shared-index schema. Host-only and schema-only are refused.
    const wanted = [`${HOST}|${space}/space`, `${SCHEMA}|${space}/sql/${SHARED_INDEX}`].sort();
    const actual = p.att.map(({ resource, ability }) => `${ability}|${resource}`).sort();
    if (actual.length !== wanted.length || actual.some((k, i) => k !== wanted[i])) {
      throw new Refusal('org_space_resource_refused');
    }
    if (!isEd25519DidKey(p.uri)) throw new Refusal('org_space_recipient_refused');
  } else if (declared === 'kv-delegation') {
    const ceiling = kvCeiling(ctx.adminAddress);
    for (const { resource, ability } of p.att) {
      const path = kvPathOf(space, resource);
      const permitted =
        path !== null && ceiling.some(([a, prefix]) => a === ability && path.startsWith(prefix));
      if (!permitted) throw new Refusal('org_space_resource_refused');
    }
    if (!isEd25519DidKey(p.uri)) throw new Refusal('org_space_recipient_refused');
  } else if (declared === 'delegation-revoke') {
    if (p.att.length !== 1) throw new Refusal('org_space_resource_refused');
    const only = p.att[0];
    if (!only.resource.startsWith('urn:cid:') || !CID_RE.test(only.resource.slice('urn:cid:'.length))) {
      throw new Refusal('org_space_resource_refused');
    }
    if (p.uri !== space) throw new Refusal('org_space_resource_refused');
  }

  const required = RULES[declared][1];
  const roleOk = required === 'ADMIN' || ctx.role === 'OWNER';
  if (!roleOk) throw new Refusal('org_space_role_insufficient');

  const now = Date.parse(ctx.now);
  const issued = Date.parse(p.issuedAt);
  const expires = Date.parse(p.expirationTime);
  if (!Number.isFinite(issued) || !Number.isFinite(expires)) throw new Refusal('org_space_time_invalid');
  if (Math.abs(issued - now) > SKEW_MS) throw new Refusal('org_space_time_invalid');
  if (expires <= now || expires <= issued) throw new Refusal('org_space_time_invalid');
  if (expires - issued > MAX_LIFETIME_MS) throw new Refusal('org_space_lifetime_exceeded');

  if (render(p) !== message) throw new Refusal('org_space_not_canonical');
  return { ok: true, kind: `org-space/${declared}`, role: required };
}

// ---- run --------------------------------------------------------------------
let failures = 0;
for (const c of cases) {
  let got;
  try {
    got = { ...classify(c.message, c.ctx), ok: true };
  } catch (e) {
    if (!(e instanceof Refusal)) throw e;
    got = { ok: false, code: e.code };
  }
  const want = c.expected;
  const match =
    got.ok === want.ok &&
    (got.ok ? got.kind === want.kind && got.role === want.role : got.code === want.code);
  // Signature must recover to the claimed address, independently of the classifier.
  const recovered = await viem.recoverMessageAddress({ message: c.message, signature: c.signature });
  const sigOk = recovered.toLowerCase() === c.address.toLowerCase();
  const pass = match && sigOk;
  if (!pass) failures++;
  const detail = got.ok ? `${got.kind} ${got.role}` : got.code;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${c.name.padEnd(40)} ${detail}${sigOk ? '' : '  [signature does not recover]'}`);
}
console.log(`\n${cases.length - failures}/${cases.length} vectors match`);
process.exit(failures === 0 ? 0 : 1);

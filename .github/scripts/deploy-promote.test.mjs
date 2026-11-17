// Behavior of deploy-api.yml's image promotion steps, run as the workflow runs them (bash) with stub `docker`
// and `gh` on PATH. The deploy job itself needs the `production` environment, so this is the only place the
// refusals ("an old tag that never passed the Review path must not deploy", "a swapped image is not pushed")
// can fail before a real deploy does. Run by review-path.yml with the other workflow script tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { gzipSync } from 'node:zlib';
import { join } from 'node:path';

const workflow = readFileSync(new URL('../workflows/deploy-api.yml', import.meta.url), 'utf8').split('\n');

/** The `run: |` body of the step with this name, dedented. */
function stepScript(name) {
  const start = workflow.findIndex((line) => line.trim() === `- name: ${name}`);
  assert.notEqual(start, -1, `deploy-api.yml has no step "${name}"`);
  const run = workflow.findIndex((line, i) => i > start && /^\s+run: [|>]/.test(line));
  assert.notEqual(run, -1, `step "${name}" has no run block`);
  const indent = workflow[run].match(/^\s*/)[0].length;
  const body = [];
  for (const line of workflow.slice(run + 1)) {
    if (line.trim() !== '' && line.match(/^\s*/)[0].length <= indent) break;
    body.push(line.slice(indent + 2));
  }
  return body.join('\n');
}

const SHA = 'a'.repeat(40);
const TESTED = 'sha256:' + '1'.repeat(64);
const OTHER = 'sha256:' + '2'.repeat(64);
const DIGEST = 'sha256:' + 'd'.repeat(64);

const DOCKER = `#!/bin/bash
echo "docker $*" >> "$STUB_LOG"
if [ "$1 $2 $3" = "buildx imagetools inspect" ]; then
  if [[ "$*" == *--raw* ]]; then
    if [ -n "$REGISTRY_CONFIG" ]; then echo "{\\"config\\":{\\"digest\\":\\"$REGISTRY_CONFIG\\"}}"; else echo '{"manifests":[]}'; fi
  elif [[ "$*" == *Manifest.Digest* ]]; then echo "\\"$DIGEST\\""
  else [ "$TAG_EXISTS" = 1 ]; fi
  exit $?
fi
if [ "$1" = load ]; then cat > /dev/null; fi
if [ "$1" = image ]; then
  if [[ "$*" == *"{{.Id}}"* ]]; then echo "$LOADED_ID"; else echo "GIT_SHA=$GIT_SHA_LABEL"; fi
fi
exit 0
`;

const GH = `#!/bin/bash
echo "gh $*" >> "$STUB_LOG"
if [ "$2" = list ]; then printf '%s' "$RUN_ID"; exit 0; fi
if [ "$1" = api ]; then printf '%s' "$ARTIFACTS"; exit 0; fi
exit 1
`;

function run(script, env = {}, recordedId = TESTED) {
  const dir = mkdtempSync(join(tmpdir(), 'deploy-promote-'));
  try {
    mkdirSync(join(dir, 'bin'));
    mkdirSync(join(dir, 'rt', 'api-image'), { recursive: true });
    for (const [name, body] of [['docker', DOCKER], ['gh', GH]]) {
      writeFileSync(join(dir, 'bin', name), body);
      chmodSync(join(dir, 'bin', name), 0o755);
    }
    writeFileSync(join(dir, 'rt', 'api-image', 'api-image.tar.gz'), gzipSync('image'));
    writeFileSync(join(dir, 'rt', 'api-image', 'api-image.id'), recordedId + '\n');
    writeFileSync(join(dir, 'log'), '');
    writeFileSync(join(dir, 'out'), '');
    writeFileSync(join(dir, 'summary'), '');
    const result = spawnSync('bash', ['-c', script], {
      cwd: dir,
      encoding: 'utf8',
      env: {
        PATH: `${join(dir, 'bin')}:${process.env.PATH}`, HOME: dir,
        STUB_LOG: join(dir, 'log'), GITHUB_OUTPUT: join(dir, 'out'), GITHUB_STEP_SUMMARY: join(dir, 'summary'),
        RUNNER_TEMP: join(dir, 'rt'), GITHUB_SHA: SHA, GITHUB_REPOSITORY: 'TinyCloudLabs/openkey',
        DOCKER_IMAGE: 'skgbafa/openkey-api', DIGEST, GIT_SHA_LABEL: SHA, ...env,
      },
    });
    return {
      status: result.status, stderr: result.stdout + result.stderr,
      log: readFileSync(join(dir, 'log'), 'utf8'), out: readFileSync(join(dir, 'out'), 'utf8'),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const promote = stepScript('Push that image under its commit tag and pin its digest');
const pushes = (log) => log.split('\n').filter((line) => line.startsWith('docker push')).length;

test('a commit tag already in the registry is refused unless it is the image the Review path ran', () => {
  const stale = run(promote, { TAG_EXISTS: '1', REGISTRY_CONFIG: OTHER });
  assert.notEqual(stale.status, 0);
  assert.match(stale.stderr, /not the image the Review path ran/);
  assert.equal(stale.out, '');
  assert.equal(pushes(stale.log), 0);

  const index = run(promote, { TAG_EXISTS: '1', REGISTRY_CONFIG: '' });
  assert.notEqual(index.status, 0, 'a tag that is not a single image is refused');
  assert.equal(index.out, '');
});

test('the tested image already in the registry is reused, pinned by digest, and not pushed again', () => {
  const reused = run(promote, { TAG_EXISTS: '1', REGISTRY_CONFIG: TESTED });
  assert.equal(reused.status, 0, reused.stderr);
  assert.equal(pushes(reused.log), 0);
  assert.equal(reused.out.trim(), `image_ref=skgbafa/openkey-api@${DIGEST}`);
});

test('a fresh image is pushed only if its loaded id is the recorded id, then pinned by digest', () => {
  const swapped = run(promote, { TAG_EXISTS: '0', LOADED_ID: OTHER });
  assert.notEqual(swapped.status, 0);
  assert.match(swapped.stderr, /not the image the Review path ran/);
  assert.equal(pushes(swapped.log), 0);

  const empty = run(promote, { TAG_EXISTS: '0', LOADED_ID: TESTED }, '');
  assert.notEqual(empty.status, 0, 'an artifact with no recorded id is refused');
  assert.equal(pushes(empty.log), 0);

  const mislabeled = run(promote, { TAG_EXISTS: '0', LOADED_ID: TESTED, GIT_SHA_LABEL: 'b'.repeat(40) });
  assert.notEqual(mislabeled.status, 0, 'the GIT_SHA label stays a second check');
  assert.equal(pushes(mislabeled.log), 0);

  const fresh = run(promote, { TAG_EXISTS: '0', LOADED_ID: TESTED });
  assert.equal(fresh.status, 0, fresh.stderr);
  assert.equal(pushes(fresh.log), 1);
  assert.match(fresh.log, new RegExp(`docker push skgbafa/openkey-api:${SHA}`));
  assert.equal(fresh.out.trim(), `image_ref=skgbafa/openkey-api@${DIGEST}`);
});

test('every deploy needs a passing Review path run with an unexpired image artifact', () => {
  const find = stepScript('Find the image that passed the Review path');
  const none = run(find, { RUN_ID: '' });
  assert.notEqual(none.status, 0, 'no passing run: not even an existing tag is deployed');
  assert.match(none.stderr, /No successful Review path run/);

  const expired = run(find, { RUN_ID: '42', ARTIFACTS: '0' });
  assert.notEqual(expired.status, 0);
  assert.match(expired.stderr, /missing or expired/);

  const found = run(find, { RUN_ID: '42', ARTIFACTS: '1' });
  assert.equal(found.status, 0, found.stderr);
  assert.equal(found.out.trim(), 'run_id=42');
});

test('the compose file runs the image by digest, with no tag left', () => {
  const dir = mkdtempSync(join(tmpdir(), 'deploy-compose-'));
  try {
    writeFileSync(join(dir, 'docker-compose.prod.yml'), 'services:\n  api:\n    image: ${DOCKER_IMAGE}\n');
    const result = spawnSync('bash', ['-c', stepScript('Update compose with the image digest')], {
      cwd: dir, encoding: 'utf8', env: { PATH: process.env.PATH, IMAGE_REF: `skgbafa/openkey-api@${DIGEST}` },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(join(dir, 'docker-compose.prod.yml'), 'utf8'), `services:\n  api:\n    image: skgbafa/openkey-api@${DIGEST}\n`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

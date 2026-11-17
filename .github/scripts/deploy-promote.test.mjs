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
    if [[ "$*" == *@sha256:* ]]; then CFG="\${PINNED_CONFIG-$REGISTRY_CONFIG}"; else CFG="$REGISTRY_CONFIG"; fi
    if [ -n "$CFG" ]; then echo "{\\"config\\":{\\"digest\\":\\"$CFG\\"}}"; else echo '{"manifests":[]}'; fi
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
case "$*" in
  *"-X POST"*"/statuses"*) exit 0 ;;
  *"-X POST"*"/deployments --input"*) cat >> "$STUB_STDIN"; echo 101; exit 0 ;;
  *"/statuses"*) printf '%s' "$SUCCESS_COUNT"; exit 0 ;;
  *"deployments?environment"*) printf '%s' "$DEPLOYMENT_IDS"; exit 0 ;;
  *"/artifacts"*) printf '%s' "$ARTIFACTS"; exit 0 ;;
esac
if [ "$2" = list ]; then printf '%s' "$RUN_ID"; exit 0; fi
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
    writeFileSync(join(dir, 'stdin'), '');
    writeFileSync(join(dir, 'out'), '');
    writeFileSync(join(dir, 'summary'), '');
    const result = spawnSync('bash', ['-c', script], {
      cwd: dir,
      encoding: 'utf8',
      env: {
        PATH: `${join(dir, 'bin')}:${process.env.PATH}`, HOME: dir,
        STUB_LOG: join(dir, 'log'), STUB_STDIN: join(dir, 'stdin'), GITHUB_OUTPUT: join(dir, 'out'), GITHUB_STEP_SUMMARY: join(dir, 'summary'),
        RUNNER_TEMP: join(dir, 'rt'), GITHUB_SHA: SHA, GITHUB_REPOSITORY: 'TinyCloudLabs/openkey', GITHUB_ACTOR: 'release-coordinator', GITHUB_RUN_ID: '555',
        DOCKER_IMAGE: 'skgbafa/openkey-api', DIGEST, GIT_SHA_LABEL: SHA, ...env,
      },
    });
    return {
      status: result.status, stderr: result.stdout + result.stderr,
      log: readFileSync(join(dir, 'log'), 'utf8'), out: readFileSync(join(dir, 'out'), 'utf8'),
      stdin: readFileSync(join(dir, 'stdin'), 'utf8'), summary: readFileSync(join(dir, 'summary'), 'utf8'),
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

  // After the push the registry serves the tested image under the tag.
  const fresh = run(promote, { TAG_EXISTS: '0', LOADED_ID: TESTED, REGISTRY_CONFIG: TESTED });
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

test('the digest the compose file will pin is itself checked against the tested image, on both paths', () => {
  // The tag moved to another image between the tag checks and the digest lookup.
  const pushed = run(promote, { TAG_EXISTS: '0', LOADED_ID: TESTED, PINNED_CONFIG: OTHER });
  assert.notEqual(pushed.status, 0);
  assert.match(pushed.stderr, /refusing to deploy it/);
  assert.equal(pushed.out, '', 'no image_ref is handed to the compose step');

  const reused = run(promote, { TAG_EXISTS: '1', REGISTRY_CONFIG: TESTED, PINNED_CONFIG: OTHER });
  assert.notEqual(reused.status, 0);
  assert.equal(reused.out, '');

  const index = run(promote, { TAG_EXISTS: '1', REGISTRY_CONFIG: TESTED, PINNED_CONFIG: '' });
  assert.notEqual(index.status, 0, 'a digest that is not a single image is refused');
});

const rollback = stepScript('Roll back to a previously deployed image');
const ROLLBACK = { ROLLBACK_DIGEST: DIGEST, ROLLBACK_REASON: 'sign-in regression in the new image', DEPLOYMENT_IDS: '7\n9', SUCCESS_COUNT: '1', TAG_EXISTS: '1' };

test('rollback promotes only an image that was deployed before, with a reason', () => {
  const ok = run(rollback, ROLLBACK);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(ok.out.trim(), `image_ref=skgbafa/openkey-api@${DIGEST}`);
  assert.match(ok.summary, /Reason: sign-in regression in the new image/);
  assert.match(ok.summary, new RegExp(DIGEST));
  assert.equal(pushes(ok.log), 0, 'a rollback never pushes or builds');

  for (const reason of ['', '   \n\t ']) {
    const noReason = run(rollback, { ...ROLLBACK, ROLLBACK_REASON: reason });
    assert.notEqual(noReason.status, 0);
    assert.match(noReason.stderr, /rollback_reason is required/);
    assert.equal(noReason.out, '');
  }
  for (const digest of ['latest', 'sha256:abc', DIGEST.toUpperCase(), `${DIGEST}\nx`]) {
    const bad = run(rollback, { ...ROLLBACK, ROLLBACK_DIGEST: digest });
    assert.notEqual(bad.status, 0, digest);
    assert.equal(bad.out, '');
  }

  const never = run(rollback, { ...ROLLBACK, DEPLOYMENT_IDS: '' });
  assert.notEqual(never.status, 0, 'an image with no deployment record was never deployed');
  assert.match(never.stderr, /never deployed/);
  assert.equal(never.out, '');

  const failed = run(rollback, { ...ROLLBACK, SUCCESS_COUNT: '0' });
  assert.notEqual(failed.status, 0, 'a deployment that did not succeed does not count');
  assert.equal(failed.out, '');

  const gone = run(rollback, { ...ROLLBACK, TAG_EXISTS: '0' });
  assert.notEqual(gone.status, 0, 'an image no longer in the registry cannot be rolled back to');
  assert.equal(gone.out, '');
});

test('the deployed digest is recorded for later rollbacks, with the reason on a rollback', () => {
  const record = stepScript('Record the deployed image');
  const env = { IMAGE_REF: `skgbafa/openkey-api@${DIGEST}`, ROLLBACK_REASON: '', IS_ROLLBACK: 'false' };
  const deploy = run(record, env);
  assert.equal(deploy.status, 0, deploy.stderr);
  const body = JSON.parse(deploy.stdin);
  assert.equal(body.environment, 'openkey-api-image');
  assert.deepEqual(body.required_contexts, []);
  assert.equal(body.payload.digest, DIGEST);
  assert.equal(body.payload.rollback, false);
  assert.match(deploy.log, /deployments\/101\/statuses.*state=success/);

  const back = JSON.parse(run(record, { ...env, ROLLBACK_REASON: 'bad release', IS_ROLLBACK: 'true' }).stdin);
  assert.equal(back.payload.rollback, true);
  assert.equal(back.payload.reason, 'bad release');
});

test('the deploy summary prints the digest that runs, not only a tag', () => {
  const summary = run(stepScript('Record deployed commit'), { IMAGE_REF: `skgbafa/openkey-api@${DIGEST}`, GITHUB_SERVER_URL: 'https://github.com' });
  assert.equal(summary.status, 0, summary.stderr);
  assert.match(summary.summary, new RegExp(`Image: \`skgbafa/openkey-api@${DIGEST}\``));
  assert.doesNotMatch(summary.summary, new RegExp(`skgbafa/openkey-api:${SHA}`));
});

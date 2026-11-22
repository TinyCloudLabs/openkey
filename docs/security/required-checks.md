# Pre-release security check

Nothing reaches production or npm unless these checks are green on the exact commit that ships.

## The checks

| Check (job name) | Workflow | Runs on | What fails it |
|---|---|---|---|
| `API test suite` | api-tests.yml | PR, push main | API unit suite (delegation, origin refusal, app-key refusal, …) |
| `Renewal lease tests on Postgres` | api-tests.yml | PR, push main | lease lock and race cases on real Postgres |
| `Web browser specs` | web-browser-tests.yml | PR, push main | Playwright specs (skips inside when the web is untouched) |
| `dstack key-derivation known answer` | dstack-key-guard.yml | PR, push main | any change to the sealing-key derivation |
| `TEE mode fails closed` | dstack-key-guard.yml | PR, push main | API starts in production without `TEE_MODE=production` |
| `Major release sign-off` | major-release-guard.yml | PR only | a major bump without a human sign-off commit |
| `gitleaks` | security.yml | PR, push main | a secret in the PR's commits (PR) or anywhere in history outside the baseline (main) |
| `Web artifact audit` | security.yml | PR, push main | the Cloudflare Pages build fails `bun run audit:web` |
| `API image scan` | security.yml | PR, push main | trivy finds a fixable CRITICAL/HIGH or a secret in the API image that isn't in `.trivyignore.yaml` |

None of them has a `paths:` filter, so each reports on every PR and can be required.

## Where they gate a release

- **Merge to main**: the ruleset below (Amos applies it).
- **API deploy** (`deploy-api.yml`, `deploy` job) and **npm publish / version PR**
  (`changesets.yml`, `release` job): the first step after checkout runs
  `.github/scripts/require-green.mjs`, which fails unless every check in
  `.github/required-checks.json` concluded `success` on `$GITHUB_SHA`. It waits up to 40 min
  for checks still running; a missing, skipped, cancelled or failed check, or a GitHub API
  error, fails the job. Only GitHub Actions' own check runs count. `Major release sign-off` is
  PR-only, so it isn't in that list; the ruleset enforces it at merge.
- **API image**: the deploy job now builds the image without pushing it, runs
  `scripts/security/scan-image.sh` on that exact image, and only then pushes it.
- **Web publish**: Cloudflare Pages builds with `bun run build --filter @openkey/web`, and the web
  app's `build` script now ends with `bun run audit:web`, so a finding fails the Pages build
  itself and leaves nothing to promote. The release coordinator's publish (retrying the skipped
  production deployment for a commit) can only promote a build that passed the audit.

### `bun run audit:web`

Run after a web build (`bun run build --filter @openkey/web` runs it for you). It audits the
Cloudflare Pages output (`apps/web/.svelte-kit/cloudflare`) plus the server bundle the worker
imports (`.svelte-kit/output/server`, `.svelte-kit/cloudflare-tmp`) with
`scripts/security/audit-artifact.mjs`:

- no sourcemaps, `sourceMappingURL` comments or dotfiles; file types on an allow-list;
- no secret shapes: `sk_live_`/`rk_live_`, `-----BEGIN`, `0x` + 64 hex, `xoxb-`/`xoxp-`, JWTs,
  `AKIA…`, `ghp_`…, `github_pat_`, `npm_`;
- no machine-local names: `*.ts.net`, home-directory paths, `localhost:<port>` / `127.0.0.1:<port>`;
- then `gitleaks dir --redact` (pinned, sha256-checked) on each directory.

Reports name the file and the pattern, never the value. A hit is a finding: fix the source,
don't widen the allow-list without a security review.

## Baselines

- `.gitleaksignore`: 40 fingerprints from the full-history scan on 2026-11-22, each reviewed
  (test vectors, migration checksums, the public Phala app id, throwaway test keys). None is a
  live credential. `.gitleaks.toml` allowlists `did:key` identifiers, two well-known test
  private keys and migration checksum rows by exact shape.
- `.trivyignore.yaml`: the 82 fixable CRITICAL/HIGH advisories in the production image of
  `d1d16d4f` (2026-11-22), each pinned to its package version by purl. They are known debt,
  not accepted risk: remove an entry when its upgrade lands.

Pinned tools (`scripts/security/install-tool.mjs`): gitleaks 8.30.1, trivy 0.76.2, with sha256
from each release's checksums file.

## Ruleset change for Amos

Today the main ruleset (id `27215997`) only blocks force-push and deletion; no check is required.
Naomi's rule: a check becomes required only after it has passed once on main. The first six
checks already have (main `d1d16d4f`, 2026-11-22, except `Major release sign-off`, which is
PR-only and passes on every PR). The three security checks have not, so this is two steps.

The required-status-checks rule applies to every update of main, so it also blocks a direct push
whose commit lacks green checks. `integration_id` 15368 is GitHub Actions: a check with the same
name from another app doesn't count.

### Current (read 2026-11-22)

`gh api repos/TinyCloudLabs/openkey/rulesets/27215997`:

```json
{
  "name": "main: block force-push and deletion",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
  "rules": [
    { "type": "non_fast_forward" },
    { "type": "deletion" }
  ],
  "bypass_actors": []
}
```

### Step 1: now

```sh
gh api -X PUT repos/TinyCloudLabs/openkey/rulesets/27215997 --input step1.json
```

`step1.json`:

```json
{
  "name": "main: block force-push and deletion, require checks",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
  "rules": [
    { "type": "non_fast_forward" },
    { "type": "deletion" },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          { "context": "API test suite", "integration_id": 15368 },
          { "context": "Renewal lease tests on Postgres", "integration_id": 15368 },
          { "context": "Web browser specs", "integration_id": 15368 },
          { "context": "dstack key-derivation known answer", "integration_id": 15368 },
          { "context": "TEE mode fails closed", "integration_id": 15368 },
          { "context": "Major release sign-off", "integration_id": 15368 }
        ]
      }
    }
  ],
  "bypass_actors": []
}
```

### Step 2: after this PR merges and `gitleaks`, `Web artifact audit` and `API image scan` have passed on a main commit

Same `PUT` with the three added to `required_status_checks`:

```json
          { "context": "gitleaks", "integration_id": 15368 },
          { "context": "Web artifact audit", "integration_id": 15368 },
          { "context": "API image scan", "integration_id": 15368 }
```

### Verify

```sh
gh api repos/TinyCloudLabs/openkey/rulesets/27215997 --jq '.rules[] | select(.type=="required_status_checks") | .parameters.required_status_checks[].context'
gh api repos/TinyCloudLabs/openkey/rules/branches/main --jq '.[].type'
```

### Undo

Put the current JSON back:

```sh
gh api -X PUT repos/TinyCloudLabs/openkey/rulesets/27215997 --input - <<'EOF'
{
  "name": "main: block force-push and deletion",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
  "rules": [ { "type": "non_fast_forward" }, { "type": "deletion" } ],
  "bypass_actors": []
}
EOF
```

Undoing the ruleset leaves the deploy and publish gates in place; those change only by a PR to
`.github/required-checks.json`.

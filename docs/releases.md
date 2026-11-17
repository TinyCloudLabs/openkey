# Where releases show up

| What | Where | Created by |
|------|-------|------------|
| npm packages (`@openkey/sdk`, `core`, `types`, `cli`, `sdk-react-native`, `sdk-capacitor`) | [npmjs.com](https://www.npmjs.com/org/openkey) | `changesets.yml` publish step (`bun run publish`) |
| Git tags (`@openkey/sdk@0.12.1-beta.1`) | repo tags | `changeset publish`, pushed by the same step |
| GitHub Releases | [Releases](https://github.com/TinyCloudLabs/openkey/releases) | `changesets.yml` "Create GitHub Releases" step |
| API deploys (Phala) | [Deployments, `production`](https://github.com/TinyCloudLabs/openkey/deployments/production) | `deploy-api.yml` (`environment: production`); its run summary links the deployed commit |
| Web and demo deploys (Cloudflare Pages) | Deployments, `pages-openkey` and `pages-openkey-demo`; Cloudflare check run on the commit | Cloudflare's GitHub integration builds; `record-pages-deployments.yml` mirrors the result as a Deployment |

## GitHub Releases

Every published package version gets one Release on its existing tag:

- Title is the tag name; notes are that package's `CHANGELOG.md` section for the version, plus an npm link. A version with no changelog entry says so.
- Any version with a `-` suffix (`0.12.1-beta.1`) is marked **prerelease**.
- Only a stable `@openkey/sdk` release is marked **latest**.
- Creation is idempotent: a tag that already has a Release is skipped.

The release step runs `scripts/release/create-github-releases.mjs --points-at-head` after `changeset publish` pushed the tags, so what is published to npm is unchanged. Re-running the workflow on the same commit retries a Release that failed.

### Backfill

Releases stopped at `@openkey/sdk@0.7.2`. To create the missing ones for every tag after it (needs `gh` authenticated and `git fetch --tags`):

```sh
node scripts/release/backfill-github-releases.mjs --dry-run   # list what would be created
node scripts/release/backfill-github-releases.mjs             # create them
```

## Deployments

`deploy-api.yml` is manual (`gh workflow run deploy-api.yml --ref main`); its `production` environment makes GitHub record a Deployment per run.

`deploy-api.yml` does not build the image. `review-path.yml` builds it once from the commit on each push to `main`, runs the Review path on it, and on green saves it as the artifact `api-image-<sha>` (30 days) with the image id the build produced. Every deploy needs that passing run and its artifact. The deploy loads the artifact, checks the loaded image's id equals the recorded id (and carries `GIT_SHA=<sha>`), pushes it as `skgbafa/openkey-api:<sha>`, resolves that tag's digest from the registry, checks that digest's own config digest is the recorded id again, and writes `skgbafa/openkey-api@sha256:<digest>` into the compose file, so what runs is pinned by digest. The run summary prints that digest, and the digest is recorded as a Deployment in the environment `openkey-api-image` (payload: digest, commit, run, actor). Nothing is pushed as `latest`. A commit tag already in the registry (a rerun) is reused only if its config digest equals the recorded id; otherwise the deploy refuses. So a deploy with no passing Review path run or no unexpired artifact for its commit (older than 30 days, or from before the Review path existed) fails before any production change. Its run summary also carries the release note for the publish, diffed from the commit production reports on `/health`.

Cloudflare Pages deploys `main` on merge but only reports a check run, not a Deployment. `record-pages-deployments.yml` reacts to each finished `Cloudflare Pages: <project>` check run on `main` and creates a Deployment named `pages-<project>` with the check run as its log link. It does not trigger or alter Pages builds. Only deploys after this workflow is merged are recorded.

### Rollback

`gh workflow run deploy-api.yml --ref main -f rollback_digest=sha256:<digest> -f rollback_reason='<why>'` puts an image that was already deployed back in production. It needs the reason (in the run summary and the Deployment record), refuses an image gone from the registry, builds and pushes nothing, and does not run migrations. Do not `gh run rerun` an older deploy run: it runs that run's own, older workflow.

It refuses a digest that was never deployed. "Deployed" is one of two things, and nothing made by hand counts:
- a Deployment in the environment `openkey-api-image` made by `github-actions[bot]` (the deploy's "Record the deployed image" step), with a success status, whose `payload.run` is a successful `deploy-api.yml` run on `main` that itself uploaded the artifact `deployed-api-image-<digest>` (kept 90 days; any workflow's token shows up as `github-actions[bot]` and can cite a real run id, but only that run can add an artifact to itself, so a record for another digest fails). List them with `gh api 'repos/TinyCloudLabs/openkey/deployments?environment=openkey-api-image' --jq '.[] | [.created_at, .payload.digest, .payload.rollback] | @tsv'`;
- a line `sha256:<digest> <reason>` in `.github/deployed-api-images.txt` (the reason is required), the images that ran in production before the records existed (for example the live digest from `rollback_image` in `scripts/inspect-api-production.ts`). Add a line only by PR, for a digest known to have run.

## Review path

`review-path.yml` runs on every pull request and every push to `main`, as one job named **Review path**. It builds the API image from the commit (`GIT_SHA=<sha>`), runs it against a throwaway Postgres with the tracked migrations and a seeded review account, starts the web app, and drives a real Chromium through review-code sign-in, OAuth consent, the token exchange and the approval screen, plus the refusals reachable without the hosted MCP (`apps/web/tests/review-path/review-path.spec.ts`; each test names the js-sdk review-evidence case whose OpenKey half it covers). It needs no secrets and reaches no registry, Cloudflare, Phala or TinyCloud node. Hosted-staging coverage of the MCP cases is not part of it.

The check always reports, so it can be required: only a diff with no API, web, package, image-build or workflow path skips the heavy steps, and any doubt runs them. It is not required yet; that is a repository setting (branch protection or a ruleset on `main`).

Every push to `main` also writes a release note to the run summary, `touches sign-in/approval: yes|no (PRs ...)`, from the diff of that push (`.github/scripts/review-path-scope.mjs note`). It says `yes` whenever the diff cannot be read.

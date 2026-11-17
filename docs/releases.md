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

Cloudflare Pages deploys `main` on merge but only reports a check run, not a Deployment. `record-pages-deployments.yml` reacts to each finished `Cloudflare Pages: <project>` check run on `main` and creates a Deployment named `pages-<project>` with the check run as its log link. It does not trigger or alter Pages builds. Only deploys after this workflow is merged are recorded.

## Review path

`review-path.yml` runs on every pull request and every push to `main`, as one job named **Review path**. It builds the API image from the commit (`GIT_SHA=<sha>`), runs it against a throwaway Postgres with the tracked migrations and a seeded review account, starts the web app, and drives a real Chromium through review-code sign-in, OAuth consent, the token exchange and the approval screen, plus the refusals reachable without the hosted MCP (`apps/web/tests/review-path/review-path.spec.ts`; each test names the js-sdk review-evidence case whose OpenKey half it covers). It needs no secrets and reaches no registry, Cloudflare, Phala or TinyCloud node. Hosted-staging coverage of the MCP cases is not part of it.

The check always reports, so it can be required: only a diff with no API, web, package, image-build or workflow path skips the heavy steps, and any doubt runs them. It is not required yet; that is a repository setting (branch protection or a ruleset on `main`).

Every push to `main` also writes a release note to the run summary, `touches sign-in/approval: yes|no (PRs ...)`, from the diff of that push (`.github/scripts/review-path-scope.mjs note`). It says `yes` whenever the diff cannot be read.

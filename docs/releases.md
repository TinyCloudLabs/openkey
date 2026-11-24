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

Every deploy and npm publish first requires the pre-release security check to be green on the
exact commit, and the web build audits its own output (`bun run audit:web`); see
[security/required-checks.md](security/required-checks.md).

Cloudflare Pages production auto-deploy is off: a merge alone does not publish
`openkey.so`. The release coordinator manually retries the skipped production
deployment. Pages reports a check run, not a Deployment.
`record-pages-deployments.yml` mirrors each finished `Cloudflare Pages: <project>`
check on `main` as `pages-<project>`; it does not trigger or alter Pages builds.

The Share sender smoke reacts to a completed production `Cloudflare Pages: openkey`
check from Cloudflare's app (`85455`) on `main`, not a push. Demo, other-app,
other-branch and `Branch Preview URL` checks cannot start a production smoke.
An unpublished push starts no smoke and consumes no polling window.

Before running smoke, the publication job fetches every check attempt for the
event's exact commit SHA (`filter=all`, paginated). The highest check-run ID among
completed, non-cancelled, non-preview attempts decides: success runs smoke;
failure or an unknown conclusion fails the workflow; skipped/neutral or no
completed attempt skips smoke with an explicit not-published summary. A newer
unfinished attempt does not override a completed decision. Invalid, missing or
tied matching IDs and incomplete API responses fail closed.

A successful retry supersedes a failed attempt for that same commit, even if
the older failure event arrives later. Superseded non-success attempts are
logged by ID and conclusion. Smoke failures on a published web still fail.
The successful API `workflow_run` and manual-dispatch smoke paths are unchanged.
Only actual smoke jobs share the existing concurrency group; unrelated
`check_run` events cannot displace a queued smoke. Details: TC-3683.

// Preloaded for every `bun test` run (bunfig.toml). The checked-in `terms-release.json` turns the Terms gate
// on (TC-3232), which would answer 403 `terms_required` to every test that signs a fresh account into the
// real API. The API tests exercise everything else with the gate off: this pins the release to "no version".
// The Terms suites set their own release with `mockModules` (the mock replaces this one for the file), and a
// run with OPENKEY_TEST_REAL_TERMS_RELEASE=1 keeps the real file (terms-release-shipped.integration.test.ts).
import { mock } from 'bun:test';

if (process.env.OPENKEY_TEST_REAL_TERMS_RELEASE !== '1') {
  mock.module('../terms-release.json', () => ({
    default: { version: null, requiredVersion: null, textSha256: null, whatChanged: null, privacyChanged: false },
  }));
}

// Preloaded for every `bun test` run (bunfig.toml). A test that leaves TinyCloud setup running in the
// background (a run past its wait, or retries 5, 15 and 45 seconds later) must not log, call the
// background observer or start a retry while a later test runs: after each test, end what it left (TC-2969).
// The module it loads has no side effects, so test runs outside the API are unaffected.
import { afterEach } from 'bun:test';
import { cancelTinyCloudBootstrapBackgroundForTests } from '../services/tinycloud-bootstrap-background';

afterEach(() => {
  cancelTinyCloudBootstrapBackgroundForTests();
});

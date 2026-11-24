// Module stubs for the mounted page tests: the page's account has agreed to the Terms, so its Terms gate is open
// and the gate's screens never render (`emptyUrl` is the test's compiled empty component).
export const termsAcceptedStubs = (emptyUrl: string): Record<string, string> => ({
  '$lib/terms-gate': `export const termsGate = { subscribe(run) { run({ phase: 'open', status: null }); return () => {}; },
    follow() {}, recheck() {}, agreed() {} };
    export const termsRefused = () => {};`,
  '$lib/components/auth/terms-gate.svelte': `export { default } from '${emptyUrl}';`,
});

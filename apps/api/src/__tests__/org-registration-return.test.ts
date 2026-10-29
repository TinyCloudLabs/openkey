/// <reference types="bun" />
import { expect, test } from 'bun:test';
interface RegistrationPageModule { load(event: { url: URL }): unknown }
// Execute the real frontend load hook without pulling SvelteKit's generated types into the API project.
const { load }: RegistrationPageModule = await import(new URL('../../../web/src/routes/auth/register/+page.ts', import.meta.url).href);

test('first-time org registration permits only the exact token-free relative consent return', async () => {
  for (const [returnTo, expected] of [
    ['/org-registration/consent', '/org-registration/consent'],
    ['/org-registration/consent?x', null],
    ['/org-registration/consent#x', null],
    ['//evil/org-registration/consent', null],
    ['https://evil/org-registration/consent', null],
    ['https://openkey.so/org-registration/consent', null],
  ]) {
    const url = new URL('https://openkey.so/auth/register');
    url.searchParams.set('returnTo', returnTo!);
    expect(await load({ url })).toMatchObject({ returnTo: expected });
  }
});

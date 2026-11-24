// TC-3893 (N1 popup-only): route-id matcher tests for `/widget/registry-change` (framed denied).
//
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { isRegistryChangePopupWidgetRoute } from '../routes/widget/registry-change/route-match';

describe('registry-change widget route matcher', () => {
  test('matches popup route id and child routes only', () => {
    expect(isRegistryChangePopupWidgetRoute('/widget/registry-change')).toBe(true);
    expect(isRegistryChangePopupWidgetRoute('/widget/registry-change/step')).toBe(true);
    expect(isRegistryChangePopupWidgetRoute('/widget/embed/registry-change')).toBe(false);
    expect(isRegistryChangePopupWidgetRoute('/widget/registry-change-other')).toBe(false);
    expect(isRegistryChangePopupWidgetRoute('/widget/registry%2Dchange')).toBe(false);
  });
});

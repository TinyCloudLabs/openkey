// TC-3893: route-id matcher tests for `/widget/registry-change` (popup: framed denied)
// and `/widget/embed/registry-change` (embed: frameable, no-referrer).
//
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  isRegistryChangeEmbedWidgetRoute,
  isRegistryChangePopupWidgetRoute,
} from '../routes/widget/registry-change/route-match';

describe('registry-change widget route matchers', () => {
  test('matches popup route id and child routes only', () => {
    expect(isRegistryChangePopupWidgetRoute('/widget/registry-change')).toBe(true);
    expect(isRegistryChangePopupWidgetRoute('/widget/registry-change/step')).toBe(true);
    expect(isRegistryChangePopupWidgetRoute('/widget/embed/registry-change')).toBe(false);
    expect(isRegistryChangePopupWidgetRoute('/widget/registry-change-other')).toBe(false);
    expect(isRegistryChangePopupWidgetRoute('/widget/registry%2Dchange')).toBe(false);
  });

  test('matches embed route id and child routes only', () => {
    expect(isRegistryChangeEmbedWidgetRoute('/widget/embed/registry-change')).toBe(true);
    expect(isRegistryChangeEmbedWidgetRoute('/widget/embed/registry-change/step')).toBe(true);
    expect(isRegistryChangeEmbedWidgetRoute('/widget/registry-change')).toBe(false);
    expect(isRegistryChangeEmbedWidgetRoute('/widget/embed/registry-change-other')).toBe(false);
    expect(isRegistryChangeEmbedWidgetRoute('/widget/embed/registry%2Dchange')).toBe(false);
  });
});

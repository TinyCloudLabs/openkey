import { describe, expect, test } from 'bun:test';
import { createBranding, updateBranding } from './oauth-client-branding';

const ICON = 'https://home.tinycloud.xyz/icons/pwa-512.png';

describe('updating an existing OAuth client (TC-3268)', () => {
  test('updating the name keeps the icon and both theme colours', () => {
    // A name-only run sets CLIENT_NAME and CLIENT_ID; the branding inputs are empty strings, as the
    // workflow passes an unset input.
    const data = updateBranding({ CLIENT_ICON: '', CLIENT_THEME_BACKGROUND_COLOR: '', CLIENT_THEME_ACCENT_COLOR: '' });
    expect(data).toEqual({});
    expect('icon' in data).toBe(false);
    expect('themeBackgroundColor' in data).toBe(false);
    expect('themeAccentColor' in data).toBe(false);
  });

  test('no branding inputs at all also keeps everything', () => {
    expect(updateBranding({})).toEqual({});
  });

  test('a set icon replaces only the icon', () => {
    expect(updateBranding({ CLIENT_ICON: ICON })).toEqual({ icon: ICON });
  });

  test('a set theme colour replaces only that colour', () => {
    expect(updateBranding({ CLIENT_THEME_ACCENT_COLOR: '#09090B' })).toEqual({ themeAccentColor: '#09090B' });
  });

  test('`none` clears the icon and the theme colours, in any case and with spaces', () => {
    expect(
      updateBranding({
        CLIENT_ICON: ' None ',
        CLIENT_THEME_BACKGROUND_COLOR: 'NONE',
        CLIENT_THEME_ACCENT_COLOR: 'none',
      }),
    ).toEqual({ icon: null, themeBackgroundColor: null, themeAccentColor: null });
  });

  test('an invalid icon or colour is refused, not skipped', () => {
    expect(() => updateBranding({ CLIENT_ICON: 'http://example.com/i.png' })).toThrow('HTTPS');
    expect(() => updateBranding({ CLIENT_ICON: 'https://user:pw@example.com/i.png' })).toThrow('without credentials');
    expect(() => updateBranding({ CLIENT_ICON: 'not a url' })).toThrow('HTTPS');
    expect(() => updateBranding({ CLIENT_THEME_BACKGROUND_COLOR: 'red' })).toThrow('CLIENT_THEME_BACKGROUND_COLOR');
    expect(() => updateBranding({ CLIENT_THEME_ACCENT_COLOR: '#12345' })).toThrow('CLIENT_THEME_ACCENT_COLOR');
  });
});

describe('registering a new OAuth client', () => {
  test('an empty branding input is written as null', () => {
    expect(createBranding({})).toEqual({ icon: null, themeBackgroundColor: null, themeAccentColor: null });
    expect(createBranding({ CLIENT_ICON: '', CLIENT_THEME_BACKGROUND_COLOR: '  ' })).toEqual({
      icon: null,
      themeBackgroundColor: null,
      themeAccentColor: null,
    });
  });

  test('set values are written; `none` is null', () => {
    expect(
      createBranding({ CLIENT_ICON: ICON, CLIENT_THEME_BACKGROUND_COLOR: '#FFFFFF', CLIENT_THEME_ACCENT_COLOR: 'none' }),
    ).toEqual({ icon: ICON, themeBackgroundColor: '#FFFFFF', themeAccentColor: null });
  });

  test('an invalid icon is refused', () => {
    expect(() => createBranding({ CLIENT_ICON: 'ftp://example.com/i.png' })).toThrow('HTTPS');
  });
});

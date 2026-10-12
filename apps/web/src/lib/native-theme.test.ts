// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { contrastRatio, nativeTheme, parseHexColor, readableTextOn } from './native-theme';

describe('parseHexColor', () => {
  test('accepts only six-digit hex and lowercases it', () => {
    expect(parseHexColor('#09090B')).toBe('#09090b');
    expect(parseHexColor('#fafafa')).toBe('#fafafa');
  });

  test.each([
    '#fff', '09090b', '#09090b;background:url(x)', 'red', 'rgb(0,0,0)', '#09090b ', '#gggggg', '', null, undefined, 12,
  ])('rejects %p', (value: unknown) => {
    expect(parseHexColor(value)).toBeNull();
  });
});

describe('readableTextOn', () => {
  test('picks light text on dark backgrounds and dark text on light ones', () => {
    expect(readableTextOn('#09090b')).toBe('#fafafa');
    expect(readableTextOn('#ffffff')).toBe('#09090b');
    expect(readableTextOn('#fafafa')).toBe('#09090b');
  });

  test('the chosen text always reaches at least 4.5:1 on black, white and mid greys that are not ambiguous', () => {
    for (const background of ['#000000', '#ffffff', '#1a1a2e', '#f5e6c8', '#0b5fff']) {
      expect(contrastRatio(background, readableTextOn(background))).toBeGreaterThanOrEqual(4.5);
    }
  });
});

describe('nativeTheme', () => {
  test('defaults to the dark shell with a near-white accent', () => {
    const theme = nativeTheme(null);
    expect(theme.dark).toBe(true);
    expect(theme.background).toBe('#09090b');
    expect(theme.style).toContain('--nb-bg:#09090b');
    expect(theme.style).toContain('--nb-accent:#fafafa');
    expect(theme.style).toContain('--nb-accent-fg:#09090b');
    expect(theme.style).toContain('color-scheme:dark');
  });

  test('uses a light foreground on a dark brand colour and a dark one on a light colour', () => {
    expect(nativeTheme({ backgroundColor: '#112233' }).style).toContain('--nb-fg:#fafafa');
    const light = nativeTheme({ backgroundColor: '#f4f4f5' });
    expect(light.dark).toBe(false);
    expect(light.style).toContain('--nb-fg:#09090b');
    expect(light.style).toContain('color-scheme:light');
  });

  test('derives the accent text colour from the accent', () => {
    expect(nativeTheme({ accentColor: '#101010' }).style).toContain('--nb-accent-fg:#fafafa');
  });

  test('ignores invalid colours instead of putting client strings into CSS', () => {
    const theme = nativeTheme({ backgroundColor: 'red;}body{display:none', accentColor: 'url(javascript:1)' });
    expect(theme.background).toBe('#09090b');
    expect(theme.style).not.toContain('red');
    expect(theme.style).not.toContain('url(');
    expect(theme.style).not.toContain('}');
  });
});

describe('text contrast on the composited surfaces', () => {
  const token = (style: string, name: string) => style.match(new RegExp(`--nb-${name}:(#[0-9a-f]{6})`))![1]!;

  test.each(['#09090b', '#f4f4f5', '#777777', '#888888', '#7a7a7a', '#000000', '#ffffff', '#0b5fff', '#ffd400', '#ff3b30'])(
    'foreground, muted and faint text reach 4.5:1 on the background and on the field over %s',
    (backgroundColor: string) => {
      const { style, background } = nativeTheme({ backgroundColor });
      const field = token(style, 'field');
      for (const name of ['fg', 'muted', 'faint']) {
        expect(contrastRatio(token(style, name), background)).toBeGreaterThanOrEqual(4.5);
        expect(contrastRatio(token(style, name), field)).toBeGreaterThanOrEqual(4.5);
      }
    },
  );

  test('the light theme keeps its faint text and placeholders readable (was 3.5:1)', () => {
    const { style } = nativeTheme({ backgroundColor: '#F4F4F5' });
    expect(contrastRatio(token(style, 'faint'), '#f4f4f5')).toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(token(style, 'faint'), token(style, 'field'))).toBeGreaterThanOrEqual(4.5);
  });

  test('a mid-grey theme falls back to pure black or white for the foreground', () => {
    const { style } = nativeTheme({ backgroundColor: '#777777' });
    expect(['#000000', '#ffffff']).toContain(token(style, 'fg'));
    expect(contrastRatio(token(style, 'fg'), '#777777')).toBeGreaterThanOrEqual(4.5);
  });

  test.each(['#fafafa', '#777777', '#7a7a7a', '#0b5fff', '#ffd400', '#101010'])('accent text reaches 4.5:1 on accent %s', (accentColor: string) => {
    const { style } = nativeTheme({ accentColor });
    expect(contrastRatio(token(style, 'accent-fg'), accentColor)).toBeGreaterThanOrEqual(4.5);
  });

  test('the Exo defaults keep their original look', () => {
    const { style } = nativeTheme(null);
    expect(token(style, 'fg')).toBe('#fafafa');
    expect(contrastRatio(token(style, 'muted'), '#09090b')).toBeGreaterThan(8);
  });
});

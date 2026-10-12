// Colours for the native-mode login and consent shell. Only `#rrggbb` values
// from a client's branding are ever used, and every CSS value the shell sets
// is computed here from those validated numbers, never a client string.

export const DEFAULT_BACKGROUND = '#09090b';
export const DEFAULT_ACCENT = '#fafafa';
const LIGHT_TEXT = '#fafafa';
const DARK_TEXT = '#09090b';

const HEX_COLOR = /^#[0-9a-fA-F]{6}$/;

export function parseHexColor(value: unknown): string | null {
  return typeof value === 'string' && HEX_COLOR.test(value) ? value.toLowerCase() : null;
}

function channels(hex: string): [number, number, number] {
  return [1, 3, 5].map((index) => parseInt(hex.slice(index, index + 2), 16)) as [number, number, number];
}

function luminance(hex: string): number {
  const [red, green, blue] = channels(hex).map((channel) => {
    const value = channel / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
}

export function contrastRatio(first: string, second: string): number {
  const [lighter, darker] = [luminance(first), luminance(second)].sort((a, b) => b - a) as [number, number];
  return (lighter + 0.05) / (darker + 0.05);
}

/** Near-white or near-black, whichever reads better on `background`. */
export function readableTextOn(background: string): string {
  return contrastRatio(background, LIGHT_TEXT) >= contrastRatio(background, DARK_TEXT) ? LIGHT_TEXT : DARK_TEXT;
}

function withAlpha(hex: string, alpha: number): string {
  const [red, green, blue] = channels(hex);
  return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
}

export interface NativeTheme {
  dark: boolean;
  background: string;
  /** CSS custom properties for the shell root, built only from validated colours. */
  style: string;
}

export function nativeTheme(input?: { backgroundColor?: string | null; accentColor?: string | null } | null): NativeTheme {
  const background = parseHexColor(input?.backgroundColor) ?? DEFAULT_BACKGROUND;
  const accent = parseHexColor(input?.accentColor) ?? DEFAULT_ACCENT;
  const foreground = readableTextOn(background);
  const dark = foreground === LIGHT_TEXT;
  const style = [
    `--nb-bg:${background}`,
    `--nb-fg:${foreground}`,
    `--nb-muted:${withAlpha(foreground, 0.68)}`,
    `--nb-faint:${withAlpha(foreground, 0.5)}`,
    `--nb-border:${withAlpha(foreground, 0.2)}`,
    `--nb-field:${withAlpha(foreground, 0.07)}`,
    `--nb-accent:${accent}`,
    `--nb-accent-fg:${readableTextOn(accent)}`,
    `color-scheme:${dark ? 'dark' : 'light'}`,
  ].join(';');
  return { dark, background, style };
}

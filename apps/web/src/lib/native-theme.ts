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

const MIN_TEXT_CONTRAST = 4.5;
const MIN_RING_CONTRAST = 3;

/** Near-white or near-black, or pure white/black when neither reaches 4.5:1 on `background`. */
export function readableTextOn(background: string): string {
  const near = contrastRatio(background, LIGHT_TEXT) >= contrastRatio(background, DARK_TEXT) ? LIGHT_TEXT : DARK_TEXT;
  if (contrastRatio(background, near) >= MIN_TEXT_CONTRAST) return near;
  return contrastRatio(background, '#ffffff') >= contrastRatio(background, '#000000') ? '#ffffff' : '#000000';
}

function toHex(values: number[]): string {
  return `#${values.map((value) => Math.round(value).toString(16).padStart(2, '0')).join('')}`;
}

/** `top` laid over `bottom` at `alpha`, as an opaque colour. */
export function composite(top: string, bottom: string, alpha: number): string {
  const [topChannels, bottomChannels] = [channels(top), channels(bottom)];
  return toHex(topChannels.map((value, index) => value * alpha + bottomChannels[index]! * (1 - alpha)));
}

function withAlpha(hex: string, alpha: number): string {
  const [red, green, blue] = channels(hex);
  return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
}

/** The lowest-alpha mix of `foreground` over `background` that reads at 4.5:1 on every surface. */
function softenedText(foreground: string, background: string, start: number, surfaces: string[]): string {
  for (let alpha = start; alpha < 1; alpha += 0.02) {
    const mixed = composite(foreground, background, alpha);
    if (surfaces.every((surface) => contrastRatio(mixed, surface) >= MIN_TEXT_CONTRAST)) return mixed;
  }
  return foreground;
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
  const dark = luminance(foreground) > luminance(background);

  // Fields tint the background toward the foreground; keep the tint only as
  // strong as leaves body text at 4.5:1 on top of it. Zero tint (the field is
  // the background) always passes because the foreground was chosen for it.
  let field = background;
  for (let step = 7; step >= 0; step--) {
    field = composite(foreground, background, step / 100);
    if (contrastRatio(foreground, field) >= MIN_TEXT_CONTRAST) break;
  }
  const surfaces = [background, field];
  const muted = softenedText(foreground, background, 0.68, surfaces);
  const faint = softenedText(foreground, background, 0.5, surfaces);

  const style = [
    `--nb-bg:${background}`,
    `--nb-fg:${foreground}`,
    `--nb-muted:${muted}`,
    `--nb-faint:${faint}`,
    `--nb-border:${withAlpha(foreground, 0.2)}`,
    `--nb-field:${field}`,
    `--nb-accent:${accent}`,
    // Focus ring and focused-box border: the accent, unless it would vanish into the background.
    `--nb-ring:${contrastRatio(accent, background) >= MIN_RING_CONTRAST ? accent : foreground}`,
    `--nb-accent-fg:${readableTextOn(accent)}`,
    `color-scheme:${dark ? 'dark' : 'light'}`,
  ].join(';');
  return { dark, background, style };
}

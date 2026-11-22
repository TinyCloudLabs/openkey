// The branding fields (icon and theme colours) of scripts/ci-register-oauth-client.ts, parsed from
// its environment without touching the database (TC-3268).
//
// Create mode writes every field, an empty input becoming null. Update mode writes only the fields
// whose input is set: an empty input leaves the stored value alone, and `none` clears it. The two
// are different results, so a field is absent from the update data, never `null`, when it is empty.

import { validateOAuthClientMetadataUrl } from '../apps/api/src/services/oauth-redirect-uris';

export type BrandingEnv = Readonly<Record<string, string | undefined>>;

export interface BrandingFields {
  icon: string | null;
  themeBackgroundColor: string | null;
  themeAccentColor: string | null;
}

/** undefined = empty input, null = `none` (clear), string = the new value. */
function icon(env: BrandingEnv): string | null | undefined {
  const rawValue = env.CLIENT_ICON?.trim();
  if (!rawValue) return undefined;
  if (rawValue.toLowerCase() === 'none') return null;
  let url: URL;
  try { url = new URL(rawValue); } catch { throw new Error('CLIENT_ICON must be an HTTPS URL'); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) {
    throw new Error('CLIENT_ICON must be an HTTPS URL without credentials');
  }
  return rawValue;
}

/** undefined = empty input, null = `none` (clear), string = the new value. */
function themeColor(env: BrandingEnv, name: string): string | null | undefined {
  const rawValue = env[name]?.trim();
  if (!rawValue) return undefined;
  if (rawValue.toLowerCase() === 'none') return null;
  if (!/^#[0-9a-fA-F]{6}$/.test(rawValue)) throw new Error(`${name} must be #rrggbb or none`);
  return rawValue;
}

function parse(env: BrandingEnv) {
  return {
    icon: icon(env),
    themeBackgroundColor: themeColor(env, 'CLIENT_THEME_BACKGROUND_COLOR'),
    themeAccentColor: themeColor(env, 'CLIENT_THEME_ACCENT_COLOR'),
  };
}

/** A new client: every branding field is written; an empty input is null. */
export function createBranding(env: BrandingEnv): BrandingFields {
  const parsed = parse(env);
  return {
    icon: parsed.icon ?? null,
    themeBackgroundColor: parsed.themeBackgroundColor ?? null,
    themeAccentColor: parsed.themeAccentColor ?? null,
  };
}

/** An existing client: only the fields whose input is set; the rest keep their stored value. */
export function updateBranding(env: BrandingEnv): Partial<BrandingFields> {
  const parsed = parse(env);
  return {
    ...(parsed.icon !== undefined ? { icon: parsed.icon } : {}),
    ...(parsed.themeBackgroundColor !== undefined ? { themeBackgroundColor: parsed.themeBackgroundColor } : {}),
    ...(parsed.themeAccentColor !== undefined ? { themeAccentColor: parsed.themeAccentColor } : {}),
  };
}

/**
 * The application website of an existing client (TC-3660): undefined = empty input (unchanged),
 * null = `none` (clear), string = the new value. Same URL rules as the admin routes, and HTTPS only.
 */
export function updateWebsite(env: BrandingEnv): { uri?: string | null } {
  const rawValue = env.CLIENT_URI?.trim();
  if (!rawValue) return {};
  if (rawValue.toLowerCase() === 'none') return { uri: null };
  if (!validateOAuthClientMetadataUrl(rawValue).valid || new URL(rawValue).protocol !== 'https:') {
    throw new Error('CLIENT_URI must be an HTTPS URL without credentials or a fragment');
  }
  return { uri: rawValue };
}

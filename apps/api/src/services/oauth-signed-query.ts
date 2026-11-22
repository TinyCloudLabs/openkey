// The signed `oauth_query` envelope of @better-auth/oauth-provider (>= 1.6.18): every signed parameter name is listed
// once in a repeated `ba_param` (itself included, `sig` excluded), and the signature covers the entries sorted by key
// then value. OpenKey's own checks of a signed query accept that form only.

/** True when no key but `ba_param` repeats and the `ba_param` list names exactly the query's other keys. */
export function signedQueryNamesExact(query: URLSearchParams): boolean {
  const keys = [...query.keys()].filter((key) => key !== 'ba_param');
  const unique = new Set(keys);
  if (unique.size !== keys.length) return false;
  unique.delete('sig');
  unique.add('ba_param');
  const names = query.getAll('ba_param');
  return new Set(names).size === names.length && names.length === unique.size && names.every((name) => unique.has(name));
}

/**
 * No key but `ba_param` repeats, and a signed query (one with `sig`) also satisfies `signedQueryNamesExact`. An
 * unsigned query keeps whatever `ba_param` list it carries: the provider's post-login continuation drops `exp`,
 * `ba_iat` and `sig` after verifying them, and its integrity rests on that verification.
 */
export function noRepeatsOutsideSignedNames(query: URLSearchParams): boolean {
  if (query.has('sig')) return signedQueryNamesExact(query);
  const keys = [...query.keys()].filter((key) => key !== 'ba_param');
  return new Set(keys).size === keys.length;
}

/** A Better Auth `ctx.query` record (a repeated key arrives as an array) as URL search params. */
export function queryRecordParams(record: Record<string, unknown> | undefined): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(record ?? {})) {
    for (const item of Array.isArray(value) ? value : [value]) if (item !== undefined) params.append(key, String(item));
  }
  return params;
}

/** The query (without `sig`) in the order the provider signs it. */
export function canonicalSignedQuery(query: URLSearchParams): string {
  const entries = [...query].filter(([key]) => key !== 'sig');
  entries.sort(([ka, va], [kb, vb]) => (ka < kb ? -1 : ka > kb ? 1 : va < vb ? -1 : va > vb ? 1 : 0));
  return new URLSearchParams(entries).toString();
}

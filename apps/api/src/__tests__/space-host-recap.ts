// Space host messages built from a raw ReCap JSON text, for the tests of what a message lets a site host. The node
// reads the ReCap with a JSON parser that decodes escapes, so the same message can spell one ability or one space id
// many ways. The statement the recap parser checks is written from the decoded values.

/** `message` with its ReCap resource replaced by `json` (base64url) and its statement by the one `ability` on `resource` implies. */
export function withRawRecap(message: string, json: string, resource: string, ability = 'tinycloud.space/host'): string {
  const statement = `I further authorize the stated URI to perform the following actions on my behalf: (1) '${ability.slice(0, ability.indexOf('/'))}': '${ability.slice(ability.indexOf('/') + 1)}' for '${resource}'.`;
  return message
    .replace(/I further authorize[^\n]*/, statement)
    .replace(/urn:recap:[A-Za-z0-9_-]+/, `urn:recap:${Buffer.from(json, 'utf8').toString('base64url')}`);
}

/** `\uXXXX` for every character of `text` that is in `chars`. */
function unicodeEscaped(text: string, chars: string): string {
  return [...text].map((ch) => (chars.includes(ch) ? `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}` : ch)).join('');
}

/** Spellings of the one capability "host `spaceName`'s `owner` space" that a JSON parser reads the same. */
export function escapedHostSpellings(resource: string): Array<{ label: string; json: string }> {
  const ability = 'tinycloud.space/host';
  const build = (res: string, ab: string, tail = '') => `{"att":{"${res}":{"${ab}":[{}]}},"prf":[]${tail}}`;
  const slashEscaped = (text: string) => text.replaceAll('/', '\\/');
  return [
    { label: 'plain', json: build(resource, ability) },
    { label: 'ability with an escaped slash', json: build(resource, slashEscaped(ability)) },
    { label: 'ability with an escaped dot', json: build(resource, unicodeEscaped(ability, '.')) },
    { label: 'ability with every character escaped', json: build(resource, unicodeEscaped(ability, ability)) },
    { label: 'resource with an escaped slash', json: build(slashEscaped(resource), ability) },
    { label: 'resource with escaped colons', json: build(unicodeEscaped(resource, ':'), ability) },
    { label: 'resource with every character escaped', json: build(unicodeEscaped(resource, resource), ability) },
    { label: 'both keys escaped', json: build(slashEscaped(unicodeEscaped(resource, ':')), slashEscaped(unicodeEscaped(ability, '.'))) },
    { label: 'whitespace around the JSON', json: ` \n${build(resource, ability)}\n ` },
    { label: 'the prf key first', json: `{"prf":[],"att":{"${resource}":{"${ability}":[{}]}}}` },
    { label: 'an unrelated key beside att', json: build(resource, ability, ',"x":{"att":{"a":{"b":[{}]}}}') },
  ];
}

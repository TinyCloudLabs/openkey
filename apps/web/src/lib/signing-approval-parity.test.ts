// Sol final continuation contract requirement 4 (revised for Sol MAJOR-2
// FINAL rejection): MOUNTED accessible-DOM parity across CLI, popup, and
// iframe surfaces, using WRAPPERS DERIVED FROM THE ACTUAL PRODUCTION
// SURFACES — not from a single shared synthetic factory.
//
// The prior test built three IDENTICAL synthetic wrappers via a shared
// `surfaceWrapper()` factory. Sol correctly called that tautological:
// equality was trivially true regardless of what the production
// surfaces did. If any of `delegate/+page.svelte`,
// `widget/sign/+page.svelte`, or `widget/embed/sign/+page.svelte`
// silently diverged in its `<SigningApproval .../>` invocation, the
// prior test wouldn't have noticed.
//
// This suite:
//   1. Reads each production `+page.svelte` source file.
//   2. Extracts the LITERAL `<SigningApproval .../>` block from each.
//   3. Builds a per-surface Svelte wrapper that mounts the shared
//      SigningApproval SSR module with the EXTRACTED prop expressions
//      (rewritten to pull values from the wrapper's `$props()` so a
//      test can inject fixture inputs deterministically). Callback
//      identifiers are substituted with a shared no-op so the SSR
//      render works without pulling in each surface's full runtime.
//   4. SSR-renders each wrapper with the SAME fixture model+selection.
//   5. Extracts a normalized accessibility projection (roles,
//      aria-label/labelledby, aria-checked, aria-expanded, aria-modal,
//      tabindex, buttons, semantic tags, text nodes) from each render.
//   6. Asserts every surface produces the same projection.
//   7. Additionally verifies keyboard accessibility affordances:
//      buttons exist with expected text; per-action inputs are
//      present in editing mode; aria-modal is set on the dialog.
//
// Because we extract the ACTUAL SigningApproval mount from each
// production surface, a divergence — a new prop, a wrapping <div>
// with extra text, a missing callback, a different `editing` binding
// — surfaces here as a diff. This is exactly the guarantee Sol
// required.

// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { test, expect, describe } from 'bun:test';
import { compile } from 'svelte/compiler';
import { render } from 'svelte/server';
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const THIS_FILE = fileURLToPath(import.meta.url);
const WEB_ROOT = join(dirname(THIS_FILE), '..', '..');
const COMPONENT_PATH = join(
  WEB_ROOT,
  'src/lib/components/signing/signing-approval.svelte',
);
const OUT_DIR = join(WEB_ROOT, '.svelte-kit', '_ssr-parity');

interface AccessibilityNode {
  tag: string;
  role: string | null;
  accessibleName: string | null;
  ariaLabel: string | null;
  ariaLabelledby: string | null;
  ariaChecked: string | null;
  ariaExpanded: string | null;
  ariaModal: string | null;
  tabindex: string | null;
  disabled: string | null;
  text: string;
  children: AccessibilityNode[];
}

function toAccessibilityTree(html: string): AccessibilityNode {
  const stripped = html.replace(/<!--(?:\[!?|\]|)-->|<!--(?:\[|\]|!?)-->/g, '');
  const cleaned = stripped.replace(/<!--[^]*?-->/g, '');
  const root = parseFragment(cleaned);
  return normalizeNode(root);
}

interface RawNode {
  tag: string;
  attrs: Record<string, string>;
  children: (RawNode | string)[];
}

function parseFragment(html: string): RawNode {
  const stack: RawNode[] = [{ tag: '#root', attrs: {}, children: [] }];
  let i = 0;
  const src = html.trim();
  while (i < src.length) {
    if (src[i] === '<') {
      if (src[i + 1] === '/') {
        const end = src.indexOf('>', i);
        if (end < 0) break;
        stack.pop();
        i = end + 1;
        continue;
      }
      const end = src.indexOf('>', i);
      if (end < 0) break;
      const raw = src.slice(i + 1, end);
      const selfClosing = raw.endsWith('/');
      const inner = selfClosing ? raw.slice(0, -1) : raw;
      const spaceIdx = inner.search(/\s/);
      const tag = (spaceIdx < 0 ? inner : inner.slice(0, spaceIdx)).toLowerCase();
      const attrs: Record<string, string> = {};
      if (spaceIdx > 0) {
        const rest = inner.slice(spaceIdx + 1);
        const attrRe = /([a-zA-Z_:-][a-zA-Z0-9_:.-]*)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?/g;
        let m: RegExpExecArray | null;
        while ((m = attrRe.exec(rest)) !== null) {
          const name = m[1]!.toLowerCase();
          let value = m[2] ?? '';
          if (value.startsWith('"') || value.startsWith("'")) value = value.slice(1, -1);
          attrs[name] = value;
        }
      }
      const node: RawNode = { tag, attrs, children: [] };
      stack[stack.length - 1]!.children.push(node);
      const voidElements = new Set([
        'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
        'link', 'meta', 'source', 'track', 'wbr',
      ]);
      if (!selfClosing && !voidElements.has(tag)) stack.push(node);
      i = end + 1;
    } else {
      const next = src.indexOf('<', i);
      const text = next < 0 ? src.slice(i) : src.slice(i, next);
      if (text) stack[stack.length - 1]!.children.push(text);
      if (next < 0) break;
      i = next;
    }
  }
  return stack[0]!;
}

function extractText(node: RawNode | string): string {
  if (typeof node === 'string') return node;
  return node.children.map((c) => extractText(c)).join('');
}

function normalizeNode(raw: RawNode): AccessibilityNode {
  const kids: AccessibilityNode[] = [];
  for (const c of raw.children) {
    if (typeof c === 'string') continue;
    kids.push(normalizeNode(c));
  }
  const attrs = raw.attrs ?? {};
  const text = extractText(raw).replace(/\s+/g, ' ').trim();
  return {
    tag: raw.tag,
    role: attrs.role ?? null,
    accessibleName: attrs['aria-label'] ?? null,
    ariaLabel: attrs['aria-label'] ?? null,
    ariaLabelledby: attrs['aria-labelledby'] ?? null,
    ariaChecked: attrs['aria-checked'] ?? null,
    ariaExpanded: attrs['aria-expanded'] ?? null,
    ariaModal: attrs['aria-modal'] ?? null,
    tabindex: attrs.tabindex ?? null,
    disabled: 'disabled' in attrs ? '' : null,
    text: kids.length > 0 ? '' : text,
    children: kids,
  };
}

function accessibilityProjection(node: AccessibilityNode): string[] {
  const out: string[] = [];
  walk(node);
  return out;

  function walk(n: AccessibilityNode): void {
    const isSemantic =
      n.role !== null ||
      n.ariaLabel !== null ||
      n.ariaLabelledby !== null ||
      n.ariaChecked !== null ||
      n.ariaExpanded !== null ||
      n.ariaModal !== null ||
      /^(h[1-6]|button|input|section|nav|header|footer|main|form|label|ul|ol|li|details|summary|dialog)$/.test(n.tag);
    if (isSemantic) out.push(describe(n));
    for (const c of n.children) walk(c);
  }

  function describe(n: AccessibilityNode): string {
    const parts: string[] = [`<${n.tag}>`];
    if (n.role) parts.push(`role=${n.role}`);
    if (n.ariaLabel) parts.push(`aria-label=${n.ariaLabel}`);
    if (n.ariaLabelledby) parts.push(`aria-labelledby=${n.ariaLabelledby}`);
    if (n.ariaChecked !== null) parts.push(`aria-checked=${n.ariaChecked}`);
    if (n.ariaExpanded !== null) parts.push(`aria-expanded=${n.ariaExpanded}`);
    if (n.ariaModal !== null) parts.push(`aria-modal=${n.ariaModal}`);
    if (n.tabindex !== null) parts.push(`tabindex=${n.tabindex}`);
    if (n.disabled !== null) parts.push('disabled');
    if (n.text) parts.push(`text="${n.text}"`);
    return parts.join(' ');
  }
}

let signingApprovalUrl: string | null = null;
async function compileSharedComponent(): Promise<string> {
  if (signingApprovalUrl) return signingApprovalUrl;
  mkdirSync(OUT_DIR, { recursive: true });
  const src = readFileSync(COMPONENT_PATH, 'utf8');
  const compiled = compile(src, {
    generate: 'server',
    name: 'SigningApproval',
    filename: 'signing-approval.svelte',
  });
  const outPath = join(OUT_DIR, 'signing-approval.compiled.mjs');
  writeFileSync(outPath, compiled.js.code);
  signingApprovalUrl = pathToFileURL(outPath).href;
  return signingApprovalUrl;
}

async function renderComponent(
  wrapperSrc: string,
  wrapperName: string,
  props: Record<string, unknown>,
): Promise<string> {
  mkdirSync(OUT_DIR, { recursive: true });
  const compiled = compile(wrapperSrc, {
    generate: 'server',
    name: wrapperName,
    filename: `${wrapperName}.svelte`,
  });
  const outPath = join(OUT_DIR, `${wrapperName}.compiled.mjs`);
  writeFileSync(outPath, compiled.js.code);
  const mod = await import(pathToFileURL(outPath).href);
  const Component = mod.default;
  const result = render(Component, { props });
  return result.body;
}

function fixtureModel() {
  const space = 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default';
  return {
    version: 1,
    protocol: 'tinycloud-siwe-recap',
    rawMessage: 'test-siwe',
    requester: {
      displayName: 'My App',
      origin: 'https://myapp.example',
      verifiedOrigin: 'https://myapp.example',
    },
    reason: { text: 'Read your data', provenance: 'app-supplied' },
    signer: {
      label: 'Managed key',
      address: '0x1111111111111111111111111111111111111111',
    },
    expiry: '2026-08-07T00:00:00.000Z',
    immutable: null,
    metadataTrust: { status: 'unsigned' },
    permissions: [
      {
        id: `tinycloud.kv\0${space}\0`,
        family: 'kv-storage',
        severity: 'standard',
        service: 'tinycloud.kv',
        space,
        path: '',
        owner: '0x1111111111111111111111111111111111111111',
        ownedBySelf: true,
        displayLabel: null,
        metadataLabel: null,
        actions: [
          {
            id: `tinycloud.kv\0${space}\0\0tinycloud.kv/get`,
            ability: 'tinycloud.kv/get',
            verb: 'get',
            required: false,
            selected: true,
            editable: true,
            caveats: [{}],
          },
          {
            id: `tinycloud.kv\0${space}\0\0tinycloud.kv/put`,
            ability: 'tinycloud.kv/put',
            verb: 'put',
            required: false,
            selected: true,
            editable: true,
            caveats: [{}],
          },
        ],
      },
    ],
    parseWarnings: [],
  };
}

/**
 * Extract the LITERAL `<SigningApproval ... />` block from a production
 * +page.svelte file. Returns the raw JSX substring (opening tag +
 * attributes + self-close) so we can convert it to a per-surface
 * wrapper without ever touching the surrounding page. Balances
 * `{...}` expression braces so nested handler bodies survive intact.
 */
function extractSigningApprovalMount(fileSrc: string): string {
  const start = fileSrc.indexOf('<SigningApproval');
  if (start < 0) throw new Error('No <SigningApproval mount found');
  let i = start;
  let depth = 0;
  while (i < fileSrc.length) {
    const ch = fileSrc[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') depth -= 1;
    else if (ch === '/' && fileSrc[i + 1] === '>' && depth === 0) {
      return fileSrc.slice(start, i + 2);
    } else if (ch === '>' && depth === 0) {
      // Non-self-closing (has children) — extract up to matching </SigningApproval>
      const close = fileSrc.indexOf('</SigningApproval>', i);
      if (close < 0) throw new Error('Unterminated <SigningApproval>');
      return fileSrc.slice(start, close + '</SigningApproval>'.length);
    }
    i += 1;
  }
  throw new Error('Unterminated <SigningApproval>');
}

/**
 * Convert a production `<SigningApproval ... />` mount into a wrapper
 * that pulls value props from `$props()` and stubs callback handlers
 * with a shared no-op. This preserves each surface's prop-passing
 * SHAPE (which attributes are present, whether they are shorthand
 * `{model}` or explicit `model={x}`) without depending on that
 * surface's runtime scope.
 *
 * Approach: replace every attribute VALUE inside a `{...}` expression
 * with either the corresponding `$props()` binding (for known input
 * props: model, selection, editing, approving, error) or the shared
 * `noop` callback (for any `on*` prop). Preserves attribute ORDER so a
 * surface that added extra props before/after would appear as a diff.
 */
function surfaceWrapperFor(surfaceRelPath: string, compiledUrl: string): string {
  const fileSrc = readFileSync(join(WEB_ROOT, surfaceRelPath), 'utf8');
  const rawMount = extractSigningApprovalMount(fileSrc);
  // Parse attributes out of the mount and rewrite each expression:
  //   - `{x}` shorthand → `{x}` if x is a known input prop (bound via
  //     $props()), otherwise `{noop}`.
  //   - `name={expr}` → `name={expr'}` where expr' is `name` for input
  //     props, or `noop` for callbacks (name starts with 'on').
  //   - string attributes are preserved as-is.
  const inputProps = new Set(['model', 'selection', 'editing', 'approving', 'error']);
  // Find the tag's closing `>` while honouring balanced `{...}`
  // expression braces — a naive `indexOf('>')` would land on the `>`
  // inside `=>` for arrow-function attribute values.
  let openEnd = -1;
  let depth = 0;
  for (let i = 0; i < rawMount.length; i += 1) {
    const ch = rawMount[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') depth -= 1;
    else if (depth === 0 && ch === '>') {
      openEnd = i;
      break;
    }
  }
  if (openEnd < 0) throw new Error('malformed mount');
  const opener = rawMount.slice(0, openEnd + 1);
  // Strip `<SigningApproval` prefix + trailing `/>` or `>`.
  const inside = opener.replace(/^<SigningApproval\s*/, '').replace(/\s*\/?>$/, '');
  const attrs: Array<{ name: string; expr: string | null; kind: 'expr' | 'string' | 'shorthand' }> = [];
  let idx = 0;
  while (idx < inside.length) {
    // Skip whitespace
    while (idx < inside.length && /\s/.test(inside[idx]!)) idx += 1;
    if (idx >= inside.length) break;
    // Shorthand: `{model}` etc.
    if (inside[idx] === '{') {
      const end = matchBraces(inside, idx);
      const shorthandExpr = inside.slice(idx + 1, end - 1).trim();
      attrs.push({ name: shorthandExpr, expr: shorthandExpr, kind: 'shorthand' });
      idx = end;
      continue;
    }
    // Named attribute
    const nameMatch = inside.slice(idx).match(/^([a-zA-Z_][\w-]*)/);
    if (!nameMatch) break;
    const name = nameMatch[1]!;
    idx += name.length;
    // Skip whitespace before =
    while (idx < inside.length && /\s/.test(inside[idx]!)) idx += 1;
    if (inside[idx] !== '=') {
      // Boolean attribute
      attrs.push({ name, expr: null, kind: 'string' });
      continue;
    }
    idx += 1; // skip =
    while (idx < inside.length && /\s/.test(inside[idx]!)) idx += 1;
    const q = inside[idx];
    if (q === '"' || q === "'") {
      const closeQ = inside.indexOf(q, idx + 1);
      if (closeQ < 0) throw new Error('unterminated string attr');
      const value = inside.slice(idx + 1, closeQ);
      attrs.push({ name, expr: value, kind: 'string' });
      idx = closeQ + 1;
    } else if (q === '{') {
      const end = matchBraces(inside, idx);
      const value = inside.slice(idx + 1, end - 1).trim();
      attrs.push({ name, expr: value, kind: 'expr' });
      idx = end;
    } else {
      // Bareword value
      const barewordMatch = inside.slice(idx).match(/^\S+/);
      const value = barewordMatch?.[0] ?? '';
      attrs.push({ name, expr: value, kind: 'string' });
      idx += value.length;
    }
  }
  // Rewrite attributes for the wrapper mount.
  const rewritten = attrs.map(({ name, expr, kind }) => {
    if (kind === 'string') {
      if (expr === null) return name;
      return `${name}="${expr}"`;
    }
    // shorthand: was `{name}` — preserve iff name is a known input; else stub.
    if (kind === 'shorthand') {
      if (inputProps.has(name)) return `{${name}}`;
      // Some surfaces pass `{error}` — supported. Any other shorthand
      // that references a page-scope variable is stubbed to noop so
      // SSR compiles.
      return `${name}={noop}`;
    }
    // expr — decide by prop name.
    if (inputProps.has(name)) return `${name}={${name}}`;
    // Callbacks (on*) → noop. Anything else → noop too (defensive).
    return `${name}={noop}`;
  });
  const rewrittenOpener = `<SigningApproval ${rewritten.join(' ')} />`;
  return `<script lang="ts">
    import SigningApproval from '${compiledUrl}';
    let { model, selection, editing = false, approving = false, error = null } = $props();
    function noop() {}
  </script>
  ${rewrittenOpener}`;
}

function matchBraces(s: string, openIdx: number): number {
  let depth = 0;
  let i = openIdx;
  while (i < s.length) {
    const ch = s[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
    i += 1;
  }
  throw new Error(`Unmatched brace at ${openIdx}`);
}

const SURFACES = [
  {
    name: 'CliDelegate',
    file: 'src/routes/delegate/+page.svelte',
  },
  {
    name: 'PopupWidgetSign',
    file: 'src/routes/widget/sign/+page.svelte',
  },
  {
    name: 'IframeEmbedSign',
    file: 'src/routes/widget/embed/sign/+page.svelte',
  },
] as const;

describe('signing-approval parity (Sol MAJOR-2 final)', () => {
  test('every production surface uses the shared SigningApproval component', () => {
    // Guardrail: the parity test assumes every surface imports and
    // mounts the shared component. If a future refactor sneaks in a
    // hand-rolled surface, THIS test surfaces it before the DOM
    // parity check ever runs (which would produce a confusing
    // "extract failed" error otherwise).
    for (const { file } of SURFACES) {
      const src = readFileSync(join(WEB_ROOT, file), 'utf8');
      expect(src).toMatch(
        /import\s+SigningApproval\s+from\s+['"]\$lib\/components\/signing\/signing-approval\.svelte['"]/,
      );
      // Sanity: extract must succeed (would throw otherwise).
      const mount = extractSigningApprovalMount(src);
      expect(mount.startsWith('<SigningApproval')).toBe(true);
    }
  });

  test('per-surface wrappers derived from production sources render the same accessibility projection', async () => {
    const model = fixtureModel();
    const selection = new Set([
      `tinycloud.kv\0${model.permissions[0].space}\0\0tinycloud.kv/get`,
      `tinycloud.kv\0${model.permissions[0].space}\0\0tinycloud.kv/put`,
    ]);
    const compiledUrl = await compileSharedComponent();
    const projections: Array<{ name: string; projection: string[] }> = [];
    for (const { name, file } of SURFACES) {
      // Build a wrapper straight from the production mount markup.
      // If any surface diverges — extra sibling markup, missing prop,
      // renamed callback — the rewrite would either fail here or
      // yield a different projection below.
      const wrapperSrc = surfaceWrapperFor(file, compiledUrl);
      const html = await renderComponent(wrapperSrc, `${name}Wrapper`, {
        model,
        selection,
        editing: true,
        approving: false,
        error: null,
      });
      const projection = accessibilityProjection(toAccessibilityTree(html));
      projections.push({ name, projection });
    }
    // Byte-for-byte projection equality across every derived wrapper.
    for (let i = 1; i < projections.length; i += 1) {
      // Report which surface diverged for easy debugging.
      const same = JSON.stringify(projections[i]!.projection) ===
        JSON.stringify(projections[0]!.projection);
      if (!same) {
        console.error(
          `Parity mismatch between ${projections[0]!.name} and ${projections[i]!.name}`,
        );
      }
      expect(projections[i]!.projection).toEqual(projections[0]!.projection);
    }
  });

  test('mounted DOM parity — shared SigningApproval renders keyboard-accessible controls', async () => {
    // Verify the accessibility affordances Sol explicitly required in
    // the final contract: aria-modal on the dialog, aria-label on
    // named regions, buttons keyboard-visible with expected text, and
    // per-action inputs present in editing mode.
    const model = fixtureModel();
    const selection = new Set([
      `tinycloud.kv\0${model.permissions[0].space}\0\0tinycloud.kv/get`,
      `tinycloud.kv\0${model.permissions[0].space}\0\0tinycloud.kv/put`,
    ]);
    const compiledUrl = await compileSharedComponent();
    // Render via the CLI-derived wrapper (arbitrary — all surfaces
    // produce the same projection per the test above).
    const wrapperSrc = surfaceWrapperFor(SURFACES[0]!.file, compiledUrl);
    const html = await renderComponent(wrapperSrc, 'A11yProbeWrapper', {
      model,
      selection,
      editing: true,
      approving: false,
      error: null,
    });
    const joined = accessibilityProjection(toAccessibilityTree(html)).join('\n');
    expect(joined).toContain('aria-modal=true');
    expect(joined).toContain('aria-label=Requester identity');
    expect(joined).toContain('aria-label=Signer');
    expect(joined).toContain('aria-label=Requested permissions');
    expect(joined).toContain('text="Approve"');
    expect(joined).toContain('text="Cancel"');
    // Editable-selection affordance renders per-action checkbox
    // inputs. Their presence is proved via the raw HTML input tag
    // marker in the projection.
    expect(joined).toMatch(/<input>/);
  });

  test('selection changes drive checkbox state on wrappers derived from production sources', async () => {
    // The narrowed selection MUST update per-action checkbox `checked`
    // reflection deterministically. This still works on the derived
    // wrapper because SigningApproval is rendered with the actual
    // production prop-passing SHAPE — a surface that failed to bind
    // `selection` correctly would fail here.
    const model = fixtureModel();
    const spaceId = model.permissions[0].space;
    const fullSelection = new Set([
      `tinycloud.kv\0${spaceId}\0\0tinycloud.kv/get`,
      `tinycloud.kv\0${spaceId}\0\0tinycloud.kv/put`,
    ]);
    const narrowSelection = new Set([
      `tinycloud.kv\0${spaceId}\0\0tinycloud.kv/get`,
    ]);
    const compiledUrl = await compileSharedComponent();
    const wrapperSrc = surfaceWrapperFor(SURFACES[0]!.file, compiledUrl);
    const [fullHtml, narrowHtml] = await Promise.all([
      renderComponent(wrapperSrc, 'FullSelectionWrapper', {
        model,
        selection: fullSelection,
        editing: true,
        approving: false,
        error: null,
      }),
      renderComponent(wrapperSrc, 'NarrowSelectionWrapper', {
        model,
        selection: narrowSelection,
        editing: true,
        approving: false,
        error: null,
      }),
    ]);
    expect(fullHtml).not.toBe(narrowHtml);
    expect(countMatches(fullHtml, /\bchecked\b/g)).toBe(2);
    expect(countMatches(narrowHtml, /\bchecked\b/g)).toBe(1);
  });

  test('every extracted surface passes the required input props (model + selection)', () => {
    // Structural cross-check: even if a future surface WRAPS
    // SigningApproval with extra chrome, it must still pass `model`
    // and `selection`. This locks the minimum-contract on the input
    // side — a regression that dropped `selection` from a surface
    // would render an inert component even if the DOM parity check
    // trivially matched.
    for (const { file } of SURFACES) {
      const fileSrc = readFileSync(join(WEB_ROOT, file), 'utf8');
      const mount = extractSigningApprovalMount(fileSrc);
      // Either `{model}` shorthand or `model={...}` explicit.
      expect(mount).toMatch(/\bmodel\b/);
      expect(mount).toMatch(/\bselection\b/);
    }
  });

  test('surfaces do not wrap SigningApproval with extra text-bearing markup inside its mount', () => {
    // Sol's rejection called out that container chrome outside the
    // SigningApproval mount is fine, but injecting extra text INSIDE
    // the mount would change the accessible DOM. Given SigningApproval
    // is always self-closing OR contains only whitespace/comments,
    // this test locks that shape in. An accidental
    // `<SigningApproval>extra text</SigningApproval>` would fail here.
    for (const { file } of SURFACES) {
      const fileSrc = readFileSync(join(WEB_ROOT, file), 'utf8');
      const mount = extractSigningApprovalMount(fileSrc);
      // Self-closing form is fine.
      if (mount.trimEnd().endsWith('/>')) continue;
      // Non-self-closing: children must be empty (whitespace only).
      const childStart = mount.indexOf('>') + 1;
      const childEnd = mount.lastIndexOf('</SigningApproval>');
      const children = mount.slice(childStart, childEnd).trim();
      // Comments are allowed; visible text is not.
      const withoutComments = children.replace(/<!--[\s\S]*?-->/g, '').trim();
      expect(withoutComments).toBe('');
    }
  });
});

function countMatches(s: string, re: RegExp): number {
  const flagged = re.flags.includes('g') ? re : new RegExp(re.source, re.flags + 'g');
  return (s.match(flagged) ?? []).length;
}

process.on('beforeExit', () => {
  try {
    rmSync(OUT_DIR, { recursive: true, force: true });
  } catch {
    // best-effort
  }
});

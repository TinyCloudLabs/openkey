# App keys for builders

An app key is an encryption key that lives under your app's own name in the user's TinyCloud space: `apps/<app id>/...`. Your app asks for app keys through `authorizeTinyCloud` (`protocolVersion: 1`) in `@openkey/sdk`. The user always sees the request in OpenKey and approves or declines it. App keys do not work through `signMessage`: that route refuses every `apps/` key.

There are two ways to ask. Both end on the same OpenKey approval screen. The difference is what OpenKey can say about your app and how much it will let you request.

## What every app-key request needs

- Your page runs on an `https://` origin with no port and no path. The host must be a real name with at least two labels (`app.example.com`). IP addresses and `localhost` hosts cannot name an app.
- The key owner is the signing user's own account on the `default` network.
- The signed message has an `Expiration Time`.
- Your app id is your host with its labels reversed: `app.example.com` becomes `com.example.app`. The id can be at most 64 characters; a longer host is refused (without a manifest, with the generic "doesn't list the key" message).
- `key.delete` is never granted to apps.

OpenKey takes your origin from the browser, not from anything you send. If you also send `reportedOrigin`, it must be byte-for-byte the same origin; anything else is refused. The SIWE domain (no port) and URI must name that same origin. Host labels must be lowercase letters, digits and hyphens, at most 63 characters, with no leading or trailing hyphen.

## A. With a published manifest

Publish a JSON file at `https://<your origin>/.well-known/openkey-manifest.json`.

```json
{
  "name": "Listen",
  "app_id": "xyz.tinycloud.listen",
  "keys": [
    { "prefix": "apps/xyz.tinycloud.listen/", "abilities": ["key.create", "decrypt"] },
    { "path": "apps/xyz.tinycloud.listen/notes", "abilities": ["decrypt"] }
  ]
}
```

- `app_id` must be your reversed host, or your reversed host followed by `.` and more labels (`xyz.tinycloud.listen.beta`). The example above only works from `https://listen.tinycloud.xyz`.
- `keys_app_id` is optional. When present it picks the key namespace instead of `app_id`, and it must also belong to your origin.
- `keys` lists what you may ask for. Each entry is either a `path` (one key) or a `prefix` (`apps/<id>/`, everything under it, where `<id>` is `keys_app_id` if present, else `app_id`), plus a non-empty list of `abilities` from `key.create`, `decrypt`, `key.block`, `key.unblock` with no repeats. Unknown fields make the whole `keys` block unreadable. At most 32 entries, one `prefix` entry at most, no duplicate `path`.
- `name` is a display name for your app.

**Digest.** Compute the SHA-256 of the manifest as canonical JSON and send it as `presentation.manifestDigest` (lowercase hex) in your `authorizeTinyCloud` request. Canonical JSON is the manifest parsed, then written back with object keys sorted at every level and no whitespace; array order stays. The helper is `canonicalManifestSha256Hex` in `apps/api/src/services/manifest-origin-fetch.ts`. `@openkey/sdk` does not compute the digest for you.

```ts
const digest = sha256Hex(canonicalJson(manifest)); // keys sorted, no spaces
await openkey.authorizeTinyCloud({
  protocolVersion: 1,
  siwe,
  presentation: { displayName: 'Listen', manifestDigest: digest },
});
```

**What OpenKey does.** When the request carries a digest and your origin is https, OpenKey fetches the file (https only, a public address, no redirects, 5 second timeout, 64 KiB maximum), canonicalizes it and compares digests. A match shows your app as `Manifest served by verified https origin`, and the manifest then governs app keys: anything you ask for that is not declared in `keys` is refused.

**What it unlocks.** The name and details from your manifest appear in the review, and you can limit your request to specific key paths or abilities. Nothing is signed: the label means your own origin served the file that matches the digest you sent. The manifest is a declaration, not a barrier: code running on your own origin can still send a request without the digest, and a fetch that fails falls back to section B.

A parent domain's manifest may use any `app_id` under its own reversed host (`tinycloud.xyz` declaring `xyz.tinycloud.listen`). That is the same namespace `listen.tinycloud.xyz` gets without a manifest, so treat those namespaces as shared between a domain and its subdomains.

If the fetch or the digest match fails, the request is treated as a request without a manifest (section B), not as an error. If the digest matches, the manifest decides: when it has no `keys` block, an empty one, an unreadable one, or an `app_id` that does not belong to your host, the app-key request is refused. It is not widened to the section B scope. Publishing a manifest for other purposes (secrets, permissions) and sending its digest therefore means you must declare your app keys in it too.

## B. Without a manifest

Skip the file and the digest. Send the same `authorizeTinyCloud` request from your https origin.

**What your app gets.** OpenKey derives your app id from the browser origin and allows requests for the prefix `apps/<reversed host>/` itself, or single keys under it. For `https://app.example.com` that is `apps/com.example.app/`. A narrower prefix such as `apps/com.example.app/notes/` is refused. Allowed actions: create keys, decrypt, block keys and unblock keys (`key.create`, `decrypt`, `key.block`, `key.unblock`).

**What the user sees.** The headline is your app id in monospace (`com.example.app`) with "Requested by app.example.com". The app keys are listed as one group, "This app is requesting:", with lines such as "Create new encryption keys tied to this app" and "Decrypt data locked with this app's keys". When decrypt is selected, a line says when the access ends. The label `No signed manifest` appears in the collapsed advanced details. The user keeps all of the app keys or none of them. There is no verified app name: a `presentation.displayName` you send appears only in the details section, as supplied by the caller and unverified.

**Limits.**
- Only `apps/<your reversed host>/`. Other paths, other apps' prefixes and anything outside `apps/` are refused.
- No `key.delete`.
- The user's own account, the `default` network, an `Expiration Time`, and the user's explicit approval are still required.
- Your request is not narrowed to specific keys or abilities. If you want a smaller request, publish a manifest (A).

## Which should I use

| | With manifest | Without manifest |
| --- | --- | --- |
| Setup | Publish file, send digest | None |
| Label shown | Manifest served by verified https origin | No signed manifest |
| Name shown | From your manifest | Only in details, marked unverified |
| Request scope | Only what `keys` declares | Whole `apps/<reversed host>/` prefix, four abilities |
| If it fails | Fetch or digest mismatch: treated as no manifest. Digest matches but `keys` is missing or unusable: refused | Not applicable |

A request whose manifest fails to fetch or match gets the broad no-manifest scope, not an error. A request whose manifest matches but declares no usable `keys` is refused. If you publish a manifest, check that it serves and that it declares your keys.

## Not the same thing as the SDK `manifest` option

`TinyCloudWeb` takes a `manifest: { app_id, name, ... }` option. That is a request-side object the SDK uses. It does not publish anything and does not send a digest. The well-known file in section A is a separate document you host.

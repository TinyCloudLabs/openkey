# TC-966 mock-seal check

Answers one question: **was any sealed key in this database sealed by the mock
TEE client instead of dstack?**

Until TC-966, `createTeeClient()` quietly used the mock client whenever
`TEE_MODE` wasn't exactly `production`. The mock seals under
`sha256(DEV_SEALING_KEY || path)`, and `DEV_SEALING_KEY` falls back to the
public default `openkey-dev-sealing-key-32b!`. That derivation has been
unchanged since the first commit of `packages/tee` (2026-01-04).

`check.ts` tries every sealed blob against the mock keys for its sealing path.
First it tries every `DEV_SEALING_KEY` value published in this repository:
- the code's fallback;
- `openkey-dev-sealing-key-32bytes!` (`docker-compose.yml`, `docs/development.md`);
- the `.env.example` and `README.md` placeholders;
- the nostr route tests' key.

Then it tries the deployment's own key, if you provide it.

| Table | Column | Sealing path |
|---|---|---|
| `ethereum_keys` | `sealedBlob` (managed keys only) | `openkey/key/<sealingContext>`, or `openkey/user/<userId>/keys` when `sealingContext` is NULL |
| `nostr_keys` | `sealedSecret` | `openkey/key/<sealingContext>` |
| `user_encryption_key` | `sealedPrivateKey` (legacy, 2026-03) | `openkey/user/<userId>/encryption` |

## Safety

- **Read-only.** It uses one connection and one transaction. It runs
  `SET TRANSACTION READ ONLY`, aborts unless `SHOW transaction_read_only` is
  `on`, and rolls back at the end. It only runs `SELECT`s.
- **Counts only.** It prints counts per table, path type and result, plus the
  `created_at` range of any blob that decrypts. It never prints, logs or
  writes key material, plaintext, user IDs, sealing contexts or blobs. Any
  plaintext it recovers is zeroed and discarded at once.
- **Credentials come from the environment.** It never prompts for them or
  echoes them. On failure it prints only the error class and code, because
  driver messages can contain connection details.
- No dependencies beyond Bun (it uses the built-in `Bun.sql` client).

## Running it

Sam authorises the run; the operator he picks runs it.

1. Check out this repository at the reviewed commit and run `bun install`.
2. Put the two values into the process environment from Secret Bridge or
   TinyCloud Secrets. Don't type them on the command line or paste them into
   chat.
   - `DATABASE_URL`: the production OpenKey database. Use a read-only role if
     one exists; the script is read-only regardless.
   - `DEV_SEALING_KEY`: the value in the openkey-api CVM's encrypted env (the
     name is listed in its `allowed_envs`). It's optional: without it, only the
     public dev keys are tried, and the output says so.
3. From the repository root, with `--no-env-file`. Bun otherwise loads a local
   `.env` (as `docs/development.md` sets up), whose `DATABASE_URL` and
   `DEV_SEALING_KEY` would silently replace the real ones:

   ```sh
   bun --no-env-file run ops/tc-966-mock-seal-check/check.ts
   ```

   The first line of output names the database that was checked
   (`current_database()`). Confirm it is production.

The run takes one sequential pass over the three tables. They are small, so
the rows are read in one go.

## Reading the result

| Result | Meaning | Action |
|---|---|---|
| `decrypts with a public dev key` | Sealed by the mock client under a key published in this repository. **Anyone can derive this key.** Production (dstack) also can't unseal it, so the user's key is broken. If the deployment's `DEV_SEALING_KEY` equals a published value, its blobs land here, because that key is public too. | Treat as compromised. Escalate immediately; the affected keys need rotation and user notification. |
| `decrypts with the prod DEV_SEALING_KEY` | Sealed by the mock client with the deployment's `DEV_SEALING_KEY`. Not public, but sealed outside the TEE: anyone with the env could unseal it. Production can't unseal it either. | Treat as exposed. Escalate the same way. |
| `doesn't decrypt` | Didn't authenticate under **the tested mock keys**. That's expected for dstack-sealed blobs, and for blobs from before 2026-02-03 (the old `TappdClient` derivation). It is not proof against a mock seal under some other `DEV_SEALING_KEY` (see below). | None, within the limits below. |
| `malformed blob` | Shorter than an AES-GCM seal (12-byte IV + 16-byte tag). | Investigate separately. |
| `no sealing path` | Legacy `ethereum_keys` row with neither `userId` nor `sealingContext`, so there's no path to test. | Inconclusive for these rows; note the count. |

The verdict is the last line or two:
- `VERDICT: AFFECTED: N blob(s) decrypt with a mock key` (exit code 1). The
  `created_at` ranges show when it happened.
- `VERDICT: no blob decrypts with the tested mock keys (…)` (exit code 0), followed
  by what wasn't covered. The output says whether the deployment's
  `DEV_SEALING_KEY` was tested or only the public dev keys.

**What a clean result does and doesn't prove.** It rules out mock seals under
the published dev keys, and under the `DEV_SEALING_KEY` you provided, for the
rows that exist now. It can't rule out:
- a mock seal under a **different or earlier** `DEV_SEALING_KEY`. The CVM's
  encrypted env was re-uploaded 15 times between 2026-02-02 and 2026-06-17, and
  only the current value can be tested;
- rows deleted since, and backups;
- the `no sealing path` rows.

If those gaps matter, a production-side canary settles them: any blob that
fails to unseal under dstack in production was not sealed by dstack.

Exit code 2 means the check didn't run: `DATABASE_URL` is missing, or there was
a connection or query error.

Share the whole output. It contains no secrets or identifiers.

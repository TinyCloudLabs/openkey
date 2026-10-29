# @openkey/capability-review

## Rule: one line per permission

Every permission descriptor (statement, label, template, hint) is one short
line that says what will happen, in plain words: "Read your data", "Decrypt
data with your key work/notes/k1". It does not explain the permission system.
Two lines are a rare exception that needs a reason.

Sam, 2026-10-29, after seeing the "Authorize capabilities" sheet on his phone:

> This is waay too long. If we ever are adding new descriptors to openkey they
> should be one line Max. 2 line are rare exceptions that need more text. As a
> principel permission requwats should be simple and clear. Clarity is more
> important than accuracy. We dont have to explain they permissioning system
> just that decryption will happen for example

Never say something false about what is granted, and never drop the line that
tells the owner about decryption, deletion or sharing: shorten it.

`test/copy-one-line.test.ts` enforces this: 50 characters per line (what fits
on a 390px-wide phone), 100 for a named two-line exception. Add an exception
there, with its reason, only when one line cannot say it.

## What this package does

The shared review model for every OpenKey authorization surface (CLI browser,
popup, iframe): it parses SIWE/ReCap requests into a presentation-safe model,
validates edits as a subset of the request, classifies severity, and renders
the consent copy (`src/copy.ts`, `src/statements.ts`). How each TinyCloud
registry ability is shown is in `registry-inventory.md`.

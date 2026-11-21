# Contributing to Wempo Accounts

Thanks for wanting to help. Accounts is a single Cloudflare Worker written in
plain JavaScript modules — no framework, no build step — so getting a local
copy running takes only a few commands.

## Setup

1. Install Node.js 22 or newer and [pnpm](https://pnpm.io). This repo uses
   pnpm only — please don't use `npm` or `npx`.

   ```bash
   corepack enable pnpm
   ```

2. Install dependencies:

   ```bash
   pnpm install
   ```

3. If you need secret values for a local run (Turnstile keys, the relay
   token), put them in a `.dev.vars` file at the repo root. It is
   git-ignored. Never commit it, and never paste its values into issues,
   logs, or pull requests.

4. Start the dev server with a local D1 database:

   ```bash
   pnpm run dev
   ```

## Tests

Tests use Node's built-in runner:

```bash
pnpm test
```

Run the whole suite before you open a pull request. It includes
migration-scoping tests that make sure Accounts only creates and writes its
own `wa_`-prefixed tables.

## Ground rules

- **License headers.** Everything here is AGPL-3.0-or-later. Every new `.js`
  or `.mjs` file starts with the same 17-line `//` license notice the
  existing files carry, followed by a blank line (copy it from `worker.mjs`).
  New `.css` files carry the same notice in a `/* */` comment. Any
  third-party code you bring in must be AGPLv3-compatible.
- **Plain JavaScript.** No frameworks and no build pipeline.
- **Stay in your own tables.** Accounts may create, read, and write only
  `wa_`-prefixed tables. It reads the forum's `users` table and writes to it
  only to insert a brand-new account; passwords are checked and set only
  through the forum worker (`api/relay.mjs`).
- **No secrets in code or commits.** No keys, peppers, or tokens anywhere in
  the repo.
- **Style.** Small files, early returns, immutable data, and named constants
  instead of magic numbers.

## Reporting issues

Open a GitHub issue at
<https://github.com/Wempo-s-Silly-Projects/wempo-accounts> with what you
did, what you expected, and what happened. For security problems, please
reach out privately instead of opening a public issue.

By contributing, you agree your work is licensed under AGPL-3.0-or-later
(see [COPYING](COPYING)).

# Contributing to Wempo Accounts

Thanks for wanting to help. Accounts is a Cloudflare Worker (vanilla
imperative JS, no frontend framework, no build step) sharing one D1
database and one identity layer with Wempo's Forum, so a
local run needs almost nothing.

## Setup

1. Install [pnpm](https://pnpm.io) (the only package manager this repo
   uses — never `npm`/`npx`):

   ```bash
   corepack enable pnpm
   ```

2. Install dependencies:

   ```bash
   pnpm install
   ```

3. For local-only development, put the secret bindings you need (Turnstile
   keys, the credential-relay token) in a `.dev.vars` file at the repo
   root. `.dev.vars` is git-ignored and never committed; never print its
   values.

4. Start the dev server on a local D1 store:

   ```bash
   pnpm run dev
   ```

## Tests

The suite is `node --test`, wired as `pnpm test`. It includes
migration-scoping tests that pin Accounts to its `wa_`-prefixed tables and
identity-readonly rows — run the whole suite before you push, not just one
file:

```bash
pnpm test
pnpx wrangler deploy --dry-run
```

## Ground rules

- **AGPL-3.0-or-later.** By contributing you agree your work is licensed
  under the same license as the repo (see [COPYING](COPYING)).
- **Vanilla imperative JS.** No new frameworks, no build pipeline.
- **Table scoping is law.** Accounts may create/read/write only
  `wa_`-prefixed tables; identity reads go through the forum's users table.
  The scoping tests fail if you break this.
- **Secrets stay out.** No keys, peppers, or tokens in code or commits.
- The house code style favors small files, early returns, immutable data,
  and named constants over magic numbers.

## Issues

Open a GitHub issue on
<https://github.com/Wempo-s-Silly-Projects/wempo-accounts> with what you
did, what you expected, and the actual result. Security reports: please
use a private channel rather than a public issue.

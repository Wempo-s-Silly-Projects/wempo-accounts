# Wempo Accounts

Wempo Accounts is the one place your Wempo account lives. You make your
account here, sign in here, and Accounts signs you into
[Wempo's Forum](https://wempos-forum.com) without a second login.

- **Live:** <https://accounts.wempos-forum.com>
- **Source:** <https://github.com/Wempo-s-Silly-Projects/wempo-accounts>

## What you can do

- **Make an account** — pick a username and password. The forum's username
  rules and word filter apply, and a Turnstile check keeps bots out.
- **Sign in** — username and password behind a Turnstile check. If your
  account has two-factor authentication turned on, Accounts asks for your
  6-digit code as a second step.
- **Change your password** — you confirm your current password first.
- **See and end your sessions** — list the places you're signed in to
  Accounts, end any one of them, or sign out everywhere (this also signs
  you out of the forum).
- **Single sign-on into Wempo's Forum** — the forum's Log in and Create
  account buttons send you here and bring you back signed in.

Two-factor setup and backup codes are not managed on Accounts today;
Accounts only checks the code at sign-in for accounts that already have
two-factor turned on.

## How the forum hands off to Accounts

1. The forum sends you to
   `https://accounts.wempos-forum.com/?return=https://wempos-forum.com`.
2. You sign in (or make an account). The page then calls
   `POST /api/sso/ticket` with that `return` value. Accounts only accepts a
   `return` that exactly matches an allowed site origin — no partial or
   pattern matches, so there are no open redirects.
3. Accounts creates a one-time ticket that lasts 60 seconds, stores only its
   SHA-256 hash, and sends your browser back to
   `https://wempos-forum.com/?wt=<ticket>`.
4. The forum's worker redeems the ticket by calling `POST /api/sso/redeem`
   over its service binding, proving itself with the shared relay token. A
   ticket redeems once, only for the site it was made for, and only before it
   expires; anything else gets the same `410` answer. A good redeem returns
   your user id, username, and role.
5. The forum starts its own session for you. Each site keeps its own cookie;
   Accounts' cookie (`wempo_account_session`) stays on the Accounts host.

Signing out of the forum sends you to
`https://accounts.wempos-forum.com/?signout=1`, which ends your Accounts
session too and shows the sign-in form instead of bouncing you back.

## How it's built

- **Cloudflare Workers** — plain JavaScript modules, no framework and no
  build step. `worker.mjs` routes `/api/*` to the handlers in `api/` and
  serves the page from `public/`.
- **Shared D1 database** — Accounts uses the same D1 database as Wempo's
  Forum. It reads the forum's `users` table for identity and keeps its own
  data in two tables of its own: `wa_sso_sessions` (Accounts sessions) and
  `wa_login_tickets` (the one-time tickets). See `migrations/`.
- **Service binding to the forum worker** — every password check or change
  goes to the forum worker over the `FORUM_WORKER` service binding
  (`api/relay.mjs`). The forum holds the password pepper and the hashes;
  **Accounts never sees a password hash.** Ending all your sessions also
  goes through this binding.
- **Rate limits** — Accounts has its own Workers rate limiters for sign-in,
  account creation, two-factor codes, password changes, ticket redeems, and
  general reads and writes (`wrangler.toml`).

## Local development

You need Node.js 22 or newer and [pnpm](https://pnpm.io) — this repo uses
pnpm only, never npm or npx.

```bash
corepack enable pnpm   # skip if you already have pnpm
pnpm install
pnpm run dev           # wrangler dev with a local D1 database
```

Run the tests:

```bash
pnpm test
```

## Secrets and deploys

The secrets (Turnstile keys and the relay token) are held by the owner.
For local runs, put the values you need in a `.dev.vars` file at the repo
root. It is git-ignored — never commit it and never print its contents.

Production deploys are run by the owner. Contributors don't need to deploy
anything; a pull request with passing tests is all that's needed.

See [CONTRIBUTING.md](CONTRIBUTING.md) to help out, and
[docs/architecture.md](docs/architecture.md) for a closer look at the design.

## License

AGPL-3.0-or-later — see the full text in [COPYING](COPYING). If you run a
modified version over a network, you must offer your users the source of
that version (AGPLv3 section 13). The source for this version is at
<https://github.com/Wempo-s-Silly-Projects/wempo-accounts>.

Copyright (C) 2026 ItsWempo

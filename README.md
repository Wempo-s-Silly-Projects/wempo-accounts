# Wempo Accounts

The unified sign-in site for the Wempo fleet: one login that walks members
across GooberCord, Wempo's Forum, and the relay lane, with Turnstile at the
front door and TOTP as the second factor.

- **Live:** <https://accounts.itswempo.workers.dev>
- **Source:** <https://github.com/Wempo-s-Silly-Projects/wempo-accounts>

Accounts keeps its own `wa_`-prefixed tables beside the shared identity
rows in one production D1 database. It may create/read/write only
`wa_`-prefixed tables and reads the forum's users table for identity; every
password verify/set rides the forum worker's token-gated credential relay,
so a password hash is written or read only by the forum worker.

## Features

- One session that tickets you into GooberCord and the forum (one-time
  60-second tickets — only their hashes are ever stored)
- Sign-in form with Turnstile challenge and optional TOTP step
- "Make a Wempo Account" lane for new members
- Manage page: password change and 2FA setup
- Exact-match origin `return=` allowlist — no open redirects

## Quick start (local dev)

Requirements: Node.js 22 or newer (22/24/26 LTS) and
[pnpm](https://pnpm.io), which is the only package manager this repo uses.

```bash
corepack enable pnpm          # skip if you already have pnpm
pnpm install
pnpm run dev                  # wrangler dev, local D1 store
```

Run the tests:

```bash
pnpm test
```

Secret bindings (Turnstile keys, the credential-relay token) are
owner-held; put what you need in a git-ignored `.dev.vars` for local runs —
never commit it and never print its values.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributing guide.

## License

AGPL-3.0-or-later — see the full text in [COPYING](COPYING). If you run a
modified version over a network, you owe your users the source of that
version (AGPLv3 section 13).

Copyright (C) 2026 ItsWempo

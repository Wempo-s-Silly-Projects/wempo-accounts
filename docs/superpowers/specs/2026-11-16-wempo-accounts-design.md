---
name: wempo-accounts-design
status: SIGN-OFF RECEIVED (2026-11-16) — §2 redirect handshake approved incl. sign-out-everywhere; scaffold may proceed
date: 2026-11-16
owner-codename-ecosystem: Project Experience (forum API, stays in wempos-forum) · Project Designer (5.0 framework, in progress) · Project Frontload (frontend/public) · Wempo Accounts (this doc)
---

# Wempo Accounts — one login for everything

`accounts.itswempo.workers.dev` — a dedicated account worker that every Wempo
project signs in through. Renames the "same forum account" story into
**Wempo Accounts** on both platforms. The account database is the SHARED
wempos-forum `users` table (the owner's explicit call: accounts keeps using
the wempos-forum database) — no second account registry ever exists.

## 1. What it is

- One account home: sign in, sign out, 2FA prompts, and (later) profile-ish
  account settings — under one roof, one URL.
- "Log into everything": after signing in at accounts, every member site
  (wempos-forum, GooberCord, future projects) admits you without a second
  login — while each site keeps its own local session and cookie (their
  existing tables, their existing behavior).
- The credentials stay exactly what they are today: the forum's password
  pepper, the forum's TOTP secrets, the existing `users` rows. No migration;
  every current user logs in with the credentials they already have.

## 2. How cross-site sign-in works (the sign-off decision)

Browsers do not allow one cookie across siblings' subdomains
(`accounts.itswempo.workers.dev` cannot set a cookie that
`wempos-forum.itswempo.workers.dev` reads — workers.dev is an eTLD+1
public-suffix entry; the Domain attribute would be refused). So the clean
fit is a redirect handshake, not a shared cookie:

1. A site's "Sign in with Wempo Accounts" button sends the member to
   `accounts.itswempo.workers.dev/login?return=<site-url>`.
2. Accounts authenticates (password + optional TOTP + Turnstile, all with
   the today-rules) and then redirects back with a ONE-TIME ticket code.
3. The site's worker redeems the ticket — service-binding call to the
   accounts worker (sibling workers.dev subrequests die at the edge on
   the public internet path; the service binding is the lane, same lesson
   as the GC↔forum relay) — and mints its OWN local session as it does
   today. The response carries the display identity it already reads
   (username, role, 2FA state); no credential material ever leaves the
   forum side.
4. Sign-out can be everywhere-at-once: each site's sign-out clears its
   local session AND offers a one-click "sign out everywhere", which
   revokes the tickets + the accounts-site SSO session.

Why this shape: it keeps the pepper where it lives (forum), keeps each
site's session model working exactly as deployed (their worker code barely
changes — login gains an alternate front door), and works on workers.dev
today and on a real domain later.

**Flagged for owner sign-off:** the handshake itself (tickets, service
binding, per-site local cookies), and the "sign out everywhere" affordance.
→ SIGN-OFF RECEIVED Nov 16 2026: approved.

## 3. Database surface

Shared `wempo-forum-data`; the accounts worker owns ONLY `wa_`-prefixed
tables (the GC rule, now the account-worker rule):

- `wa_login_tickets` — the one-time ticket codes (code, user_id,
  return-site, expires_at ≤ 60s, redeemed_at/consumed-by worker name).
  Nothing else; no profile data lives here.
- `wa_sso_sessions` — the sessions at the accounts SITE itself (what
  "sign out everywhere" revokes; cookie stays on the accounts host).

Password set/verify, TOTP, and Turnstile keep being the FORUM worker's
job (the existing relay contract via Project Experience gains only the
two relay routes accounts needs: verify + 2FA-state read — no new secret
paths, no printed secrets, ever).

## 4. The rename

- Copy on both platforms: "Wempo Account" everywhere an account is
  described (sign-in screens, register copy, settings).
- The forum's login route gains the Wempo Accounts front door (same
  fields first; the redirect adds on later, phase 2).
- GooberCord's login card: "Same forum account" chip becomes "One Wempo
  Account for everything".
- Visuals: Project Frontload tokens + blaxel in his welcome role.

## 5. Build phases

1. **Scaffold + login** — accounts worker on the shared DB (wa_ tables),
   password login through the forum relay, Turnstile, the page itself.
   Ships dark-first with the light theme beside it like the apps.
2. **The handshake** — tickets + forum/GC "Sign in with Wempo Accounts"
   buttons + sign-out-everywhere; the rename lands with this phase.
3. **Account settings** — change password (through the relay), sessions
   view, 2FA enroll/replace where the forum already has the primitives.

Deliberate non-goals for v1: OAuth-ish public API (no third-party clients),
profile editing (stays with each site), email (the accounts DB doesn't
carry it).

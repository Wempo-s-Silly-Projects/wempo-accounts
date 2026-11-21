// Wempo Accounts page: states rendered CSP-safe — the login form
// (+ the 2FA step, an extra field on the SAME form), the Make Account form,
// and the signed-in account-management view (identity, the relayed password
// change, the account's own sessions with per-row revoke + sign-out-
// everywhere, sign out). Everything builds DOM
// through el() and user data rides textContent only — never innerHTML; no
// inline styles (the theme toggle writes the data-theme attribute, CSSOM at
// most). The dialog idiom (self-remove on close) is not needed here: phase 1
// renders in-page states only.
import { el } from "./dom.js";
import { addTurnstileSlot, renderTurnstileSlots, takeTurnstileToken, refreshTurnstile } from "./turnstile.js";

const app = document.getElementById("app");

// In-memory only — never persisted anywhere; a reload re-reads /api/me.
let csrfToken = null;
let signingIn = false;

// The phase-2 handshake's return target: a member who arrived from a site's
// "Sign in with Wempo Accounts" button carries ?return=<origin>. The page
// does NOT judge the value (an off-allowlist return just means the plain
// login page, no error banner) — the server's POST /api/sso/ticket is the
// sole enforcement point; it answers a redirect only for an allowed origin.
const ssoReturn = new URLSearchParams(window.location.search).get("return") || null;

// The member-site names the continue-back card can speak of (the known
// member origin). The ?return value is NEVER trusted with navigation — the
// server's POST /api/sso/ticket allowlist and its redirect answer are the
// only gate; this map is a human label and nothing more.
const SSO_SITE_NAMES = {
  "https://wempos-forum.com": "Wempo Forum",
};

// --- theme (dark-first) --------------------------------------------------------
const THEME_KEY = "wa-theme";

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
}
applyTheme(localStorage.getItem(THEME_KEY) === "light" ? "light" : "dark");

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
  refreshTurnstile();
}

// --- shared bits ---------------------------------------------------------------

async function postJson(path, body, headers = {}) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  if (response.status === 204) return { status: 204, data: null };
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  return { status: response.status, data };
}

// --- the signed-in hand-off (the phase-2 return flow) --------------------------
// Both login paths (single-shot and the TOTP two-step) land here. With a
// ?return= target: ask the server to mint the one-time ticket and follow the
// redirect it answers (only ever an allowlisted origin — the server's
// answer, never the page's own judgment of the parameter). Any ticket
// failure — no session, a non-allowlisted origin, a network miss — just
// lands on the plain signed-in view; the member keeps their accounts-site
// session either way.
async function finishLogin(user) {
  if (!ssoReturn) {
    renderSignedIn(user);
    return;
  }
  try {
    const { status, data } = await postJson("/api/sso/ticket", { return: ssoReturn });
    if (status === 200 && data && typeof data.redirect === "string" && data.redirect) {
      window.location.assign(data.redirect);
      return;
    }
  } catch {
    /* the ticket service is unreachable → the plain signed-in view */
  }
  renderSignedIn(user);
}

// --- the login form (login + 2FA step on one form) -----------------------------

function loginView() {
  const error = el("p", { class: "form-error", hidden: "hidden" });
  const username = el("input", {
    type: "text",
    name: "username",
    autocomplete: "username",
    required: "required",
    maxlength: "24",
    spellcheck: "false",
    "aria-label": "Wempo Account username",
  });
  const password = el("input", {
    type: "password",
    name: "password",
    autocomplete: "current-password",
    required: "required",
    "aria-label": "Password",
  });
  const totp = el("input", {
    type: "text",
    name: "totp",
    autocomplete: "one-time-code",
    inputmode: "numeric",
    maxlength: "6",
    "aria-label": "Two-factor code",
    hidden: "hidden",
  });
  const totpLabel = el("label", { hidden: "hidden", text: "Two-factor code" });
  const submit = el("button", { type: "submit", class: "button", text: "Sign in" });
  const note = el("p", {
    class: "form-note",
    text: "One login for Wempo's projects — use the credentials you already have.",
  });

  const form = el(
    "form",
    { class: "auth-card", novalidate: "novalidate" },
    el("h1", { text: "Wempo Accounts" }),
    el("p", { class: "tagline", text: "One login for Wempo's projects." }),
    el("div", { class: "form-field" }, el("label", { text: "Username" }), username),
    el("div", { class: "form-field" }, el("label", { text: "Password" }), password),
    el("div", { class: "form-field" }, totpLabel, totp, note),
    error,
    submit,
  );
  addTurnstileSlot(form, "login");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (signingIn) return;
    error.hidden = true;
    let turnstileToken;
    try {
      turnstileToken = takeTurnstileToken(form);
    } catch (why) {
      error.textContent = why.message;
      error.hidden = false;
      return;
    }
    const payload = {
      username: username.value,
      password: password.value,
      "cf-turnstile-response": turnstileToken,
    };
    if (totp.value.trim()) payload.totp = totp.value.trim();
    signingIn = true;
    submit.disabled = true;
    submit.textContent = "Signing in…";
    try {
      const { status, data } = await postJson("/api/login", payload);
      if (status === 200 && data && data.user && !data.totpRequired) {
        csrfToken = data.csrfToken;
        await finishLogin(data.user);
        return;
      }
      if (status === 200 && data && data.totpRequired) {
        // The 2FA step: the SAME form gains the code field; the password is
        // re-proofed on the verify POST (the challenge-token shape is phase
        // 2+ — the pepper must never ride this worker).
        totp.hidden = false;
        totpLabel.hidden = false;
        submit.textContent = "Verify code";
        submit.disabled = false;
        signingIn = false;
        totp.focus();
        return;
      }
      error.textContent =
        status === 200 ? "Something went wrong." : (data && data.error) || "The username or password is incorrect.";
      error.hidden = false;
      renderTurnstileSlots(form).catch(() => {});
    } catch {
      error.textContent = "The login service could not be reached. Try again.";
      error.hidden = false;
      renderTurnstileSlots(form).catch(() => {});
    } finally {
      submit.disabled = false;
      if (submit.textContent === "Signing in…") submit.textContent = "Sign in";
      signingIn = false;
    }
  });

  renderTurnstileSlots(form).catch(() => {});
  return form;
}

// --- the Make Account form (§4b) -------------------------------------------------

function registerView() {
  const error = el("p", { class: "form-error", hidden: "hidden" });
  const username = el("input", {
    type: "text",
    name: "username",
    autocomplete: "username",
    required: "required",
    maxlength: "24",
    spellcheck: "false",
    "aria-label": "Wempo Account username",
  });
  const password = el("input", {
    type: "password",
    name: "password",
    autocomplete: "new-password",
    required: "required",
    minlength: "12",
    maxlength: "128",
    "aria-label": "Password",
  });
  const submit = el("button", { type: "submit", class: "button", text: "Make Account" });
  const note = el("p", {
    class: "form-note",
    text: "12–128 characters. The same Wempo Account signs you into every Wempo project.",
  });
  const switchToSignIn = el("button", {
    type: "button",
    class: "link-button",
    text: "Already have a Wempo Account? Sign in",
  });
  switchToSignIn.addEventListener("click", () => renderLogin());

  const heading = el("h1", { text: "Make a Wempo Account" });
  const tagline = el("p", { class: "tagline", text: "One account for Wempo's projects." });
  const form = el(
    "form",
    { class: "auth-card", novalidate: "novalidate" },
    heading,
    tagline,
    el("div", { class: "form-field" }, el("label", { text: "Username" }), username),
    el("div", { class: "form-field" }, el("label", { text: "Password" }), password, note),
    error,
    submit,
    el("p", { class: "form-swap" }, switchToSignIn),
  );
  addTurnstileSlot(form, "register");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (signingIn) return;
    error.hidden = true;
    let turnstileToken;
    try {
      turnstileToken = takeTurnstileToken(form);
    } catch (why) {
      error.textContent = why.message;
      error.hidden = false;
      return;
    }
    signingIn = true;
    submit.disabled = true;
    submit.textContent = "Making your account…";
    try {
      const { status, data } = await postJson("/api/register", {
        username: username.value,
        password: password.value,
        "cf-turnstile-response": turnstileToken,
      });
      if (status === 201 && data && data.user) {
        csrfToken = data.csrfToken;
        finishLogin(data.user); // auto-login + the §2 ticket redirect
        return;
      }
      error.textContent = (data && data.error) || "Account creation failed.";
      error.hidden = false;
      renderTurnstileSlots(form).catch(() => {});
    } catch {
      error.textContent = "The account service could not be reached. Try again.";
      error.hidden = false;
      renderTurnstileSlots(form).catch(() => {});
    } finally {
      submit.disabled = false;
      if (submit.textContent === "Making your account…") submit.textContent = "Make Account";
      signingIn = false;
    }
  });

  renderTurnstileSlots(form).catch(() => {});
  return form;
}

// --- the signed-in state (the account-management page) -------------------------
// The owner-approved "new account management" page: identity, the relayed
// password change, the account's own active sessions (per-row revoke +
// sign-out-everywhere), and the plain sign out. Every POST rides the
// X-CSRF-Token the boot's /api/me read (or the login itself) already holds;
// server copy rides data.error verbatim, and every user-controlled string is
// textContent only — never innerHTML.

function csrfHeaders() {
  return { "X-CSRF-Token": csrfToken || "" };
}

function formatWhen(seconds) {
  const when = new Date(Number(seconds) * 1000);
  return Number.isFinite(when.getTime()) ? when.toLocaleString() : "";
}

// The identity card: what the member is signed in as (and their role chip).
function identityCard(user) {
  return el(
    "div",
    { class: "auth-card" },
    el("h1", { text: "Wempo Accounts" }),
    el("p", { class: "tagline", text: "One login for Wempo's projects." }),
    el("p", { class: "signed-in-user" }, "Signed in as " + user.username + " "),
    el("p", { class: "form-note" },
      "Role: ",
      el("span", { class: "role-chip", text: user.role }),
    ),
  );
}

// The password-change card: the POST rides the relay (accounts never sees a
// pepper); a wrong current password is a clean 403 and a degraded relay never
// changes anything — every failure keeps the form ready for another try.
function passwordChangeCard(signedOut) {
  const error = el("p", { class: "form-error", hidden: "hidden" });
  const notice = el("p", { class: "form-status", hidden: "hidden" });
  const current = el("input", {
    type: "password",
    autocomplete: "current-password",
    required: "required",
    "aria-label": "Current password",
  });
  const fresh = el("input", {
    type: "password",
    autocomplete: "new-password",
    required: "required",
    minlength: "12",
    maxlength: "128",
    "aria-label": "New password",
  });
  const note = el("p", {
    class: "form-note",
    text: "12–128 characters. Every Wempo site signs in with it.",
  });
  const submit = el("button", { type: "submit", class: "button", text: "Change password" });
  let busy = false;

  const form = el(
    "form",
    { class: "auth-card", novalidate: "novalidate" },
    el("h2", { text: "Change password" }),
    el("div", { class: "form-field" }, el("label", { text: "Current password" }), current),
    el("div", { class: "form-field" }, el("label", { text: "New password" }), fresh, note),
    error,
    notice,
    submit,
  );

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    error.hidden = true;
    notice.hidden = true;
    if (fresh.value.length < 12 || fresh.value.length > 128) {
      error.textContent = "Password must be 12–128 characters long.";
      error.hidden = false;
      return;
    }
    busy = true;
    submit.disabled = true;
    submit.textContent = "Changing…";
    try {
      const { status, data } = await postJson(
        "/api/password/change",
        { currentPassword: current.value, newPassword: fresh.value },
        csrfHeaders(),
      );
      if (status === 200 && data && data.changed === true) {
        current.value = "";
        fresh.value = "";
        notice.textContent = "Password changed.";
        notice.hidden = false;
      } else if (status === 401) {
        signedOut(); // the session is gone — the boot flow decides the view
        return;
      } else {
        error.textContent =
          (data && data.error) || "That didn't go through. Nothing was changed — try again.";
        error.hidden = false;
      }
    } catch {
      error.textContent = "The account service could not be reached. Try again.";
      error.hidden = false;
    } finally {
      submit.disabled = false;
      submit.textContent = "Change password";
      busy = false;
    }
  });

  return form;
}

// The sessions card: the account's own wa_sso_sessions rows, per-row revoke,
// sign-out-everywhere (a two-tap confirm — no dialogs under this CSP), and
// the plain sign out last.
function sessionsCard(signedOut) {
  const list = el("div", { class: "session-list" },
    el("p", { class: "form-note", text: "Loading your sessions…" }));
  const error = el("p", { class: "form-error", hidden: "hidden" });
  const notice = el("p", { class: "form-status", hidden: "hidden" });
  const everywhere = el("button", {
    type: "button", class: "button button-quiet", text: "Sign out everywhere",
  });
  const everywhereNote = el("p", {
    class: "form-note",
    text: "Signs you out of Wempo Accounts AND every member site — this browser included.",
  });
  const signOut = el("button", { type: "button", class: "button button-quiet", text: "Sign out" });
  let loading = false;
  let armed = false;

  async function load() {
    if (loading) return;
    loading = true;
    try {
      const response = await fetch("/api/sessions");
      if (response.status === 401) {
        signedOut();
        return;
      }
      if (!response.ok) throw new Error("sessions " + response.status);
      const data = await response.json();
      renderRows(Array.isArray(data && data.sessions) ? data.sessions : []);
    } catch {
      list.replaceChildren(
        el("p", { class: "form-note", text: "The session list could not be loaded. Try again." }),
      );
    } finally {
      loading = false;
    }
  }

  function resetArmed() {
    armed = false;
    everywhere.textContent = "Sign out everywhere";
    everywhere.disabled = false;
  }

  function renderRows(rows) {
    resetArmed();
    if (!rows.length) {
      list.replaceChildren(el("p", { class: "form-note", text: "No other active sessions." }));
      return;
    }
    list.replaceChildren(...rows.map((row) => {
      const when = el("span", {
        class: "session-when",
        text: "Signed in " + formatWhen(row.createdAt) + (row.current ? " — this browser" : ""),
      });
      const line = el("div", { class: "session-row" }, when);
      if (row.current) {
        line.append(el("span", { class: "role-chip", text: "This browser" }));
        return line;
      }
      const revoke = el("button", { type: "button", class: "button button-small", text: "Revoke" });
      revoke.addEventListener("click", async () => {
        revoke.disabled = true;
        try {
          const { status, data } = await postJson(
            "/api/sessions/revoke", { sessionId: row.id }, csrfHeaders(),
          );
          if (status === 401 || (status === 200 && data && data.signedOut)) {
            signedOut(); // revoking the calling session behaves like logout
            return;
          }
          notice.textContent = "That session is signed out.";
          notice.hidden = false;
          await load();
        } catch {
          revoke.disabled = false;
        }
      });
      line.append(revoke);
      return line;
    }));
  }

  // Sign-out-everywhere is destructive enough for a two-tap confirm, built
  // in-page (the viewer never opens a confirm() dialog under this CSP).
  everywhere.addEventListener("click", async () => {
    if (!armed) {
      armed = true;
      everywhere.textContent = "Tap again to sign out everywhere";
      return;
    }
    armed = false;
    everywhere.disabled = true;
    everywhere.textContent = "Signing out…";
    error.hidden = true;
    notice.hidden = true;
    try {
      const { status, data } = await postJson("/api/sessions/revoke-all", {}, csrfHeaders());
      if (status === 401 || (status === 200 && data && data.signedOut)) {
        // "Everywhere" includes THIS browser — the server expired the cookie
        // and deleted the calling row, so the page drops to the sign-in form
        // (the shared calling-session shape).
        signedOut();
        return;
      }
      // Anything else is the fail-closed refusal (shared-toned copy) — the
      // page keeps its session list and stays usable for another try.
      error.textContent =
        (data && data.error) || "That didn't go through. Nothing was signed out — try again.";
      error.hidden = false;
    } catch {
      error.textContent = "The account service could not be reached. Nothing was signed out.";
      error.hidden = false;
    } finally {
      armed = false;
      everywhere.disabled = false;
      everywhere.textContent = "Sign out everywhere";
    }
  });

  signOut.addEventListener("click", async () => {
    if (loading) return;
    signOut.disabled = true;
    signOut.textContent = "Signing out…";
    try {
      const { status } = await postJson("/api/logout", {}, csrfHeaders());
      if (status === 204 || status === 401) {
        signedOut();
        return;
      }
      signOut.disabled = false;
      signOut.textContent = "Sign out";
    } catch {
      signOut.disabled = false;
      signOut.textContent = "Sign out";
    }
  });

  load();

  return el(
    "div",
    { class: "auth-card" },
    el("h2", { text: "Active sessions" }),
    list,
    error,
    notice,
    everywhere,
    everywhereNote,
    el("div", { class: "signout-row" }, signOut,
      el("p", {
        class: "form-note",
        text: "Sign out signs you out of Wempo Accounts only. Use Sign out everywhere to leave the member sites too.",
      })),
  );
}

// The continue-back card: post-loop-breaker, a plain ?return= arrival with a
// live session lands HERE (no auto-ticket — the deliberate behavior), so the
// way back is a visible one-tap instead of a dead end. The button runs the
// SAME manual ticket flow a fresh login runs (POST /api/sso/ticket → follow
// the redirect the SERVER answers — never the raw parameter) and the known
// member origins get their name in the label.
function continueBackCard() {
  const siteName = SSO_SITE_NAMES[ssoReturn] || "that site";
  const goLabel = "Continue to " + siteName;
  const error = el("p", { class: "form-error", hidden: "hidden" });
  let busy = false;
  const go = el("button", { type: "button", class: "button", text: goLabel });

  go.addEventListener("click", async () => {
    if (busy) return;
    busy = true;
    go.disabled = true;
    go.textContent = "Continuing…";
    error.hidden = true;
    try {
      const { status, data } = await postJson("/api/sso/ticket", { return: ssoReturn });
      if (status === 200 && data && typeof data.redirect === "string" && data.redirect) {
        window.location.assign(data.redirect); // the SERVER's answer, never the parameter
        return;
      }
      error.textContent =
        (data && data.error) || "The sign-in hand-off did not go through. Try again.";
      error.hidden = false;
    } catch {
      error.textContent = "The account service could not be reached. Try again.";
      error.hidden = false;
    } finally {
      busy = false;
      go.disabled = false;
      go.textContent = goLabel;
    }
  });

  return el(
    "div",
    { class: "auth-card" },
    el("h2", { text: siteName === "that site" ? "Continue back" : "Back to " + siteName }),
    el("p", { class: "form-note", text: "You are already signed in here." }),
    go,
    error,
  );
}

function signedInView(user) {
  const signedOut = () => {
    csrfToken = null;
    renderLogin();
  };
  const cards = [identityCard(user), passwordChangeCard(signedOut), sessionsCard(signedOut)];
  if (ssoReturn) cards.unshift(continueBackCard());
  return cards;
}

// --- the three-way render ---------------------------------------------------------

function renderLogin() {
  const makeAccount = el("button", {
    type: "button",
    class: "link-button",
    text: "New here? Make a Wempo Account",
  });
  makeAccount.addEventListener("click", () => renderRegister());
  app.replaceChildren(
    loginView(),
    el("p", { class: "form-swap" }, makeAccount),
    el("p", { class: "theme-note" },
      el("button", { type: "button", class: "theme-toggle", onclick: toggleTheme, text: "Switch theme" }),
    ),
  );
}

function renderRegister() {
  app.replaceChildren(
    registerView(),
    el("p", { class: "theme-note" },
      el("button", { type: "button", class: "theme-toggle", onclick: toggleTheme, text: "Switch theme" }),
    ),
  );
}

function renderSignedIn(user) {
  app.replaceChildren(
    ...signedInView(user),
    el("p", { class: "theme-note" },
      el("button", { type: "button", class: "theme-toggle", onclick: toggleTheme, text: "Switch theme" }),
    ),
  );
}

async function boot() {
  // ?signout=1: a member site's sign-out hands the browser here so the
  // accounts-site session clears too — without it, an existing Accounts
  // session would auto-ticket straight back through the return flow and the
  // member could never actually leave. Best-effort; the member then sees
  // the sign-in form (never the return redirect).
  if (new URLSearchParams(window.location.search).get("signout")) {
    try {
      const me = await fetch("/api/me");
      if (me.ok) {
        const data = await me.json();
        await fetch("/api/logout", {
          method: "POST",
          headers: { "X-CSRF-Token": data.csrfToken || "" },
        });
      }
    } catch {
      /* the member simply keeps the accounts session they came with */
    }
    renderLogin();
    return;
  }
  // The signed-in read decides the first view; a failed read is just the
  // login form (never an error page — the account home always answers).
  try {
    const response = await fetch("/api/me");
    if (response.ok) {
      const data = await response.json();
      csrfToken = data.csrfToken;
      // A PLAIN arrival with ?return= and a pre-existing session renders the
      // signed-in view — never an auto-ticket. Auto-ticketing on every
      // arrival turned any sibling site's persistent redeem refusal into a
      // ~10-hop cross-origin bounce carousel, each hop burning the login
      // limiter until a 429 stranded the member (the audit's loop-breaker
      // finding). Only THIS site's own login/register success auto-tickets
      // (the finishLogin leg); from the account page the member can use
      // their site's sign-in button again and complete the hand-off there.
      renderSignedIn(data.user);
      return;
    }
  } catch {
    /* offline → the login form */
  }
  renderLogin();
}

boot();

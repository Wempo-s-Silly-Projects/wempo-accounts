// Wempo Accounts login page: states rendered CSP-safe — the login form
// (+ the 2FA step, an extra field on the SAME form), and the signed-in
// state (username + role chip + sign out). Everything builds DOM
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

// --- the signed-in state --------------------------------------------------------

function signedInFromMe(user) {
  return signedInView(user);
}

function signedInView(user) {
  const signOut = el("button", { type: "button", class: "button button-quiet", text: "Sign out" });
  signOut.addEventListener("click", async () => {
    if (signingIn) return;
    signOut.disabled = true;
    signOut.textContent = "Signing out…";
    const { status } = await postJson("/api/logout", {}, { "X-CSRF-Token": csrfToken || "" });
    if (status === 204 || status === 401) {
      csrfToken = null;
      renderLogin();
      return;
    }
    signOut.disabled = false;
    signOut.textContent = "Sign out";
  });

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
    signOut,
  );
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
    signedInFromMe(user),
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
      // A member site may send an already-authenticated Accounts session
      // back here. Complete the same SSO ticket hand-off as a fresh login.
      await finishLogin(data.user);
      return;
    }
  } catch {
    /* offline → the login form */
  }
  renderLogin();
}

boot();

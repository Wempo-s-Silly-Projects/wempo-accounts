// The Turnstile client for the login page (a trimmed copy of GooberCord's
// public/js/turnstile.js): the widget loads lazily, the token rides the
// login POST as `cf-turnstile-response`, and nothing user-facing is built
// with markup strings. The sitekey CONSTANT is Accounts' OWN widget — the
// owner mints a Turnstile widget for accounts.itswempo.workers.dev
// (TURNSTILE_HOSTNAMES in wrangler.toml) and pastes its sitekey here; an
// empty string keeps the widget unrendered (the server stays fail-closed).
const TURNSTILE_SITEKEY = "";
const TURNSTILE_SCRIPT = "https://challenges.cloudflare.com/turnstile/v0/api.js";

const widgets = new Map();
let loadPromise = null;

async function ensureTurnstile(timeoutMs = 15_000) {
  if (!loadPromise) {
    loadPromise = (async () => {
      const script = document.createElement("script");
      script.src = TURNSTILE_SCRIPT;
      script.async = true;
      script.defer = true;
      document.head.append(script);
      const deadline = Date.now() + timeoutMs;
      while (!window.turnstile) {
        if (Date.now() > deadline) {
          throw new Error("The human-verification widget failed to load. Refresh the page and try again.");
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      return window.turnstile;
    })();
    const attempt = loadPromise;
    attempt.catch(() => {
      if (loadPromise === attempt) loadPromise = null;
    });
  }
  return loadPromise;
}

export function addTurnstileSlot(form, action) {
  const slot = document.createElement("div");
  slot.className = "turnstile-slot";
  slot.dataset.turnstileAction = action;
  slot.dataset.verificationPending = "true";
  const submitButton = form.querySelector('button[type="submit"]');
  form.insertBefore(slot, submitButton);
  widgets.set(form, { widgetId: null, token: "" });
}

// Turnstile follows the site theme: the dark-first page defaults dark, a
// manual toggle wins.
function resolvedTurnstileTheme() {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export async function renderTurnstileSlots(root) {
  const pending = root.querySelectorAll(".turnstile-slot[data-verification-pending]");
  for (const slot of pending) {
    delete slot.dataset.verificationPending;
    const form = slot.closest("form");
    const state = widgets.get(form);
    if (!state) continue;
    // Local dev keeps the dummy-token flow (the dev testing secret in
    // .dev.vars): the real widget can't mint a token the testing secret
    // accepts, and the real script doesn't render inside loopback previews.
    const hostname = globalThis.location?.hostname || "";
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "[::1]" ||
      hostname.endsWith(".local")
    ) {
      state.token = "XXXX.DUMMY.PASS.TOKEN.XXXX";
      delete slot.dataset.verificationPending;
      continue;
    }
    if (!TURNSTILE_SITEKEY) {
      state.token = "";
      const note = document.createElement("small");
      note.className = "form-note";
      note.textContent = "Human verification is not configured yet. The owner mints the widget and pastes its sitekey.";
      slot.append(note);
      continue;
    }
    try {
      const turnstile = await ensureTurnstile();
      if (slot.isConnected && !state.widgetId) {
        state.widgetId = turnstile.render(slot, {
          sitekey: TURNSTILE_SITEKEY,
          theme: resolvedTurnstileTheme(),
          action: slot.dataset.turnstileAction,
          callback: (token) => {
            delete slot.dataset.turnstileError;
            state.token = token;
          },
          "error-callback": (code) => {
            slot.dataset.turnstileError = code || "unknown";
            state.token = "";
          },
          "expired-callback": () => {
            delete slot.dataset.turnstileError;
            state.token = "";
          },
        });
      }
    } catch (error) {
      slot.replaceChildren();
      state.widgetId = null;
      addTextToSlot(slot, error.message);
    }
  }
}

function addTextToSlot(slot, message) {
  const note = document.createElement("small");
  note.className = "form-note";
  note.textContent = message;
  slot.append(note);
}

export function takeTurnstileToken(form) {
  const state = widgets.get(form);
  if (!state || !state.token) {
    throw new Error("Please complete the human-verification step first.");
  }
  const token = state.token;
  state.token = "";
  return token;
}

// Theme switches (Turnstile cannot retheme in place): park the token and
// re-render the live widget under the new scheme.
export function refreshTurnstile() {
  for (const form of widgets.keys()) {
    const state = widgets.get(form);
    state.token = "";
    const slot = form.querySelector(".turnstile-slot");
    if (!slot) continue;
    if (state.widgetId !== null) {
      try { window.turnstile?.remove(state.widgetId); } catch { /* widget already gone */ }
      state.widgetId = null;
      delete slot.dataset.turnstileError;
      slot.dataset.verificationPending = "true";
    }
  }
  renderTurnstileSlots(document).catch(() => {
    // Best-effort: a failed re-render surfaces through the normal error path.
  });
}

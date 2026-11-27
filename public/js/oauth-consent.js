// Copyright 2026 ItsWempo
//
// This file is part of Wempo Accounts.
//
// Wempo Accounts is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>

const app = document.getElementById("app");
const params = new URLSearchParams(window.location.search);
const request = {
  response_type: params.get("response_type") || "",
  client_id: params.get("client_id") || "",
  redirect_uri: params.get("redirect_uri") || "",
  scope: params.get("scope") || "",
  state: params.get("state") || "",
  code_challenge: params.get("code_challenge") || "",
  code_challenge_method: params.get("code_challenge_method") || "",
  nonce: params.get("nonce") || "",
};

const scopeDescriptions = {
  openid: "Confirm your Wempo Account identity",
  profile: "Share your Wempo username and display name",
};

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function showError(message) {
  const card = element("section", null, "auth-card");
  card.append(
    element("h1", "Authorization unavailable"),
    element("p", message, "form-error"),
    element("a", "Return to Wempo Accounts", "form-swap"),
  );
  card.lastChild.href = "/";
  app.replaceChildren(card);
}

async function postDecision(csrfToken, approved, buttons) {
  for (const button of buttons) button.disabled = true;
  try {
    const response = await fetch("/api/oauth/authorize", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
      body: JSON.stringify({ ...request, approved }),
    });
    const data = await response.json().catch(() => null);
    if (!response.ok || !data || typeof data.redirect !== "string") {
      showError((data && data.error) || "The authorization decision could not be completed.");
      return;
    }
    window.location.assign(data.redirect);
  } catch {
    showError("The account service could not be reached. Try again.");
  } finally {
    for (const button of buttons) button.disabled = false;
  }
}

async function boot() {
  try {
    const [sessionResponse, infoResponse] = await Promise.all([
      fetch("/api/me"),
      (() => {
        const url = new URL("/api/oauth/authorize-info", window.location.origin);
        url.search = window.location.search;
        return fetch(url);
      })(),
    ]);
    if (sessionResponse.status === 401) {
      const login = new URL("/", window.location.origin);
      login.searchParams.set("oauth_request", window.location.href);
      window.location.assign(login.toString());
      return;
    }
    const session = await sessionResponse.json();
    const info = await infoResponse.json();
    if (!sessionResponse.ok || !infoResponse.ok || !session.csrfToken) {
      showError((info && info.error) || "This authorization request could not be verified.");
      return;
    }

    const card = element("section", null, "auth-card");
    card.append(
      element("h1", "Allow this application?"),
      element("p", info.client_name + " is requesting access to your Wempo Account.", "tagline"),
      element("p", "If you continue, this application will be able to:", "form-note"),
    );
    const list = element("ul", null, "oauth-scope-list");
    for (const scope of info.scopes || []) {
      list.append(element("li", scopeDescriptions[scope] || scope));
    }
    card.append(list);
    card.append(element("p", "You can revoke this application's access later by disabling it through Wempo Accounts.", "form-note"));

    const actions = element("div", null, "oauth-actions");
    const approve = element("button", "Allow", "button");
    approve.type = "button";
    const deny = element("button", "Deny", "button button-quiet");
    deny.type = "button";
    actions.append(deny, approve);
    card.append(actions);
    app.replaceChildren(card);

    const buttons = [deny, approve];
    approve.addEventListener("click", () => postDecision(session.csrfToken, true, buttons));
    deny.addEventListener("click", () => postDecision(session.csrfToken, false, buttons));
  } catch {
    showError("The account service could not be reached. Try again.");
  }
}

boot();

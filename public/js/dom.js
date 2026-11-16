// Tiny CSP-safe DOM factory (vendored from GooberCord's public/js/dom.js):
// every element is created via createElement and user-provided TEXT rides
// textContent only — never innerHTML (the forum's escaping discipline; user
// data must never reach a markup parser).

export function el(tagName, props = {}, ...children) {
  const element = document.createElement(tagName);

  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null) continue;

    if (key === "class") {
      element.className = String(value);
      continue;
    }

    if (key === "text") {
      element.textContent = String(value);
      continue;
    }

    if (key === "dataset") {
      for (const [dk, dv] of Object.entries(value)) {
        if (dv !== undefined && dv !== null) element.dataset[dk] = String(dv);
      }
      continue;
    }

    if (key.startsWith("on") && typeof value === "function") {
      element.addEventListener(key.slice(2).toLowerCase(), value);
      continue;
    }

    if (key === "value") {
      element.value = String(value);
      continue;
    }

    element.setAttribute(key, String(value));
  }

  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    element.append(child);
  }

  return element;
}

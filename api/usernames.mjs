// The username shape rule shared with GooberCord's api/usernames.mjs (which
// mirrors the forum's api/core/shapers.mjs character for character): one
// rule, three apps.
export function isValidUsername(value) {
  return typeof value === "string" && /^[A-Za-z0-9_]{3,24}$/.test(value);
}

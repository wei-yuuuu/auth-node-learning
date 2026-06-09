export function normalizeEmail(email) {
  if (typeof email !== "string") {
    return "";
  }

  return email.trim().toLowerCase();
}

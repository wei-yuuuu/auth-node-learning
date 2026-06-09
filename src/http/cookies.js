export function parseCookies(cookieHeader = "") {
  const cookies = new Map();

  for (const part of cookieHeader.split(";")) {
    const [rawName, ...rawValueParts] = part.trim().split("=");

    if (!rawName) {
      continue;
    }

    cookies.set(rawName, decodeURIComponent(rawValueParts.join("=")));
  }

  return cookies;
}

export function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];

  if (options.maxAge !== undefined) {
    parts.push(`Max-Age=${options.maxAge}`);
  }

  parts.push("Path=/", "HttpOnly", "SameSite=Lax");

  if (options.secure) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

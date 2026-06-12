import { MIMEType } from "node:util";

// Anti-CSRF tokens are still common, especially for HTML forms. This JSON API
// starts with Pilcrow's stricter origin checks and non-simple content type so
// the browser must prove the request came from the same origin.

// These methods are safe for CSRF purposes because this server does not use
// them for state changes. Pilcrow's CSRF chapter specifically calls out GET and
// "GET-like" methods (HEAD, OPTIONS, TRACE) when discussing SameSite=Lax.
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);

export function validateUnsafeBrowserRequest(request) {
  if (SAFE_METHODS.has(request.method)) {
    return null;
  }

  const contentTypeError = validateJsonContentType(request.headers["content-type"]);

  if (contentTypeError) {
    return contentTypeError;
  }

  const csrfError = validateSameOrigin(request);

  if (csrfError) {
    return csrfError;
  }

  return null;
}

export function validateJsonContentType(header) {
  const mimeType = parseMimeType(header);

  if (mimeType !== "application/json") {
    return {
      statusCode: 415,
      message: "Unsafe requests must use Content-Type: application/json."
    };
  }

  return null;
}

export function validateSameOrigin(request) {
  const secFetchSite = singleHeader(request.headers["sec-fetch-site"]);

  // Sec-Fetch-Site is a browser-provided forbidden header. Pilcrow recommends
  // rejecting non-GET requests unless this value is exactly "same-origin".
  // This matters because browsers attach cookies automatically, so a malicious
  // page can try to send authenticated requests even if it cannot read them.
  if (secFetchSite !== null) {
    if (secFetchSite === "same-origin") {
      return null;
    }

    return {
      statusCode: 403,
      message: "Cross-site request blocked."
    };
  }

  const origin = singleHeader(request.headers.origin);
  const trustedOrigin = requestOrigin(request);

  // Origin is the fallback when Sec-Fetch-Site is unavailable. It must match
  // exactly; same-site subdomains are still different origins.
  if (!origin || !trustedOrigin || origin !== trustedOrigin) {
    return {
      statusCode: 403,
      message: "Unsafe requests must come from the same origin."
    };
  }

  return null;
}

function parseMimeType(header) {
  const value = singleHeader(header);

  if (value === null) {
    return null;
  }

  try {
    return new MIMEType(value).essence.toLowerCase();
  } catch {
    return null;
  }
}

function requestOrigin(request) {
  const host = singleHeader(request.headers.host);

  if (host === null) {
    return null;
  }

  const protocol = request.socket?.encrypted ? "https" : "http";

  return `${protocol}://${host}`;
}

function singleHeader(header) {
  if (Array.isArray(header)) {
    return header.at(0) ?? null;
  }

  return header ?? null;
}

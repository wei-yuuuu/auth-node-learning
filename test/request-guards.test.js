import assert from "node:assert/strict";
import test from "node:test";
import {
  CSRF_COOKIE,
  CSRF_HEADER,
  validateCsrfToken,
  validateJsonContentType,
  validateSameOrigin,
  validateUnsafeBrowserRequest
} from "../src/http/request-guards.js";

test("validateJsonContentType accepts only application/json MIME type", () => {
  assert.equal(validateJsonContentType("application/json"), null);
  assert.equal(validateJsonContentType("application/json; charset=utf-8"), null);
  assert.deepEqual(
    validateJsonContentType("text/plain; application/json"),
    {
      statusCode: 415,
      message: "Unsafe requests must use Content-Type: application/json."
    }
  );
  assert.deepEqual(validateJsonContentType(null), {
    statusCode: 415,
    message: "Unsafe requests must use Content-Type: application/json."
  });
});

test("validateSameOrigin accepts Sec-Fetch-Site same-origin", () => {
  assert.equal(
    validateSameOrigin(request({
      "sec-fetch-site": "same-origin"
    })),
    null
  );
});

test("validateSameOrigin rejects cross-site browser requests", () => {
  assert.deepEqual(
    validateSameOrigin(request({
      "sec-fetch-site": "cross-site"
    })),
    {
      statusCode: 403,
      message: "Cross-site request blocked."
    }
  );
});

test("validateSameOrigin falls back to exact Origin matching", () => {
  assert.equal(
    validateSameOrigin(request({
      host: "localhost:3000",
      origin: "http://localhost:3000"
    })),
    null
  );
  assert.deepEqual(
    validateSameOrigin(request({
      host: "localhost:3000",
      origin: "http://evil.test"
    })),
    {
      statusCode: 403,
      message: "Unsafe requests must come from the same origin."
    }
  );
});

test("validateUnsafeBrowserRequest skips safe methods and guards unsafe methods", () => {
  assert.equal(validateUnsafeBrowserRequest(request({}, "GET")), null);
  assert.equal(
    validateUnsafeBrowserRequest(request({
      "content-type": "application/json",
      "sec-fetch-site": "same-origin",
      cookie: `${CSRF_COOKIE}=token`,
      [CSRF_HEADER]: "token"
    }, "POST")),
    null
  );
  assert.deepEqual(
    validateUnsafeBrowserRequest(request({
      "content-type": "application/json"
    }, "POST")),
    {
      statusCode: 403,
      message: "Unsafe requests must come from the same origin."
    }
  );
});

test("validateCsrfToken requires matching cookie and request header", () => {
  assert.equal(
    validateCsrfToken(request({
      cookie: `${CSRF_COOKIE}=token`,
      [CSRF_HEADER]: "token"
    })),
    null
  );
  assert.deepEqual(
    validateCsrfToken(request({
      cookie: `${CSRF_COOKIE}=token`,
      [CSRF_HEADER]: "other-token"
    })),
    {
      statusCode: 403,
      message: "CSRF token is missing or invalid."
    }
  );
  assert.deepEqual(validateCsrfToken(request({})), {
    statusCode: 403,
    message: "CSRF token is missing or invalid."
  });
});

function request(headers, method = "POST") {
  return {
    method,
    headers,
    socket: {
      encrypted: false
    }
  };
}

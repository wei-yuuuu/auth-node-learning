import assert from "node:assert/strict";
import test from "node:test";
import { serializeCookie } from "../src/http/cookies.js";

test("serializeCookie keeps auth cookies HttpOnly by default", () => {
  assert.equal(
    serializeCookie("auth_session", "token"),
    "auth_session=token; Path=/; HttpOnly; SameSite=Lax"
  );
});

test("serializeCookie can expose a CSRF cookie to browser JavaScript", () => {
  assert.equal(
    serializeCookie("csrf_token", "token", { httpOnly: false }),
    "csrf_token=token; Path=/; SameSite=Lax"
  );
});

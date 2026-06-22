import assert from "node:assert/strict";
import test from "node:test";
import { EmailCodeSigninService } from "../src/auth/email-code-signin-service.js";
import { SessionService } from "../src/auth/session-service.js";
import { SQLiteStore } from "../src/store/sqlite-store.js";

test("EmailCodeSigninService creates a hashed code and completes a single-use sign-in", async () => {
  const store = new SQLiteStore(":memory:");
  const sessions = new SessionService(store);
  const user = await store.createUser({
    email: "code@example.com",
    passwordHash: "hash"
  });
  let sentCode = null;
  let formattedCode = null;
  const service = new EmailCodeSigninService(store, sessions, {
    async sendEmailCodeSigninCode(_email, code) {
      formattedCode = code;
      sentCode = code.replace("-", "");
    }
  });

  const started = await service.createSigninCode(user);
  const [signInSessionId] = started.token.split(".");
  const storedCode = await store.getEmailCodeSigninCode(signInSessionId);

  assert.equal(started.ok, true);
  assert.match(sentCode, /^[A-HJ-NP-Z2-9]{8}$/);
  assert.notEqual(storedCode.codeHash, sentCode);
  assert.match(storedCode.codeHash, /^node-argon2id-email-code\$v=1\$m=16384,t=3,p=1,l=32\$/);

  const completed = await service.verifySigninCode(started.token, formattedCode);

  assert.equal(completed.ok, true);
  assert.notEqual(await sessions.validateAuthToken(completed.authToken), null);
  assert.equal(await store.getSession(signInSessionId), null);
  assert.equal(await store.getEmailCodeSigninCode(signInSessionId), null);
  assert.equal((await store.getUserById(user.id)).emailVerified, true);
  assert.deepEqual(await service.verifySigninCode(started.token, sentCode), {
    ok: false,
    error: "Sign-in code expired.",
    clearSession: true
  });
});

test("EmailCodeSigninService expires sign-in sessions with node:test mock timers", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 0 });

  const store = new SQLiteStore(":memory:");
  const sessions = new SessionService(store);
  const user = await store.createUser({
    email: "expired-code@example.com",
    passwordHash: "hash"
  });
  let sentCode = null;
  const service = new EmailCodeSigninService(store, sessions, {
    async sendEmailCodeSigninCode(_email, formattedCode) {
      sentCode = formattedCode.replace("-", "");
    }
  });

  const started = await service.createSigninCode(user);
  t.mock.timers.tick(60 * 60 * 1000 + 1);

  assert.deepEqual(await service.verifySigninCode(started.token, sentCode), {
    ok: false,
    error: "Sign-in code expired.",
    clearSession: true
  });
});

test("EmailCodeSigninService rate-limits verification per user", async () => {
  const store = new SQLiteStore(":memory:");
  const sessions = new SessionService(store);
  const user = await store.createUser({
    email: "rate-limited-code@example.com",
    passwordHash: "hash"
  });
  let sentCode = null;
  const service = new EmailCodeSigninService(store, sessions, {
    async sendEmailCodeSigninCode(_email, formattedCode) {
      sentCode = formattedCode.replace("-", "");
    }
  });
  const started = await service.createSigninCode(user);
  const wrongCode = sentCode[0] === "A" ? `B${sentCode.slice(1)}` : `A${sentCode.slice(1)}`;

  for (let index = 0; index < 5; index += 1) {
    assert.deepEqual(await service.verifySigninCode(started.token, wrongCode), {
      ok: false,
      error: "Sign-in code is incorrect."
    });
  }

  assert.deepEqual(await service.verifySigninCode(started.token, wrongCode), {
    ok: false,
    error: "Too many sign-in code attempts. Try again later."
  });
});

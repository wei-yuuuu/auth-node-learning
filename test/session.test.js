import assert from "node:assert/strict";
import test from "node:test";
import { SessionService } from "../src/auth/session-service.js";
import { SQLiteStore } from "../src/store/sqlite-store.js";

test("SessionService stores hashed session secrets and validates tokens", async () => {
  const store = new SQLiteStore(":memory:");
  const sessions = new SessionService(store);
  const token = await sessions.createAuthSession("user-1");
  const [sessionId, secret] = token.split(".");
  const storedSession = await store.getSession(sessionId);

  assert.equal(storedSession.userId, "user-1");
  assert.notEqual(storedSession.secretHashHex, secret);

  const validSession = await sessions.validateAuthToken(token);
  assert.equal(validSession.id, sessionId);

  await sessions.invalidateSession(sessionId);

  assert.equal(await sessions.validateAuthToken(token), null);
});

test("SessionService refreshes rolling expiration with node:test mock Date", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 0 });

  const store = new SQLiteStore(":memory:");
  const sessions = new SessionService(store);
  const token = await sessions.createAuthSession("user-1");
  const [sessionId] = token.split(".");
  const originalSession = await store.getSession(sessionId);

  t.mock.timers.tick(60 * 60 * 1000);

  const refreshedSession = await sessions.validateAuthToken(token);
  const storedSession = await store.getSession(sessionId);

  assert.equal(refreshedSession.id, sessionId);
  assert.ok(storedSession.expiresAt > originalSession.expiresAt);
});

test("SessionService consumes verification sessions for one matching action", async () => {
  const store = new SQLiteStore(":memory:");
  const sessions = new SessionService(store);
  const authToken = await sessions.createAuthSession("user-1");
  const [authSessionId] = authToken.split(".");
  const wrongPurposeToken = await sessions.createVerificationSession({
    userId: "user-1",
    action: "password-update",
    authSessionId
  });
  const token = await sessions.createVerificationSession({
    userId: "user-1",
    action: "password-update",
    authSessionId
  });
  const [sessionId] = token.split(".");

  assert.equal(
    await sessions.consumeVerificationToken(wrongPurposeToken, {
      action: "email-update",
      userId: "user-1",
      authSessionId
    }),
    false
  );
  assert.equal(await sessions.consumeVerificationToken(wrongPurposeToken, {
    action: "password-update",
    userId: "user-1",
    authSessionId
  }), false);
  assert.equal(await sessions.consumeVerificationToken(token, {
    action: "password-update",
    userId: "user-1",
    authSessionId
  }), true);
  assert.equal(await store.getSession(sessionId), null);
});

test("SessionService can invalidate other auth sessions only", async () => {
  const store = new SQLiteStore(":memory:");
  const sessions = new SessionService(store);
  const currentToken = await sessions.createAuthSession("user-1");
  const otherToken = await sessions.createAuthSession("user-1");
  const [currentSessionId] = currentToken.split(".");

  await sessions.invalidateOtherAuthSessions("user-1", currentSessionId);

  assert.notEqual(await sessions.validateAuthToken(currentToken), null);
  assert.equal(await sessions.validateAuthToken(otherToken), null);
});

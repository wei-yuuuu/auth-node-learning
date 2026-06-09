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

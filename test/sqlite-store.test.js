import assert from "node:assert/strict";
import test from "node:test";
import { SQLiteStore } from "../src/store/sqlite-store.js";

test("SQLiteStore persists users, sessions, and email verification codes", async () => {
  const store = new SQLiteStore(":memory:");
  const user = await store.createUser({
    email: "Demo@Example.com",
    passwordHash: "hash"
  });

  assert.equal(user.email, "demo@example.com");
  assert.equal(user.emailVerified, false);
  assert.equal((await store.getUserByEmail("demo@example.com")).id, user.id);

  await store.markEmailVerified(user.id);
  assert.equal((await store.getUserById(user.id)).emailVerified, true);

  await store.insertSession({
    id: "session-1",
    kind: "auth",
    userId: user.id,
    action: null,
    authSessionId: null,
    secretHashHex: "abc",
    createdAt: 1,
    expiresAt: 2
  });
  assert.equal((await store.getSession("session-1")).userId, user.id);

  await store.insertEmailVerificationCode({
    sessionId: "session-1",
    email: user.email,
    code: "12345678",
    expiresAt: 3
  });
  assert.equal(
    (await store.getEmailVerificationCode("session-1", "demo@example.com")).code,
    "12345678"
  );
});

test("SQLiteStore deletes expired sessions, email codes, and rate-limit buckets", async () => {
  const store = new SQLiteStore(":memory:");

  await store.insertSession({
    id: "expired-session",
    kind: "auth",
    userId: "user-1",
    action: null,
    authSessionId: null,
    secretHashHex: "abc",
    createdAt: 1,
    expiresAt: 10
  });
  await store.insertEmailVerificationCode({
    sessionId: "expired-session",
    email: "demo@example.com",
    code: "12345678",
    expiresAt: 10
  });
  await store.setRateLimitBucket("signin", "demo@example.com", {
    tokens: 0,
    updatedAt: 1,
    expiresAt: 10
  });

  const counts = await store.deleteExpiredRecords(11);

  assert.deepEqual(counts, {
    sessions: 1,
    emailVerificationCodes: 1,
    rateLimitBuckets: 1
  });
  assert.equal(await store.getSession("expired-session"), null);
  assert.equal(await store.getEmailVerificationCode("expired-session", "demo@example.com"), null);
  assert.equal(await store.getRateLimitBucket("signin", "demo@example.com"), null);
});

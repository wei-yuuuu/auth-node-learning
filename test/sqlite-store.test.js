import assert from "node:assert/strict";
import test from "node:test";
import { SQLiteStore } from "../src/store/sqlite-store.js";

test("SQLiteStore persists users, sessions, and email verification codes", async () => {
  const store = new SQLiteStore(":memory:");
  const user = await store.createUser({
    email: "demo@example.com",
    passwordHash: "hash"
  });

  assert.equal(user.email, "demo@example.com");
  assert.equal(user.emailVerified, false);
  assert.equal((await store.getUserByEmail("demo@example.com")).id, user.id);

  await store.markEmailVerified(user.id);
  assert.equal((await store.getUserById(user.id)).emailVerified, true);

  await store.updateUserEmail(user.id, "new-email@example.com");
  assert.equal((await store.getUserById(user.id)).email, "new-email@example.com");
  assert.equal((await store.getUserById(user.id)).emailVerified, true);

  await store.updateUserPassword(user.id, "new-hash");
  assert.equal((await store.getUserById(user.id)).passwordHash, "new-hash");

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

  await store.insertPasswordResetCode({
    email: user.email,
    code: "87654321",
    expiresAt: 4
  });
  assert.equal((await store.getPasswordResetCode("demo@example.com")).code, "87654321");
});

test("SQLiteStore rejects duplicate email updates", async () => {
  const store = new SQLiteStore(":memory:");
  const firstUser = await store.createUser({
    email: "first@example.com",
    passwordHash: "hash"
  });
  await store.createUser({
    email: "second@example.com",
    passwordHash: "hash"
  });

  await assert.rejects(
    () => store.updateUserEmail(firstUser.id, "second@example.com"),
    /Email address is already registered\./
  );
});

test("SQLiteStore rejects duplicate users", async () => {
  const store = new SQLiteStore(":memory:");

  await store.createUser({
    email: "demo@example.com",
    passwordHash: "hash"
  });

  await assert.rejects(
    () => store.createUser({
      email: "demo@example.com",
      passwordHash: "hash"
    }),
    /Email address is already registered\./
  );
});

test("SQLiteStore deletes expired auth records", async () => {
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
  await store.insertPasswordResetCode({
    email: "demo@example.com",
    code: "87654321",
    expiresAt: 10
  });
  await store.setRateLimitBucket("signin", "demo@example.com", {
    tokens: 0,
    updatedAt: 1,
    expiresAt: 10
  });
  await store.insertPasskeySigninAttempt({
    challengeHashHex: "challenge-hash",
    expiresAt: 10
  });

  const counts = await store.deleteExpiredRecords(11);

  assert.deepEqual(counts, {
    sessions: 1,
    emailVerificationCodes: 1,
    passwordResetCodes: 1,
    rateLimitBuckets: 1,
    passkeySigninAttempts: 1
  });
  assert.equal(await store.getSession("expired-session"), null);
  assert.equal(await store.getEmailVerificationCode("expired-session", "demo@example.com"), null);
  assert.equal(await store.getPasswordResetCode("demo@example.com"), null);
  assert.equal(await store.getRateLimitBucket("signin", "demo@example.com"), null);
  assert.equal(await store.getPasskeySigninAttempt("challenge-hash"), null);
});

test("SQLiteStore persists passkeys and sign-in attempts", async () => {
  const store = new SQLiteStore(":memory:");
  const user = await store.createUser({
    email: "passkey@example.com",
    passwordHash: "hash"
  });

  await store.insertPasskey({
    credentialId: "credential-1",
    userId: user.id,
    publicKeyDer: Buffer.from("public-key"),
    algorithm: -7,
    authenticatorId: "00000000000000000000000000000000",
    name: "MacBook Touch ID",
    signCount: 1,
    createdAt: 20
  });

  const passkey = await store.getPasskeyByCredentialId("credential-1");

  assert.equal(passkey.userId, user.id);
  assert.equal(passkey.name, "MacBook Touch ID");
  assert.deepEqual(passkey.publicKeyDer, Buffer.from("public-key"));
  assert.equal(await store.countPasskeysByUserId(user.id), 1);

  await store.updatePasskeySignCount("credential-1", 2);
  assert.equal((await store.getPasskeyByCredentialId("credential-1")).signCount, 2);

  await store.insertPasskeySigninAttempt({
    challengeHashHex: "challenge-hash",
    expiresAt: 100
  });
  assert.equal(
    (await store.getPasskeySigninAttempt("challenge-hash")).challengeHashHex,
    "challenge-hash"
  );

  await store.deletePasskeySigninAttempt("challenge-hash");
  assert.equal(await store.getPasskeySigninAttempt("challenge-hash"), null);
});

test("SQLiteStore can delete other auth sessions while keeping the current one", async () => {
  const store = new SQLiteStore(":memory:");

  await store.insertSession({
    id: "current-session",
    kind: "auth",
    userId: "user-1",
    action: null,
    authSessionId: null,
    secretHashHex: "abc",
    createdAt: 1,
    expiresAt: 100
  });
  await store.insertSession({
    id: "other-session",
    kind: "auth",
    userId: "user-1",
    action: null,
    authSessionId: null,
    secretHashHex: "abc",
    createdAt: 1,
    expiresAt: 100
  });

  await store.deleteOtherAuthSessionsByUserId("user-1", "current-session");

  assert.notEqual(await store.getSession("current-session"), null);
  assert.equal(await store.getSession("other-session"), null);
});

test("SQLiteStore can delete a user and related auth state", async () => {
  const store = new SQLiteStore(":memory:");
  const user = await store.createUser({
    email: "delete@example.com",
    passwordHash: "hash"
  });

  await store.insertSession({
    id: "auth-session",
    kind: "auth",
    userId: user.id,
    action: null,
    authSessionId: null,
    secretHashHex: "abc",
    createdAt: 1,
    expiresAt: 100
  });
  await store.insertSession({
    id: "verification-session",
    kind: "verification",
    userId: user.id,
    action: "account-delete",
    authSessionId: "auth-session",
    secretHashHex: "abc",
    createdAt: 1,
    expiresAt: 100
  });
  await store.insertEmailVerificationCode({
    sessionId: "verification-session",
    email: "new-delete@example.com",
    code: "12345678",
    expiresAt: 100
  });
  await store.insertPasswordResetCode({
    email: user.email,
    code: "87654321",
    expiresAt: 100
  });
  await store.setRateLimitBucket("password-signin", user.email, {
    tokens: 0,
    updatedAt: 1,
    expiresAt: 100
  });
  await store.setRateLimitBucket("password-verification", user.id, {
    tokens: 0,
    updatedAt: 1,
    expiresAt: 100
  });
  await store.insertPasskey({
    credentialId: "credential-1",
    userId: user.id,
    publicKeyDer: Buffer.from("public-key"),
    algorithm: -7,
    authenticatorId: null,
    name: "MacBook Touch ID",
    signCount: 1,
    createdAt: 10
  });

  await store.deleteUser(user.id);

  assert.equal(await store.getUserById(user.id), null);
  assert.equal(await store.getSession("auth-session"), null);
  assert.equal(await store.getSession("verification-session"), null);
  assert.equal(
    await store.getEmailVerificationCode("verification-session", "new-delete@example.com"),
    null
  );
  assert.equal(await store.getPasswordResetCode(user.email), null);
  assert.equal(await store.getRateLimitBucket("password-signin", user.email), null);
  assert.equal(await store.getRateLimitBucket("password-verification", user.id), null);
  assert.equal(await store.getPasskeyByCredentialId("credential-1"), null);
});

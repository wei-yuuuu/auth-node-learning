import assert from "node:assert/strict";
import test from "node:test";
import { hashPassword } from "../src/auth/password-service.js";
import { PasswordResetService } from "../src/auth/password-reset-service.js";
import { SQLiteStore } from "../src/store/sqlite-store.js";

test("PasswordResetService sends and consumes reset codes", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 0 });

  const store = new SQLiteStore(":memory:");
  const user = await store.createUser({
    email: "demo@example.com",
    passwordHash: await hashPassword("correct horse battery staple")
  });
  let sentCode = null;
  const passwordResets = new PasswordResetService(store, {
    async sendPasswordResetCode(_email, code) {
      sentCode = code;
    }
  });

  assert.equal((await passwordResets.createPasswordResetCode(user.email)).ok, true);
  assert.match(sentCode, /^\d{8}$/);
  assert.equal(
    (await passwordResets.verifyPasswordResetCode({
      email: user.email,
      code: sentCode
    })).ok,
    true
  );
  assert.equal(await store.getPasswordResetCode(user.email), null);
});

test("PasswordResetService expires reset codes", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 0 });

  const store = new SQLiteStore(":memory:");
  await store.createUser({
    email: "demo@example.com",
    passwordHash: "hash"
  });
  let sentCode = null;
  const passwordResets = new PasswordResetService(store, {
    async sendPasswordResetCode(_email, code) {
      sentCode = code;
    }
  });

  await passwordResets.createPasswordResetCode("demo@example.com");
  t.mock.timers.tick(15 * 60 * 1000 + 1);

  assert.deepEqual(
    await passwordResets.verifyPasswordResetCode({
      email: "demo@example.com",
      code: sentCode
    }),
    {
      ok: false,
      error: "Password reset code expired."
    }
  );
});

test("PasswordResetService rejects malformed reset codes", async () => {
  const store = new SQLiteStore(":memory:");
  const passwordResets = new PasswordResetService(store, {
    async sendPasswordResetCode() {}
  });

  assert.deepEqual(
    await passwordResets.verifyPasswordResetCode({
      email: "demo@example.com",
      code: "1234"
    }),
    {
      ok: false,
      error: "Code must be an 8-digit number."
    }
  );
});

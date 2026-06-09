import assert from "node:assert/strict";
import test from "node:test";
import { EmailCodeService } from "../src/auth/email-code-service.js";
import { SQLiteStore } from "../src/store/sqlite-store.js";

test("EmailCodeService expires codes with node:test mock timers", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 0 });

  const store = new SQLiteStore(":memory:");
  let sentCode = null;
  const emailSender = {
    async sendEmailVerificationCode(_email, code) {
      sentCode = code;
    }
  };
  const emailCodes = new EmailCodeService(store, emailSender);

  await emailCodes.createEmailVerificationCode({
    sessionId: "session-1",
    email: "demo@example.com"
  });

  assert.equal(
    (await emailCodes.verifyEmailCode({
      sessionId: "session-1",
      email: "demo@example.com",
      code: sentCode
    })).ok,
    true
  );

  await emailCodes.createEmailVerificationCode({
    sessionId: "session-2",
    email: "demo@example.com"
  });
  t.mock.timers.tick(15 * 60 * 1000 + 1);

  const result = await emailCodes.verifyEmailCode({
    sessionId: "session-2",
    email: "demo@example.com",
    code: sentCode
  });

  assert.deepEqual(result, {
    ok: false,
    error: "Verification code expired."
  });
});

test("AbortSignal.timeout follows mocked timers on Node versions that support it", async (t) => {
  t.mock.timers.enable({ now: 0 });

  const signal = AbortSignal.timeout(1000);

  assert.equal(signal.aborted, false);
  t.mock.timers.tick(1000);
  await Promise.resolve();

  if (!signal.aborted) {
    t.skip("AbortSignal.timeout mock timers require Node 24.16.0 or newer.");
    return;
  }

  assert.equal(signal.reason.name, "AbortError");
});

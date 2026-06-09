import assert from "node:assert/strict";
import test from "node:test";
import { hashPassword, validatePassword, verifyPassword } from "../src/auth/password-service.js";

test("validatePassword accepts long printable ASCII passwords", () => {
  assert.equal(validatePassword("correct horse battery staple"), null);
});

test("validatePassword rejects short, trimmed, or non-printable passwords", () => {
  assert.equal(validatePassword("short"), "Password must be at least 10 characters.");
  assert.equal(validatePassword(" leading-space"), "Password cannot start or end with a space.");
  assert.equal(validatePassword("trailing-space "), "Password cannot start or end with a space.");
  assert.equal(validatePassword("contains-tab\tvalue"), "Password must use printable ASCII characters.");
});

test("hashPassword and verifyPassword use native Node Argon2id", async () => {
  const passwordHash = await hashPassword("correct horse battery staple");

  assert.match(passwordHash, /^node-argon2id\$v=1\$m=19456,t=3,p=1,l=32\$/);
  assert.equal(await verifyPassword(passwordHash, "correct horse battery staple"), true);
  assert.equal(await verifyPassword(passwordHash, "wrong password value"), false);
});

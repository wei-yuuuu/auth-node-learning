import assert from "node:assert/strict";
import test from "node:test";
import {
  formatEmailSigninCode,
  generateEmailSigninCode,
  generateUnbiasedEightDigitCode,
  normalizeEmailSigninCode,
  validateEmailSigninCode,
  validateEightDigitCode
} from "../src/auth/random.js";

test("generateUnbiasedEightDigitCode returns an 8-digit numeric string", () => {
  for (let index = 0; index < 100; index += 1) {
    const code = generateUnbiasedEightDigitCode();

    assert.match(code, /^\d{8}$/);
  }
});

test("validateEightDigitCode accepts only 8 numeric characters", () => {
  assert.equal(validateEightDigitCode("12345678"), null);
  assert.equal(validateEightDigitCode(undefined), "Code is required.");
  assert.equal(validateEightDigitCode("1234567"), "Code must be an 8-digit number.");
  assert.equal(validateEightDigitCode("123456789"), "Code must be an 8-digit number.");
  assert.equal(validateEightDigitCode("1234abcd"), "Code must be an 8-digit number.");
});

test("generateEmailSigninCode returns 8 characters from the 32-character alphabet", () => {
  for (let index = 0; index < 100; index += 1) {
    const code = generateEmailSigninCode();

    assert.match(code, /^[A-HJ-NP-Z2-9]{8}$/);
    assert.equal(formatEmailSigninCode(code), `${code.slice(0, 4)}-${code.slice(4)}`);
  }
});

test("validateEmailSigninCode accepts the 40-bit code format", () => {
  assert.equal(validateEmailSigninCode("ABCD2345"), null);
  assert.equal(normalizeEmailSigninCode("ABCD-2345"), "ABCD2345");
  assert.equal(normalizeEmailSigninCode("abcd 2345"), "ABCD2345");
  assert.equal(validateEmailSigninCode(undefined), "Sign-in code is required.");
  assert.equal(
    validateEmailSigninCode("abcd2345"),
    "Sign-in code must use 8 uppercase letters or numbers."
  );
  assert.equal(
    validateEmailSigninCode("ABCD-234"),
    "Sign-in code must use 8 uppercase letters or numbers."
  );
});

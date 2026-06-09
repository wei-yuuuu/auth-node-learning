import assert from "node:assert/strict";
import test from "node:test";
import { generateUnbiasedEightDigitCode, validateEightDigitCode } from "../src/auth/random.js";

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

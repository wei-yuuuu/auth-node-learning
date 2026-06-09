import assert from "node:assert/strict";
import test from "node:test";
import { generateUnbiasedEightDigitCode } from "../src/auth/random.js";

test("generateUnbiasedEightDigitCode returns an 8-digit numeric string", () => {
  for (let index = 0; index < 100; index += 1) {
    const code = generateUnbiasedEightDigitCode();

    assert.match(code, /^\d{8}$/);
  }
});

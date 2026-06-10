import assert from "node:assert/strict";
import test from "node:test";
import { normalizeEmail, validateEmail } from "../src/store/email.js";

test("normalizeEmail trims email addresses without changing case", () => {
  assert.equal(normalizeEmail(" Demo.User+Test@Example.COM "), "Demo.User+Test@Example.COM");
});

test("validateEmail accepts the current educational email policy", () => {
  assert.equal(validateEmail("demo.user+tag_1@example-domain.com"), null);
});

test("validateEmail rejects invalid structure and length", () => {
  assert.equal(validateEmail(""), "Email address is required.");
  assert.equal(validateEmail("demo.example.com"), 'Email address must contain exactly one "@".');
  assert.equal(validateEmail("demo@@example.com"), 'Email address must contain exactly one "@".');
  assert.equal(validateEmail("@example.com"), "Email username and domain are required.");
  assert.equal(validateEmail("demo@"), "Email username and domain are required.");
  assert.equal(
    validateEmail(`${"a".repeat(90)}@example.com`),
    "Email address must be at most 100 characters."
  );
});

test("validateEmail rejects unsupported username and domain characters", () => {
  assert.equal(
    validateEmail("demo!user@example.com"),
    "Email username can only use lowercase letters, numbers, periods, plus signs, underscores, and hyphens."
  );
  assert.equal(
    validateEmail("Demo@example.com"),
    "Email username can only use lowercase letters, numbers, periods, plus signs, underscores, and hyphens."
  );
  assert.equal(
    validateEmail("demo@Example.com"),
    "Email domain can only use lowercase letters, numbers, hyphens, and periods."
  );
  assert.equal(validateEmail("demo@example"), 'Email domain must contain at least one ".".');
  assert.equal(
    validateEmail("demo@example!.com"),
    "Email domain can only use lowercase letters, numbers, hyphens, and periods."
  );
});

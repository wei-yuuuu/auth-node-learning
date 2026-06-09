import assert from "node:assert/strict";
import test from "node:test";
import { RateLimiter, TokenBucket } from "../src/auth/rate-limit.js";
import { SQLiteStore } from "../src/store/sqlite-store.js";

test("TokenBucket consumes capacity and refills over time", () => {
  let now = 0;
  const bucket = new TokenBucket({
    capacity: 2,
    refillTokens: 1,
    refillIntervalMs: 60_000,
    now: () => now
  });

  assert.equal(bucket.consume(), true);
  assert.equal(bucket.consume(), true);
  assert.equal(bucket.consume(), false);

  now = 60_000;

  assert.equal(bucket.consume(), true);
  assert.equal(bucket.consume(), false);
});

test("TokenBucket can be tested with node:test mock Date", (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 0 });

  const bucket = new TokenBucket({
    capacity: 1,
    refillTokens: 1,
    refillIntervalMs: 60_000
  });

  assert.equal(bucket.consume(), true);
  assert.equal(bucket.consume(), false);

  t.mock.timers.tick(60_000);

  assert.equal(bucket.consume(), true);
});

test("RateLimiter persists bucket state in SQLite", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 0 });

  const store = new SQLiteStore(":memory:");
  const options = {
    name: "test-limiter",
    capacity: 1,
    refillTokens: 1,
    refillIntervalMs: 60_000
  };

  const firstLimiter = new RateLimiter(options, store);

  assert.equal(await firstLimiter.consume("DEMO@example.com"), true);

  const secondLimiter = new RateLimiter(options, store);

  assert.equal(await secondLimiter.consume("demo@example.com"), false);

  t.mock.timers.tick(60_000);

  assert.equal(await secondLimiter.consume("demo@example.com"), true);
});

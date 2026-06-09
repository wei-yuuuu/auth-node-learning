export class TokenBucket {
  constructor({
    capacity,
    refillTokens,
    refillIntervalMs,
    now = () => Date.now(),
    tokens = capacity,
    updatedAt = now()
  }) {
    this.capacity = capacity;
    this.refillTokens = refillTokens;
    this.refillIntervalMs = refillIntervalMs;
    this.now = now;
    this.tokens = tokens;
    this.updatedAt = updatedAt;
  }

  consume(tokens = 1) {
    this.#refill();

    if (this.tokens < tokens) {
      return false;
    }

    this.tokens -= tokens;
    return true;
  }

  #refill() {
    const elapsed = this.now() - this.updatedAt;
    const intervals = Math.floor(elapsed / this.refillIntervalMs);

    if (intervals <= 0) {
      return;
    }

    this.tokens = Math.min(this.capacity, this.tokens + intervals * this.refillTokens);
    this.updatedAt += intervals * this.refillIntervalMs;
  }
}

export class RateLimiter {
  constructor(options, store) {
    this.options = options;
    this.store = store;
  }

  async consume(key) {
    const bucket = await this.#getBucket(key);
    const allowed = bucket.consume();

    await this.store.setRateLimitBucket(this.options.name, normalizeRateLimitKey(key), {
      tokens: bucket.tokens,
      updatedAt: bucket.updatedAt,
      expiresAt: this.#expiresAt(bucket)
    });

    return allowed;
  }

  async #getBucket(key) {
    const normalizedKey = normalizeRateLimitKey(key);
    const storedBucket = await this.store.getRateLimitBucket(this.options.name, normalizedKey);

    if (storedBucket) {
      return new TokenBucket({
        ...this.options,
        tokens: storedBucket.tokens,
        updatedAt: storedBucket.updatedAt
      });
    }

    return new TokenBucket(this.options);
  }

  #expiresAt(bucket) {
    const missingTokens = this.options.capacity - bucket.tokens;
    const intervalsUntilFull = Math.ceil(missingTokens / this.options.refillTokens);

    return bucket.updatedAt + Math.max(1, intervalsUntilFull) * this.options.refillIntervalMs;
  }
}

function normalizeRateLimitKey(key) {
  return String(key).toLowerCase();
}

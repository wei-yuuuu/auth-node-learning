import { generateUnbiasedEightDigitCode } from "./random.js";
import { RateLimiter } from "./rate-limit.js";

const PASSWORD_RESET_CODE_TTL_MS = 1000 * 60 * 15;

export class PasswordResetService {
  constructor(store, emailSender, { now = () => Date.now() } = {}) {
    this.store = store;
    this.emailSender = emailSender;
    this.now = now;
    this.requestLimiter = new RateLimiter({
      name: "password-reset-request",
      capacity: 3,
      refillTokens: 1,
      refillIntervalMs: 1000 * 60 * 10,
      now
    }, store);
    this.verifyLimiter = new RateLimiter({
      name: "password-reset-verify",
      capacity: 5,
      refillTokens: 1,
      refillIntervalMs: 1000 * 60,
      now
    }, store);
  }

  async createPasswordResetCode(email) {
    if (!(await this.requestLimiter.consume(email))) {
      return { ok: false, error: "Too many password reset requests. Try again later." };
    }

    const user = await this.store.getUserByEmail(email);

    if (!user) {
      return { ok: true };
    }

    const code = generateUnbiasedEightDigitCode();

    await this.store.insertPasswordResetCode({
      email: user.email,
      code,
      expiresAt: this.now() + PASSWORD_RESET_CODE_TTL_MS
    });
    await this.emailSender.sendPasswordResetCode(user.email, code);

    return { ok: true };
  }

  async verifyPasswordResetCode({ email, code }) {
    if (!(await this.verifyLimiter.consume(email))) {
      return { ok: false, error: "Too many password reset attempts. Try again later." };
    }

    const record = await this.store.getPasswordResetCode(email);

    if (!record || record.expiresAt <= this.now()) {
      return { ok: false, error: "Password reset code expired." };
    }

    if (record.code !== code) {
      return { ok: false, error: "Password reset code is incorrect." };
    }

    await this.store.deletePasswordResetCode(email);
    return { ok: true };
  }
}

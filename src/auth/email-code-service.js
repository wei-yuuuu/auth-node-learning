import { generateUnbiasedEightDigitCode } from "./random.js";
import { RateLimiter } from "./rate-limit.js";

const EMAIL_CODE_TTL_MS = 1000 * 60 * 15;

export class EmailCodeService {
  constructor(store, emailSender, { now = () => Date.now() } = {}) {
    this.store = store;
    this.emailSender = emailSender;
    this.now = now;
    this.verifyLimiter = new RateLimiter({
      name: "email-code",
      capacity: 5,
      refillTokens: 1,
      refillIntervalMs: 1000 * 60,
      now
    }, store);
  }

  async createEmailVerificationCode({ sessionId, email }) {
    const code = generateUnbiasedEightDigitCode();

    await this.store.insertEmailVerificationCode({
      sessionId,
      email,
      code,
      expiresAt: this.now() + EMAIL_CODE_TTL_MS
    });

    await this.emailSender.sendEmailVerificationCode(email, code);
  }

  async verifyEmailCode({ sessionId, email, code }) {
    if (!(await this.verifyLimiter.consume(email))) {
      return { ok: false, error: "Too many attempts. Try again later." };
    }

    const record = await this.store.getEmailVerificationCode(sessionId, email);

    if (!record || record.expiresAt <= this.now()) {
      return { ok: false, error: "Verification code expired." };
    }

    if (record.code !== code) {
      return { ok: false, error: "Verification code is incorrect." };
    }

    await this.store.deleteEmailVerificationCode(sessionId, email);
    return { ok: true };
  }
}

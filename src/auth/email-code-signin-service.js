import { hashArgon2id, verifyArgon2id } from "./argon2.js";
import {
  formatEmailSigninCode,
  generateEmailSigninCode,
  normalizeEmailSigninCode,
  validateEmailSigninCode
} from "./random.js";
import { RateLimiter } from "./rate-limit.js";

const HASH_FORMAT = "node-argon2id-email-code";
const ARGON2_PARAMETERS = {
  // The email-code chapter recommends 16 MiB, 3 iterations, and parallelism 1.
  memory: 16 * 1024,
  passes: 3,
  parallelism: 1,
  tagLength: 32
};

export class EmailCodeSigninService {
  constructor(store, sessions, emailSender, { now = () => Date.now() } = {}) {
    this.store = store;
    this.sessions = sessions;
    this.emailSender = emailSender;
    this.requestLimiter = new RateLimiter({
      name: "email-code-signin-request",
      capacity: 3,
      refillTokens: 1,
      refillIntervalMs: 1000 * 60 * 10,
      now
    }, store);
    this.verifyLimiter = new RateLimiter({
      name: "email-code-signin-verify",
      capacity: 5,
      refillTokens: 1,
      refillIntervalMs: 1000 * 60,
      now
    }, store);
  }

  async createSigninCode(user) {
    if (!(await this.requestLimiter.consume(user.email))) {
      return { ok: false, error: "Too many sign-in code requests. Try again later." };
    }

    const signInSession = await this.sessions.createEmailCodeSigninSession(user.id);
    const code = generateEmailSigninCode();
    const codeHash = await hashArgon2id(code, {
      format: HASH_FORMAT,
      parameters: ARGON2_PARAMETERS
    });

    await this.store.insertEmailCodeSigninCode({
      sessionId: signInSession.id,
      codeHash
    });
    await this.emailSender.sendEmailCodeSigninCode(user.email, formatEmailSigninCode(code));

    return { ok: true, token: signInSession.token };
  }

  async verifySigninCode(token, code) {
    const normalizedCode = normalizeEmailSigninCode(code);
    const codeError = validateEmailSigninCode(normalizedCode);

    if (codeError) {
      return { ok: false, error: codeError };
    }

    const signInSession = await this.sessions.validateEmailCodeSigninToken(token);

    if (!signInSession) {
      return { ok: false, error: "Sign-in code expired.", clearSession: true };
    }

    if (!(await this.verifyLimiter.consume(signInSession.userId))) {
      return { ok: false, error: "Too many sign-in code attempts. Try again later." };
    }

    const record = await this.store.getEmailCodeSigninCode(signInSession.id);

    if (!record || !(await verifyArgon2id(record.codeHash, normalizedCode, { format: HASH_FORMAT }))) {
      return { ok: false, error: "Sign-in code is incorrect." };
    }

    const authToken = await this.sessions.completeEmailCodeSigninSession(signInSession);

    if (!authToken) {
      return { ok: false, error: "Sign-in code expired.", clearSession: true };
    }

    return { ok: true, authToken, userId: signInSession.userId };
  }
}

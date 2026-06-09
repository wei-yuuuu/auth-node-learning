import { sha256, timingSafeEqualHex } from "./hash.js";
import { randomSessionId, randomSessionSecret } from "./random.js";

const AUTH_SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const AUTH_SESSION_REFRESH_INTERVAL_MS = 1000 * 60 * 60;
const ACTION_SESSION_TTL_MS = 1000 * 60 * 10;

export class SessionService {
  constructor(store, { now = () => Date.now() } = {}) {
    this.store = store;
    this.now = now;
  }

  async createAuthSession(userId) {
    const session = this.#buildSession({
      kind: "auth",
      userId,
      action: null,
      expiresInMs: AUTH_SESSION_TTL_MS
    });

    await this.store.insertSession(session.record);
    return session.token;
  }

  async createActionSession({ userId, action, authSessionId }) {
    const session = this.#buildSession({
      kind: "action",
      userId,
      action,
      authSessionId,
      expiresInMs: ACTION_SESSION_TTL_MS
    });

    await this.store.insertSession(session.record);
    return session.token;
  }

  async validateAuthToken(token) {
    const validation = await this.#validateToken(token, "auth");

    if (!validation) {
      return null;
    }

    const { session } = validation;
    const now = this.now();

    if (session.expiresAt - now <= AUTH_SESSION_TTL_MS - AUTH_SESSION_REFRESH_INTERVAL_MS) {
      session.expiresAt = now + AUTH_SESSION_TTL_MS;
      await this.store.updateSession(session);
    }

    return session;
  }

  async consumeActionToken(token, { action, userId, authSessionId }) {
    const validation = await this.#validateToken(token, "action");

    if (!validation) {
      return false;
    }

    const { session } = validation;
    const matchesPurpose =
      session.action === action &&
      session.userId === userId &&
      session.authSessionId === authSessionId;

    await this.store.deleteSession(session.id);
    return matchesPurpose;
  }

  async invalidateSession(sessionId) {
    await this.store.deleteSession(sessionId);
  }

  async invalidateAllAuthSessions(userId) {
    await this.store.deleteAuthSessionsByUserId(userId);
  }

  async #validateToken(token, expectedKind) {
    const parsed = parseSessionToken(token);

    if (!parsed) {
      return null;
    }

    const session = await this.store.getSession(parsed.id);

    if (!session || session.kind !== expectedKind || session.expiresAt <= this.now()) {
      return null;
    }

    const secretHashHex = sha256(parsed.secret).toString("hex");

    if (!timingSafeEqualHex(secretHashHex, session.secretHashHex)) {
      return null;
    }

    return { session };
  }

  #buildSession({ kind, userId, action, authSessionId = null, expiresInMs }) {
    const id = randomSessionId();
    const secret = randomSessionSecret();

    return {
      token: `${id}.${secret.toString("base64url")}`,
      record: {
        id,
        kind,
        userId,
        action,
        authSessionId,
        secretHashHex: sha256(secret).toString("hex"),
        createdAt: this.now(),
        expiresAt: this.now() + expiresInMs
      }
    };
  }
}

export function parseSessionToken(token) {
  if (typeof token !== "string") {
    return null;
  }

  const [id, encodedSecret, extra] = token.split(".");

  if (!id || !encodedSecret || extra !== undefined) {
    return null;
  }

  try {
    return {
      id,
      secret: Buffer.from(encodedSecret, "base64url")
    };
  } catch {
    return null;
  }
}

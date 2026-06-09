import { DatabaseSync } from "node:sqlite";
import { normalizeEmail } from "./email.js";

export class SQLiteStore {
  constructor(path = "auth-node.sqlite") {
    // `node:sqlite` is new in Node 24 and currently release-candidate status.
    // It keeps this learning app dependency-free while still using real storage.
    this.database = new DatabaseSync(path);
    this.database.exec("PRAGMA foreign_keys = ON");
    this.database.exec("PRAGMA journal_mode = WAL");
    this.#migrate();
    this.#prepareStatements();
  }

  async createUser({ email, passwordHash }) {
    const normalizedEmail = normalizeEmail(email);
    const now = Date.now();

    try {
      const result = this.insertUser.run({
        email: normalizedEmail,
        password_hash: passwordHash,
        email_verified: 0,
        created_at: now
      });

      return {
        id: String(result.lastInsertRowid),
        email: normalizedEmail,
        passwordHash,
        emailVerified: false,
        createdAt: now
      };
    } catch (error) {
      if (error.code === "ERR_SQLITE_ERROR") {
        throw new Error("Email address is already registered.");
      }

      throw error;
    }
  }

  async getUserByEmail(email) {
    return rowToUser(this.getUserByEmailStatement.get(normalizeEmail(email)));
  }

  async getUserById(userId) {
    return rowToUser(this.getUserByIdStatement.get(userId));
  }

  async markEmailVerified(userId) {
    this.markEmailVerifiedStatement.run(userId);
  }

  async insertSession(session) {
    this.insertSessionStatement.run(session);
  }

  async getSession(sessionId) {
    return rowToSession(this.getSessionStatement.get(sessionId));
  }

  async updateSession(session) {
    this.updateSessionStatement.run({
      id: session.id,
      expires_at: session.expiresAt
    });
  }

  async deleteSession(sessionId) {
    this.deleteSessionStatement.run(sessionId);
  }

  async deleteAuthSessionsByUserId(userId) {
    this.deleteAuthSessionsByUserIdStatement.run(userId);
  }

  async insertEmailVerificationCode(record) {
    this.insertEmailVerificationCodeStatement.run({
      session_id: record.sessionId,
      email: normalizeEmail(record.email),
      code: record.code,
      expires_at: record.expiresAt
    });
  }

  async getEmailVerificationCode(sessionId, email) {
    return rowToEmailVerificationCode(
      this.getEmailVerificationCodeStatement.get({
        session_id: sessionId,
        email: normalizeEmail(email)
      })
    );
  }

  async deleteEmailVerificationCode(sessionId, email) {
    this.deleteEmailVerificationCodeStatement.run({
      session_id: sessionId,
      email: normalizeEmail(email)
    });
  }

  async getRateLimitBucket(name, key) {
    return rowToRateLimitBucket(
      this.getRateLimitBucketStatement.get({
        name,
        key
      })
    );
  }

  async setRateLimitBucket(name, key, bucket) {
    this.setRateLimitBucketStatement.run({
      name,
      key,
      tokens: bucket.tokens,
      updated_at: bucket.updatedAt,
      expires_at: bucket.expiresAt
    });
  }

  async deleteExpiredRecords(now = Date.now()) {
    const sessions = this.deleteExpiredSessionsStatement.run(now).changes;
    const emailVerificationCodes = this.deleteExpiredEmailVerificationCodesStatement.run(now).changes;
    const rateLimitBuckets = this.deleteExpiredRateLimitBucketsStatement.run(now).changes;

    return {
      sessions,
      emailVerificationCodes,
      rateLimitBuckets
    };
  }

  #migrate() {
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email_verified INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        user_id TEXT NOT NULL,
        action TEXT,
        auth_session_id TEXT,
        secret_hash_hex TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS sessions_user_id_kind_idx
        ON sessions (user_id, kind);

      CREATE TABLE IF NOT EXISTS email_verification_codes (
        session_id TEXT NOT NULL,
        email TEXT NOT NULL,
        code TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (session_id, email)
      );

      CREATE TABLE IF NOT EXISTS rate_limit_buckets (
        name TEXT NOT NULL,
        key TEXT NOT NULL,
        tokens REAL NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (name, key)
      );

      CREATE INDEX IF NOT EXISTS rate_limit_buckets_expires_at_idx
        ON rate_limit_buckets (expires_at);
    `);
  }

  #prepareStatements() {
    this.insertUser = this.database.prepare(`
      INSERT INTO users (email, password_hash, email_verified, created_at)
      VALUES (:email, :password_hash, :email_verified, :created_at)
    `);
    this.getUserByEmailStatement = this.database.prepare("SELECT * FROM users WHERE email = ?");
    this.getUserByIdStatement = this.database.prepare("SELECT * FROM users WHERE id = ?");
    this.markEmailVerifiedStatement = this.database.prepare(
      "UPDATE users SET email_verified = 1 WHERE id = ?"
    );
    this.insertSessionStatement = this.database.prepare(`
      INSERT INTO sessions (
        id,
        kind,
        user_id,
        action,
        auth_session_id,
        secret_hash_hex,
        created_at,
        expires_at
      )
      VALUES (
        :id,
        :kind,
        :userId,
        :action,
        :authSessionId,
        :secretHashHex,
        :createdAt,
        :expiresAt
      )
    `);
    this.getSessionStatement = this.database.prepare("SELECT * FROM sessions WHERE id = ?");
    this.updateSessionStatement = this.database.prepare(
      "UPDATE sessions SET expires_at = :expires_at WHERE id = :id"
    );
    this.deleteSessionStatement = this.database.prepare("DELETE FROM sessions WHERE id = ?");
    this.deleteAuthSessionsByUserIdStatement = this.database.prepare(
      "DELETE FROM sessions WHERE user_id = ? AND kind = 'auth'"
    );
    this.insertEmailVerificationCodeStatement = this.database.prepare(`
      INSERT OR REPLACE INTO email_verification_codes (session_id, email, code, expires_at)
      VALUES (:session_id, :email, :code, :expires_at)
    `);
    this.getEmailVerificationCodeStatement = this.database.prepare(`
      SELECT * FROM email_verification_codes
      WHERE session_id = :session_id AND email = :email
    `);
    this.deleteEmailVerificationCodeStatement = this.database.prepare(`
      DELETE FROM email_verification_codes
      WHERE session_id = :session_id AND email = :email
    `);
    this.getRateLimitBucketStatement = this.database.prepare(`
      SELECT * FROM rate_limit_buckets
      WHERE name = :name AND key = :key
    `);
    this.setRateLimitBucketStatement = this.database.prepare(`
      INSERT INTO rate_limit_buckets (name, key, tokens, updated_at, expires_at)
      VALUES (:name, :key, :tokens, :updated_at, :expires_at)
      ON CONFLICT(name, key) DO UPDATE SET
        tokens = excluded.tokens,
        updated_at = excluded.updated_at,
        expires_at = excluded.expires_at
    `);
    this.deleteExpiredSessionsStatement = this.database.prepare(
      "DELETE FROM sessions WHERE expires_at <= ?"
    );
    this.deleteExpiredEmailVerificationCodesStatement = this.database.prepare(
      "DELETE FROM email_verification_codes WHERE expires_at <= ?"
    );
    this.deleteExpiredRateLimitBucketsStatement = this.database.prepare(
      "DELETE FROM rate_limit_buckets WHERE expires_at <= ?"
    );
  }
}

function rowToUser(row) {
  if (!row) {
    return null;
  }

  return {
    id: String(row.id),
    email: row.email,
    passwordHash: row.password_hash,
    emailVerified: row.email_verified === 1,
    createdAt: row.created_at
  };
}

function rowToSession(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    kind: row.kind,
    userId: row.user_id,
    action: row.action,
    authSessionId: row.auth_session_id,
    secretHashHex: row.secret_hash_hex,
    createdAt: row.created_at,
    expiresAt: row.expires_at
  };
}

function rowToEmailVerificationCode(row) {
  if (!row) {
    return null;
  }

  return {
    sessionId: row.session_id,
    email: row.email,
    code: row.code,
    expiresAt: row.expires_at
  };
}

function rowToRateLimitBucket(row) {
  if (!row) {
    return null;
  }

  return {
    tokens: row.tokens,
    updatedAt: row.updated_at,
    expiresAt: row.expires_at
  };
}

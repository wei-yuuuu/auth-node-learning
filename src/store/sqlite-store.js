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

  async updateUserEmail(userId, email) {
    try {
      this.updateUserEmailStatement.run({
        id: userId,
        email: normalizeEmail(email)
      });
    } catch (error) {
      if (error.code === "ERR_SQLITE_ERROR") {
        throw new Error("Email address is already registered.");
      }

      throw error;
    }
  }

  async updateUserPassword(userId, passwordHash) {
    this.updateUserPasswordStatement.run({
      id: userId,
      password_hash: passwordHash
    });
  }

  async deleteUser(userId) {
    const user = await this.getUserById(userId);

    if (!user) {
      return;
    }

    this.database.exec("BEGIN");

    try {
      this.deleteEmailVerificationCodesByUserStatement.run({
        user_id: userId,
        email: user.email
      });
      this.deletePasswordResetCodeStatement.run(user.email);
      this.deleteRateLimitBucketsForUserStatement.run({
        user_id: userId,
        email: user.email
      });
      this.deletePasskeysByUserIdStatement.run(userId);
      this.deleteSessionsByUserIdStatement.run(userId);
      this.deleteUserByIdStatement.run(userId);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
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

  async deleteOtherAuthSessionsByUserId(userId, sessionId) {
    this.deleteOtherAuthSessionsByUserIdStatement.run({
      user_id: userId,
      session_id: sessionId
    });
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

  async insertPasswordResetCode(record) {
    this.insertPasswordResetCodeStatement.run({
      email: normalizeEmail(record.email),
      code: record.code,
      expires_at: record.expiresAt
    });
  }

  async getPasswordResetCode(email) {
    return rowToPasswordResetCode(
      this.getPasswordResetCodeStatement.get(normalizeEmail(email))
    );
  }

  async deletePasswordResetCode(email) {
    this.deletePasswordResetCodeStatement.run(normalizeEmail(email));
  }

  async insertPasskey(record) {
    try {
      this.insertPasskeyStatement.run({
        credential_id: record.credentialId,
        user_id: record.userId,
        public_key_der: record.publicKeyDer,
        algorithm: record.algorithm,
        authenticator_id: record.authenticatorId,
        name: record.name,
        sign_count: record.signCount,
        created_at: record.createdAt
      });
    } catch (error) {
      if (error.code === "ERR_SQLITE_ERROR") {
        throw new Error("Passkey is already registered.");
      }

      throw error;
    }
  }

  async getPasskeyByCredentialId(credentialId) {
    return rowToPasskey(this.getPasskeyByCredentialIdStatement.get(credentialId));
  }

  async listPasskeysByUserId(userId) {
    return this.listPasskeysByUserIdStatement.all(userId).map(rowToPasskey);
  }

  async countPasskeysByUserId(userId) {
    const row = this.countPasskeysByUserIdStatement.get(userId);
    return row.count;
  }

  async updatePasskeySignCount(credentialId, signCount) {
    this.updatePasskeySignCountStatement.run({
      credential_id: credentialId,
      sign_count: signCount
    });
  }

  async deletePasskeyByCredentialId(userId, credentialId) {
    this.deletePasskeyByCredentialIdStatement.run({
      user_id: userId,
      credential_id: credentialId
    });
  }

  async insertPasskeySigninAttempt(record) {
    this.insertPasskeySigninAttemptStatement.run({
      challenge_hash_hex: record.challengeHashHex,
      expires_at: record.expiresAt
    });
  }

  async getPasskeySigninAttempt(challengeHashHex) {
    return rowToPasskeySigninAttempt(
      this.getPasskeySigninAttemptStatement.get(challengeHashHex)
    );
  }

  async deletePasskeySigninAttempt(challengeHashHex) {
    this.deletePasskeySigninAttemptStatement.run(challengeHashHex);
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
    const passwordResetCodes = this.deleteExpiredPasswordResetCodesStatement.run(now).changes;
    const rateLimitBuckets = this.deleteExpiredRateLimitBucketsStatement.run(now).changes;
    const passkeySigninAttempts = this.deleteExpiredPasskeySigninAttemptsStatement.run(now).changes;

    return {
      sessions,
      emailVerificationCodes,
      passwordResetCodes,
      rateLimitBuckets,
      passkeySigninAttempts
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

      CREATE TABLE IF NOT EXISTS password_reset_codes (
        email TEXT PRIMARY KEY,
        code TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS passkeys (
        credential_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        public_key_der BLOB NOT NULL,
        algorithm INTEGER NOT NULL,
        authenticator_id TEXT,
        name TEXT NOT NULL,
        sign_count INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS passkeys_user_id_idx
        ON passkeys (user_id);

      CREATE TABLE IF NOT EXISTS passkey_signin_attempts (
        challenge_hash_hex TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS passkey_signin_attempts_expires_at_idx
        ON passkey_signin_attempts (expires_at);

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
    this.updateUserEmailStatement = this.database.prepare(
      "UPDATE users SET email = :email, email_verified = 1 WHERE id = :id"
    );
    this.updateUserPasswordStatement = this.database.prepare(
      "UPDATE users SET password_hash = :password_hash WHERE id = :id"
    );
    this.deleteUserByIdStatement = this.database.prepare("DELETE FROM users WHERE id = ?");
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
    this.deleteSessionsByUserIdStatement = this.database.prepare(
      "DELETE FROM sessions WHERE user_id = ?"
    );
    this.deleteAuthSessionsByUserIdStatement = this.database.prepare(
      "DELETE FROM sessions WHERE user_id = ? AND kind = 'auth'"
    );
    this.deleteOtherAuthSessionsByUserIdStatement = this.database.prepare(`
      DELETE FROM sessions
      WHERE user_id = :user_id AND kind = 'auth' AND id != :session_id
    `);
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
    this.deleteEmailVerificationCodesByUserStatement = this.database.prepare(`
      DELETE FROM email_verification_codes
      WHERE email = :email
         OR session_id IN (SELECT id FROM sessions WHERE user_id = :user_id)
    `);
    this.insertPasswordResetCodeStatement = this.database.prepare(`
      INSERT OR REPLACE INTO password_reset_codes (email, code, expires_at)
      VALUES (:email, :code, :expires_at)
    `);
    this.getPasswordResetCodeStatement = this.database.prepare(
      "SELECT * FROM password_reset_codes WHERE email = ?"
    );
    this.deletePasswordResetCodeStatement = this.database.prepare(
      "DELETE FROM password_reset_codes WHERE email = ?"
    );
    this.insertPasskeyStatement = this.database.prepare(`
      INSERT INTO passkeys (
        credential_id,
        user_id,
        public_key_der,
        algorithm,
        authenticator_id,
        name,
        sign_count,
        created_at
      )
      VALUES (
        :credential_id,
        :user_id,
        :public_key_der,
        :algorithm,
        :authenticator_id,
        :name,
        :sign_count,
        :created_at
      )
    `);
    this.getPasskeyByCredentialIdStatement = this.database.prepare(
      "SELECT * FROM passkeys WHERE credential_id = ?"
    );
    this.listPasskeysByUserIdStatement = this.database.prepare(`
      SELECT * FROM passkeys
      WHERE user_id = ?
      ORDER BY created_at DESC
    `);
    this.countPasskeysByUserIdStatement = this.database.prepare(
      "SELECT count(*) AS count FROM passkeys WHERE user_id = ?"
    );
    this.updatePasskeySignCountStatement = this.database.prepare(`
      UPDATE passkeys
      SET sign_count = :sign_count
      WHERE credential_id = :credential_id
    `);
    this.deletePasskeyByCredentialIdStatement = this.database.prepare(`
      DELETE FROM passkeys
      WHERE user_id = :user_id AND credential_id = :credential_id
    `);
    this.deletePasskeysByUserIdStatement = this.database.prepare(
      "DELETE FROM passkeys WHERE user_id = ?"
    );
    this.insertPasskeySigninAttemptStatement = this.database.prepare(`
      INSERT OR REPLACE INTO passkey_signin_attempts (challenge_hash_hex, expires_at)
      VALUES (:challenge_hash_hex, :expires_at)
    `);
    this.getPasskeySigninAttemptStatement = this.database.prepare(
      "SELECT * FROM passkey_signin_attempts WHERE challenge_hash_hex = ?"
    );
    this.deletePasskeySigninAttemptStatement = this.database.prepare(
      "DELETE FROM passkey_signin_attempts WHERE challenge_hash_hex = ?"
    );
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
    this.deleteExpiredPasswordResetCodesStatement = this.database.prepare(
      "DELETE FROM password_reset_codes WHERE expires_at <= ?"
    );
    this.deleteExpiredRateLimitBucketsStatement = this.database.prepare(
      "DELETE FROM rate_limit_buckets WHERE expires_at <= ?"
    );
    this.deleteExpiredPasskeySigninAttemptsStatement = this.database.prepare(
      "DELETE FROM passkey_signin_attempts WHERE expires_at <= ?"
    );
    this.deleteRateLimitBucketsForUserStatement = this.database.prepare(
      "DELETE FROM rate_limit_buckets WHERE key = :email OR key = :user_id"
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

function rowToPasswordResetCode(row) {
  if (!row) {
    return null;
  }

  return {
    email: row.email,
    code: row.code,
    expiresAt: row.expires_at
  };
}

function rowToPasskey(row) {
  if (!row) {
    return null;
  }

  return {
    credentialId: row.credential_id,
    userId: String(row.user_id),
    publicKeyDer: Buffer.from(row.public_key_der),
    algorithm: row.algorithm,
    authenticatorId: row.authenticator_id,
    name: row.name,
    signCount: row.sign_count,
    createdAt: row.created_at
  };
}

function rowToPasskeySigninAttempt(row) {
  if (!row) {
    return null;
  }

  return {
    challengeHashHex: row.challenge_hash_hex,
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

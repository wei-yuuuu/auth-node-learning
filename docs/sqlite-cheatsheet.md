# SQLite Cheatsheet

Run commands from the project root:

```sh
cd "/Users/weichen/Documents/auth-node-learning"
```

Use `-header -column` to make output readable:

```sh
sqlite3 -header -column auth-node.sqlite "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name;"
```

Timestamps are stored as Unix milliseconds. Use:

```sql
datetime(column_name / 1000, 'unixepoch', 'localtime')
```

## users

User accounts and password hashes.

```sh
sqlite3 -header -column auth-node.sqlite "SELECT id, email, CASE email_verified WHEN 1 THEN 'yes' ELSE 'no' END AS verified, datetime(created_at / 1000, 'unixepoch', 'localtime') AS created_at FROM users ORDER BY id;"
```

Columns:

- `id`: Internal user ID.
- `email`: Trimmed email address that passed the account-identifier rules.
- `password_hash`: Encoded native Node Argon2id hash. Usually omit it from casual queries.
- `email_verified`: `1` means verified, `0` means not verified.
- `created_at`: Unix milliseconds.

## sessions

Server-side auth and verification sessions.

```sh
sqlite3 -header -column auth-node.sqlite "SELECT id, kind, user_id, action, auth_session_id, datetime(created_at / 1000, 'unixepoch', 'localtime') AS created_at, datetime(expires_at / 1000, 'unixepoch', 'localtime') AS expires_at FROM sessions ORDER BY expires_at DESC;"
```

Columns:

- `id`: Public session ID from the `id.secret` token.
- `kind`: `auth` for signed-in sessions, `verification` for short-lived identity verification sessions.
- `user_id`: Owner user ID.
- `action`: Purpose name for verification sessions, such as `password-update`, `email-update`, or `account-delete`.
- `auth_session_id`: Auth session that a verification session is tied to.
- `secret_hash_hex`: SHA-256 hash of the session secret. The raw secret is never stored.
- `created_at`: Unix milliseconds.
- `expires_at`: Unix milliseconds.

## email_verification_codes

Email verification codes for new accounts.

```sh
sqlite3 -header -column auth-node.sqlite "SELECT session_id, email, code, datetime(expires_at / 1000, 'unixepoch', 'localtime') AS expires_at FROM email_verification_codes ORDER BY expires_at DESC;"
```

Columns:

- `session_id`: Auth session the code is tied to.
- `email`: Email address being verified.
- `code`: 8-digit numeric code printed by the development email sender.
- `expires_at`: Unix milliseconds.

## password_reset_codes

Password reset codes for users who forgot their password.

```sh
sqlite3 -header -column auth-node.sqlite "SELECT email, code, datetime(expires_at / 1000, 'unixepoch', 'localtime') AS expires_at FROM password_reset_codes ORDER BY expires_at DESC;"
```

Columns:

- `email`: Account email address.
- `code`: 8-digit numeric reset code printed by the development email sender.
- `expires_at`: Unix milliseconds.

## rate_limit_buckets

Persistent token buckets for sign-in, email-code, and password-reset rate limits.

```sh
sqlite3 -header -column auth-node.sqlite "SELECT name, key, tokens, datetime(updated_at / 1000, 'unixepoch', 'localtime') AS updated_at, datetime(expires_at / 1000, 'unixepoch', 'localtime') AS expires_at FROM rate_limit_buckets ORDER BY name, key;"
```

Columns:

- `name`: Rate limiter name, such as `password-signin`, `password-verification`, `email-code`, `password-reset-request`, or `password-reset-verify`.
- `key`: Rate limit key, usually a validated email address or user ID.
- `tokens`: Remaining bucket tokens.
- `updated_at`: Unix milliseconds when the bucket was last refilled/consumed.
- `expires_at`: Unix milliseconds when the full bucket can be deleted.

## Useful Counts

Quick table counts:

```sh
sqlite3 -header -column auth-node.sqlite "SELECT 'users' AS table_name, count(*) AS rows FROM users UNION ALL SELECT 'sessions', count(*) FROM sessions UNION ALL SELECT 'email_verification_codes', count(*) FROM email_verification_codes UNION ALL SELECT 'password_reset_codes', count(*) FROM password_reset_codes UNION ALL SELECT 'rate_limit_buckets', count(*) FROM rate_limit_buckets;"
```

Expired rows that cleanup can delete:

```sh
sqlite3 -header -column auth-node.sqlite "SELECT 'sessions' AS table_name, count(*) AS expired FROM sessions WHERE expires_at <= unixepoch('subsec') * 1000 UNION ALL SELECT 'email_verification_codes', count(*) FROM email_verification_codes WHERE expires_at <= unixepoch('subsec') * 1000 UNION ALL SELECT 'password_reset_codes', count(*) FROM password_reset_codes WHERE expires_at <= unixepoch('subsec') * 1000 UNION ALL SELECT 'rate_limit_buckets', count(*) FROM rate_limit_buckets WHERE expires_at <= unixepoch('subsec') * 1000;"
```

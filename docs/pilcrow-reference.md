# Pilcrow Reference Mapping

Source: [Pilcrow's auth book](https://auth.pilcrowonpaper.com/).

## Current Scope

Current position: Chapter 3 is complete. Chapter 1 auth foundations are implemented, Chapter 2 persists auth state in SQLite, and Chapter 3 adds password maintenance.

### Sessions

- Reference: [Sessions](https://auth.pilcrowonpaper.com/sessions), especially the paragraphs that recommend storing a server-side session record, issuing a client token, and generating both a session ID and a session secret.
- Implemented in: `src/auth/session-service.js` and `src/store/sqlite-store.js`.
- Code choices:
  - Session tokens are `id.secret`, where the ID identifies the session and the secret proves possession.
  - Session secrets are generated from 32 cryptographically secure random bytes.
  - Only the SHA-256 hash of the secret is stored, using Node 24's `crypto.hash()` helper.
  - Verification uses constant-time comparison.

### Auth Sessions

- Reference: [Auth sessions](https://auth.pilcrowonpaper.com/auth-sessions), especially the recommendation to refresh expiration periodically instead of on every request, invalidate server-side sessions on sign-out, support sign-out of all devices, and use action-specific sessions for identity verification.
- Implemented in: `src/auth/session-service.js` and `src/server.js`.
- Code choices:
  - Auth sessions use rolling expiration.
  - Expiration is refreshed only after the configured refresh interval.
  - Sign-out deletes the server-side session.
  - Sign-out-all deletes all sessions for the user.
  - `createVerificationSession()` creates single-purpose verification sessions for sensitive actions.
  - Password update consumes a verification session that is tied to the current auth session.

### Passwords

- Reference: [Passwords](https://auth.pilcrowonpaper.com/passwords), especially the paragraphs recommending printable ASCII constraints, 8 or 10 character minimum length, no extra complexity requirements, Argon2id with at least 16 MiB memory, 3 iterations, 1 degree of parallelism, strict rate limiting, and avoiding account lockouts or strict IP-based rate limits.
- Implemented in: `src/auth/password-service.js`, `src/auth/rate-limit.js`, and `src/server.js`.
- Code choices:
  - Passwords must be printable ASCII and cannot start or end with a space.
  - Passwords must be 10 to 100 characters.
  - There are no composition rules like uppercase, number, or symbol requirements.
  - Password hashes use Node 24.16.0 native `node:crypto` Argon2id with 19 MiB memory, 3 iterations, and parallelism 1.
  - The stored hash encodes the Argon2 parameters, salt, and derived key because Node's native Argon2 API returns a raw derived key.
  - Hashing is guarded by a small async semaphore so concurrent work is queued.
  - Sign-in attempts are limited with a SQLite-backed token bucket keyed by email.
  - The server returns explicit account/password errors for this educational app.

### Email Addresses

- Reference: [Email addresses](https://auth.pilcrowonpaper.com/email-addresses), especially the listed validation rules for maximum length, exactly one `@`, non-empty username and domain, restricted username/domain characters, and requiring at least one period in the domain.
- Implemented in: `src/store/email.js` and `src/server.js`.
- Code choices:
  - Email input is trimmed and lowercased before validation and storage.
  - Email addresses are limited to 100 characters.
  - The username allows lowercase letters, numbers, `.`, `+`, `_`, and `-`.
  - The domain allows lowercase letters, numbers, `-`, and `.`.
  - The domain must include at least one period.

### Email Address Verification Codes

- Reference: [Email address verification codes](https://auth.pilcrowonpaper.com/email-address-verification-codes), especially the preference for codes over links, tying the code to one session and one email address, using an 8-digit numeric code, rate limiting per email address, keeping the code valid for less than an hour, and generating the code without modulo bias.
- Implemented in: `src/auth/email-code-service.js` and `src/auth/random.js`.
- Code choices:
  - Verification uses an 8-digit numeric code.
  - Submitted codes must also be exactly 8 numeric characters.
  - Codes are bound to the auth session ID and email address.
  - Codes expire after 15 minutes.
  - Verification attempts are rate-limited per email address with SQLite-backed bucket state.
  - Code generation discards 5 bits from 4 random bytes and retries out-of-range values.

### Persistent Storage And Cleanup

- Reference: The article recommends server-side session storage and strict rate limiting; this project keeps those states persistent for local restarts.
- Implemented in: `src/store/sqlite-store.js`, `src/auth/rate-limit.js`, and `src/server.js`.
- Code choices:
  - Users, sessions, email verification codes, password reset codes, and rate-limit buckets are stored in SQLite.
  - The server deletes expired records at startup and on a periodic interval.
  - Tests use `:memory:` databases so persistence behavior is covered without writing files.

### Password Maintenance

- Reference: [Auth sessions](https://auth.pilcrowonpaper.com/auth-sessions), especially the recommendation to use action-specific sessions for actions requiring identity verification such as updating a password, and the note that signing out of all devices after password changes should be offered but not mandatory.
- Implemented in: `src/server.js`, `src/auth/session-service.js`, `src/auth/password-reset-service.js`, and `src/store/sqlite-store.js`.
- Code choices:
  - Updating a password requires the current password first.
  - Successful password verification creates a short-lived, single-use verification session for `password-update`.
  - Password reset uses an 8-digit email code and a 15-minute expiration.
  - Password reset request and verification attempts are rate-limited with SQLite-backed buckets.
  - Password update can sign out other devices while keeping the current session.
  - Password reset can sign out all devices.

### Node.js 24 APIs

- Reference: The project uses Node.js 24.16.0 APIs where they make the auth concepts clearer.
- Implemented in:
  - `src/store/sqlite-store.js` uses `node:sqlite` for users, sessions, email verification codes, password reset codes, rate-limit buckets, and cleanup.
  - `src/auth/hash.js` uses `crypto.hash()` for SHA-256 session-secret hashing.
  - `test/*.test.js` uses the built-in `node:test` runner.
  - `test/rate-limit.test.js`, `test/session.test.js`, and `test/email-code-service.test.js` use mock timers for time-dependent auth behavior.
  - `package.json` includes `npm run test:random` for Node 24.16 test-order randomization with a fixed seed.
  - `src/auth/password-service.js` uses native `node:crypto` Argon2id.

### Cookies

- Reference: The article's session guidance relies on browser cookies carrying the session token.
- Implemented in: `src/http/cookies.js` and `src/server.js`.
- Code choices:
  - Node's `node:http` server exposes cookies as request and response headers, so this project keeps a small native helper for parsing `Cookie` and writing `Set-Cookie`.
  - Auth cookies are `HttpOnly`, `SameSite=Lax`, path-scoped to `/`, and marked `Secure` in production.
  - Browser JavaScript should never read the auth session token directly.

## Example Repository Notes

- Reference: [basic-example.auth.pilcrowonpaper.com source](https://github.com/pilcrowonpaper/basic-example.auth.pilcrowonpaper.com), whose README lists email verification, password authentication, password update/reset, account deletion, and basic rate limiting.
- Chapter 1 covers the common foundation: password auth, email verification, sessions, and rate limiting.
- Chapter 2 is complete with SQLite persistence and cleanup.
- Chapter 3 is complete with password update and password reset.
- Later chapters can add email address update, browser hardening, and account deletion.

## Passwordless Example Notes

- Reference: [passwordless-example.auth.pilcrowonpaper.com source](https://github.com/pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com), whose README describes email code sign-in, passkey authentication, passkey registration/deletion, email address update, account deletion, SQLite storage, basic rate limiting, and local development emails printed to stdout.
- Current status: not implemented in this Node.js project yet.
- Planned chapter: Chapter 7, Passwordless and Passkeys.
- Integration approach:
  - Keep the existing `sessions` table and auth-session validation as the shared signed-in state.
  - Add passwordless-specific tables instead of replacing password auth tables.
  - Reuse SQLite-backed `rate_limit_buckets` for email-code sign-in and passkey challenge attempts.
  - Reuse existing cleanup infrastructure for expired passwordless sessions and WebAuthn challenges.
  - Reuse verification sessions before passkey registration and deletion.
  - Restore a small browser HTML UI because WebAuthn passkeys require browser APIs.
- Planned tables based on the reference schema:
  - `passkeys` for user passkey records.
  - `passkey_signin_attempts` for short-lived WebAuthn sign-in challenges.
  - `email_code_signin_sessions` for email-code sign-in.
  - `passkey_registration_sessions` for signed-in passkey creation.
  - `passkey_deletion_sessions` for signed-in passkey deletion.
- Planned WebAuthn checks based on the reference implementation:
  - Require user presence and user verification.
  - Validate relying party ID hash.
  - Validate browser origin.
  - Reject cross-origin client data.
  - Verify the stored challenge.
  - Check backup state and attested credential state according to registration versus authentication flow.
- Planned browser UI:
  - Minimal HTML, CSS, and browser JavaScript.
  - Password/email-code pages can call existing JSON actions.
  - Passkey registration will call `navigator.credentials.create()`.
  - Passkey sign-in and verification will call `navigator.credentials.get()`.
  - Auth session cookies stay `HttpOnly`.

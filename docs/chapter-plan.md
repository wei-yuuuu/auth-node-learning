# Chapter Plan

This project can grow in chapters so each auth concept stays teachable and reviewable.

## [x] Chapter 1: Password Auth Foundation

- Password sign-up and sign-in.
- Native Node.js `node:crypto` Argon2id hashing with queued concurrency.
- SQLite-backed persistence with `node:sqlite`.
- Server-side auth sessions.
- Email verification codes.
- Token bucket rate limits.
- Current-device and all-device sign-out.
- Verification session primitive for sensitive actions.

## [x] Chapter 2: Persistent Storage

- Replaced the teaching-only in-memory store with `node:sqlite`.
- Added SQLite tables for users, sessions, and email verification codes.
- Added SQLite persistence for rate-limit bucket state.
- Added cleanup for expired sessions, email verification codes, and rate-limit buckets.
- Kept tests on disposable `:memory:` databases.

## [x] Chapter 3: Password Maintenance

- Password update.
- Password reset via email code.
- Identity verification before sensitive actions.
- Optional "sign out of all devices" prompt after password change.
- `/password/verify` verifies the current password and creates a single-use verification session.
- `/password/update` consumes that verification session before changing the password.
- `/password-reset/start` sends an 8-digit reset code to the account email.
- `/password-reset/finish` consumes that reset code before changing the password.
- Password update can sign out other devices.
- Password reset can sign out all devices.
- Expired password reset codes are deleted by the existing cleanup path.

## [x] Chapter 4: Email Address Updates

- Start a verification session for the email update action.
- Verify the new email address with a code bound to that session and email.
- Rate-limit by target email address.
- `/email-update/verify` verifies the current password and creates a single-use verification session.
- `/email-update/start` sends an 8-digit code to the new email address.
- `/email-update/finish` consumes the code and verification session before updating the account email.
- Updated email addresses are marked verified because the code was sent to the new address.

## [x] Chapter 5: Browser Hardening

- Restore a small browser HTML UI for the existing password and email-code flows.
- CSRF protection for cookie-authenticated unsafe methods.
- Secure cookie behavior for production.
- Origin and content-type checks.
- Unsafe methods must use `Content-Type: application/json`.
- JSON content-type parsing uses the MIME type instead of substring matching.
- Browser unsafe requests must send `Sec-Fetch-Site: same-origin`.
- Non-browser clients can use an exact same-origin `Origin` header fallback.
- Unsafe requests must include a double-submit anti-CSRF token cookie/header pair.
- Invalid JSON request bodies return `400` instead of a generic server error.
- Cookies remain `HttpOnly`, `SameSite=Lax`, path-scoped to `/`, and `Secure` in production.

## [x] Chapter 6: Account Deletion

- Identity verification before deletion.
- Server-side session invalidation.
- Background cleanup behavior.
- `/account/delete/verify` verifies the current password and creates a single-use verification session.
- `/account/delete` requires typing the current account email, then consumes that verification session before deleting the account.
- Account deletion clears user-owned auth sessions, verification sessions, email codes, password reset codes, and related rate-limit buckets.

## [ ] Chapter 7: Passwordless and Passkeys

Reference: [pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com](https://github.com/pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com).

Goals:

- Add email code sign-in as a passwordless sign-in path.
- Add passkey registration for signed-in users after identity verification.
- Add passkey sign-in using stored WebAuthn credential IDs and public keys.
- Add passkey deletion behind identity verification.
- Add browser HTML pages for registration, sign-in, account management, passkey registration, and passkey deletion.
- Keep passkey flows integrated with existing server-side auth sessions.
- Reuse SQLite-backed rate limits for email-code sign-in and passkey attempts.
- Reuse cleanup infrastructure for expired WebAuthn challenges and passwordless sessions.

Storage plan:

- `passkeys`: user-owned credential records with WebAuthn credential ID, authenticator ID, COSE public key, display name, and creation time.
- `passkey_signin_attempts`: short-lived WebAuthn challenges for unauthenticated sign-in attempts.
- `email_code_signin_sessions`: short-lived email-code sign-in state bound to a user and secret.
- `passkey_registration_sessions`: signed-in registration state bound to an auth session and identity verification.
- `passkey_deletion_sessions`: signed-in deletion state bound to an auth session, passkey ID, and identity verification.
- Existing `sessions`, `rate_limit_buckets`, and cleanup paths stay shared.

WebAuthn validation plan:

- Require user presence and user verification.
- Verify relying party ID hash and browser origin.
- Reject cross-origin client data.
- Verify the stored challenge.
- Store passkey public keys and credential IDs as SQLite BLOB values.
- Reject invalid backup state and unexpected attested credential state depending on registration versus authentication.

Browser UI plan:

- Use minimal HTML, CSS, and browser JavaScript.
- Call server JSON actions with `fetch()`.
- Use `navigator.credentials.create()` for passkey registration.
- Use `navigator.credentials.get()` for passkey sign-in and identity verification.
- Keep cookies `HttpOnly`; browser JavaScript should not read auth session tokens.

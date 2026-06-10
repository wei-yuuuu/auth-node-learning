# Chapter Plan

This project can grow in chapters so each auth concept stays teachable and reviewable.

Current position: Chapter 4 is complete. Chapter 5 is next.

## Chapter 1: Password Auth Foundation

Status: implemented.

- Password sign-up and sign-in.
- Native Node.js `node:crypto` Argon2id hashing with queued concurrency.
- SQLite-backed persistence with `node:sqlite`.
- Server-side auth sessions.
- Email verification codes.
- Token bucket rate limits.
- Current-device and all-device sign-out.
- Verification session primitive for sensitive actions.

## Chapter 2: Persistent Storage

Status: implemented.

Implemented:

- Replaced the teaching-only in-memory store with `node:sqlite`.
- Added SQLite tables for users, sessions, and email verification codes.
- Added SQLite persistence for rate-limit bucket state.
- Added cleanup for expired sessions, email verification codes, and rate-limit buckets.
- Kept tests on disposable `:memory:` databases.

## Chapter 3: Password Maintenance

Status: implemented.

- Password update.
- Password reset via email code.
- Identity verification before sensitive actions.
- Optional "sign out of all devices" prompt after password change.

Implemented:

- `/password/verify` verifies the current password and creates a single-use verification session.
- `/password/update` consumes that verification session before changing the password.
- `/password-reset/start` sends an 8-digit reset code to the account email.
- `/password-reset/finish` consumes that reset code before changing the password.
- Password update can sign out other devices.
- Password reset can sign out all devices.
- Expired password reset codes are deleted by the existing cleanup path.

## Chapter 4: Email Address Updates

Status: implemented.

- Start a verification session for the email update action.
- Verify the new email address with a code bound to that session and email.
- Rate-limit by target email address.

Implemented:

- `/email-update/verify` verifies the current password and creates a single-use verification session.
- `/email-update/start` sends an 8-digit code to the new email address.
- `/email-update/finish` consumes the code and verification session before updating the account email.
- Updated email addresses are marked verified because the code was sent to the new address.

## Chapter 5: Browser Hardening

Status: not started.

- Restore a small browser HTML UI for the existing password and email-code flows.
- CSRF protection for cookie-authenticated unsafe methods.
- Secure cookie behavior for production.
- Origin and content-type checks.

## Chapter 6: Account Deletion

Status: not started.

- Identity verification before deletion.
- Server-side session invalidation.
- Background cleanup behavior.

## Chapter 7: Passwordless and Passkeys

Status: not started.

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

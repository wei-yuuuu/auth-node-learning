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

## [x] Chapter 7: Passwordless and Passkeys

Reference: [pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com](https://github.com/pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com).

Implemented:

- Add passkey registration for signed-in users after identity verification.
- Add passkey sign-in using stored WebAuthn credential IDs and public keys.
- Add passkey deletion behind identity verification.
- Add browser HTML pages for registration, sign-in, account management, passkey registration, and passkey deletion.
- Keep passkey flows integrated with existing server-side auth sessions.
- Reuse cleanup infrastructure for expired WebAuthn challenges.
- Support browser passkey autofill with conditional mediation when available.

Storage:

- `passkeys`: user-owned credential records with WebAuthn credential ID, authenticator ID, SubjectPublicKeyInfo public key bytes, signature algorithm, display name, signature counter, and creation time.
- `passkey_signin_attempts`: short-lived WebAuthn challenges for unauthenticated sign-in attempts.
- Existing `sessions` stores the short-lived `passkey-manage` verification session for passkey registration and deletion.
- Existing cleanup paths delete expired passkey sign-in attempts.

WebAuthn validation:

- Require user presence and user verification.
- Verify relying party ID hash and browser origin.
- Reject cross-origin client data.
- Verify the stored challenge.
- Validate ES256 P-256, RS256 2048-bit-plus RSA exponent 65537, and EdDSA Ed25519 public keys.
- Use `getPublicKey()` and `getPublicKeyAlgorithm()` so the server validates DER SubjectPublicKeyInfo bytes without parsing COSE key maps.
- Store passkey public keys as SQLite BLOB values and credential IDs as base64url text.
- Reject invalid backup state and unexpected attested credential state depending on registration versus authentication.

Browser UI:

- Use minimal HTML, CSS, and browser JavaScript.
- Call server JSON actions with `fetch()`.
- Use `navigator.credentials.create()` for passkey registration.
- Use `navigator.credentials.get()` for passkey sign-in.
- Keep cookies `HttpOnly`; browser JavaScript should not read auth session tokens.

## [ ] Chapter 8: Email Code Sign-In

- Add email code sign-in as another passwordless path.
- Create a short-lived sign-in session for each email-code attempt.
- Generate an 8-character code with at least 40 bits of entropy.
- Hash the email sign-in code with Argon2id or bcrypt before storing it.
- Rate-limit verification at 1 attempt per minute per user with a small burst capacity.

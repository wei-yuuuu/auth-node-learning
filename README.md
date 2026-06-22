# Auth Node Learning

This repository is a chapter-by-chapter Node.js learning implementation inspired by [Pilcrow's auth book](https://auth.pilcrowonpaper.com/) and example repositories.

## Implemented So Far

- Password sign-up and sign-in with Argon2id.
- Email address validation based on the article's simple allowed-character rules.
- Native Node.js `node:crypto` Argon2id hashing for learning-friendly salt and parameter handling.
- SQLite-backed users, sessions, and email verification codes with `node:sqlite`.
- SQLite-backed rate-limit bucket state.
- Expired session, email-code, and rate-limit cleanup.
- SHA-256 session-secret hashing with `crypto.hash()`.
- Server-side auth sessions with an ID plus a secret.
- SHA-256 hashed session secrets and constant-time verification.
- Rolling auth session expiration with periodic refresh.
- Email address verification via an 8-digit numeric code.
- Token bucket rate limits for password and email-code attempts.
- Current-device and all-device sign-out.
- Verification sessions as a reusable primitive for sensitive actions.
- Password update after short-lived identity verification.
- Password reset with an email code.
- Passwordless email code sign-in with an 8-character, 40-bit code hashed by Argon2id.
- Optional sign-out of other devices after password update.
- Optional sign-out of all devices after password reset.
- Email address update after identity verification and an email code sent to the new address.
- Browser hardening for unsafe JSON requests with strict content-type and same-origin checks.
- Account deletion after identity verification with related auth state cleanup.
- Passkey registration, passkey sign-in, and passkey deletion with browser WebAuthn APIs.
- Built-in `node:test` coverage for password/code hashing, sessions, rate limits, email-code TTL, WebAuthn validation, SQLite persistence, and random-code formatting.

The API uses a local SQLite database by default while keeping the auth services small enough to inspect.

The current code includes a small browser HTML UI for sign-up, password/email-code/passkey sign-in, email verification, passkey registration/deletion, email update, account deletion, and session controls.

## Requirements

- Node.js 24.16.0 or newer.
- npm for running scripts.

There are no runtime npm dependencies.

Run the server:

```sh
npm start
```

The server listens on `http://localhost:3000` by default and stores local data in `auth-node.sqlite`.

Use an in-memory database for a disposable run:

```sh
AUTH_DB_PATH=:memory: npm start
```

Open the browser UI:

```text
http://localhost:3000
```

Run tests:

```sh
npm test
```

Run tests with Node 24.16 test-order randomization:

```sh
npm run test:random
```

## Node 24 Notes

This project uses the native `node:crypto` Argon2 API added in Node 24. The API is currently a release candidate, which makes it useful for learning the salt, parameter, and derived-key pieces directly. A production service may still prefer a mature password-hashing package until the native API becomes stable.

The project also uses `node:sqlite`, which is currently a release candidate in Node 24. If Node prints an SQLite experimental warning, that is expected.

Passkey signature verification uses Node's built-in `crypto.verify()` with WebAuthn public keys stored as DER SubjectPublicKeyInfo bytes.

The test suite uses `node:test` mock timers for rate-limit refill, rolling session expiration, email-code TTL, and `AbortSignal.timeout()`.

## Try It

The browser automatically sends `Sec-Fetch-Site` for same-origin requests. The curl examples include an `Origin` header because Chapter 5 rejects unsafe requests that do not prove they came from the same origin.

The browser UI also sends an anti-CSRF token on every unsafe JSON request. For curl, first save the CSRF cookie and copy it into a shell variable:

```sh
curl -s -c /tmp/auth-node-cookies.txt http://localhost:3000/ >/dev/null
CSRF_TOKEN=$(awk '$6 == "csrf_token" { print $7 }' /tmp/auth-node-cookies.txt)
```

```sh
curl -i -X POST http://localhost:3000/signup \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"email":"demo@example.com","password":"correct horse battery staple"}'
```

The verification code is printed to stdout by the development email sender.

```sh
curl -i -X POST http://localhost:3000/verify-email \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"code":"12345678"}'
```

Check the current session with the cookie returned by sign-up or sign-in:

```sh
curl -i http://localhost:3000/me \
  -b /tmp/auth-node-cookies.txt
```

Start passwordless email code sign-in. The development sender prints an 8-character code as `ABCD-EFGH`; the browser and API normalize spaces/hyphens, so `ABCD-EFGH` and `ABCDEFGH` both work.

```sh
curl -i -X POST http://localhost:3000/email-code-signin/start \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"email":"demo@example.com"}'
```

Verify the code. The `email_code_signin_session` cookie binds the code to this browser/device and is replaced by an `auth_session` cookie on success.

```sh
curl -i -X POST http://localhost:3000/email-code-signin/verify \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"code":"ABCDEFGH"}'
```

Verify identity before updating the password:

The browser UI presents this as one "Change password" form. Internally, it first verifies the current password and then consumes the short-lived verification session to update the password.

```sh
curl -i -X POST http://localhost:3000/password/verify \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"password":"correct horse battery staple"}'
```

Update the password with the returned `password_update_session` cookie:

```sh
curl -i -X POST http://localhost:3000/password/update \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"password":"new correct horse battery staple","signOutOtherDevices":true}'
```

Start a password reset:

```sh
curl -i -X POST http://localhost:3000/password-reset/start \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"email":"demo@example.com"}'
```

Finish a password reset with the code printed to stdout:

```sh
curl -i -X POST http://localhost:3000/password-reset/finish \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"email":"demo@example.com","code":"12345678","password":"new correct horse battery staple","signOutAllDevices":true}'
```

Verify identity before updating the email address:

```sh
curl -i -X POST http://localhost:3000/email-update/verify \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"password":"correct horse battery staple"}'
```

Send a verification code to the new email address:

```sh
curl -i -X POST http://localhost:3000/email-update/start \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"email":"new-demo@example.com"}'
```

Finish the email update with the code printed to stdout:

```sh
curl -i -X POST http://localhost:3000/email-update/finish \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"email":"new-demo@example.com","code":"12345678"}'
```

Verify identity before deleting the account:

```sh
curl -i -X POST http://localhost:3000/account/delete/verify \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"password":"correct horse battery staple"}'
```

Delete the account:

```sh
curl -i -X POST http://localhost:3000/account/delete \
  -b /tmp/auth-node-cookies.txt \
  -c /tmp/auth-node-cookies.txt \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:3000' \
  -H "x-csrf-token: $CSRF_TOKEN" \
  -d '{"confirmationEmail":"demo@example.com"}'
```

Passkeys require browser WebAuthn APIs, so the normal way to try them is through the browser UI:

```text
http://localhost:3000
```

The flow is:

- Sign in with a password.
- Verify identity in the "Passkeys" section.
- Register a passkey with `navigator.credentials.create()`.
- Sign out.
- Sign back in with the "Sign in with passkey" button or browser passkey autofill.
- Verify identity again before deleting a passkey.

## References

See [docs/pilcrow-reference.md](docs/pilcrow-reference.md) for the article sections mapped to the current implementation.

See [docs/chapter-plan.md](docs/chapter-plan.md) for the suggested chapter order toward the full ideal implementation.

See [docs/sqlite-cheatsheet.md](docs/sqlite-cheatsheet.md) for copy-paste SQLite queries for each table.

## Passwordless Reference

- [pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com](https://github.com/pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com)

Implemented scope:

- Passkey registration.
- Passkey sign-in.
- Passkey deletion behind identity verification.
- Email code sign-in with session-bound, Argon2id-hashed codes.
- WebAuthn challenge storage and cleanup.
- SQLite tables for passkeys, WebAuthn attempts, and email code sign-in codes.
- Browser HTML pages that call the WebAuthn APIs and existing JSON actions.

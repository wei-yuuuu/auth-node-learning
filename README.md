# Auth Node Learning

This repository is a chapter-by-chapter Node.js learning implementation inspired by Pilcrow's auth book and example repositories.

Current status: Chapter 2 is complete. Chapter 3 is the next planned chapter.

## Implemented So Far

- Password sign-up and sign-in with Argon2id.
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
- Action-specific identity verification sessions as a reusable primitive.
- Built-in `node:test` coverage for password hashing, sessions, rate limits, email-code TTL, SQLite persistence, and random-code formatting.

The API uses a local SQLite database by default while keeping the auth services small enough to inspect.

The current code includes a small browser HTML UI for sign-up, sign-in, email verification, and session controls. Passkey support is planned for a later chapter and will use browser WebAuthn APIs.

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

This chapter uses the native `node:crypto` Argon2 API added in Node 24. The API is currently a release candidate, which makes it useful for learning the salt, parameter, and derived-key pieces directly. A production service may still prefer a mature password-hashing package until the native API becomes stable.

It also uses `node:sqlite`, which is currently a release candidate in Node 24. If Node prints an SQLite experimental warning, that is expected.

The test suite uses `node:test` mock timers for rate-limit refill, rolling session expiration, email-code TTL, and `AbortSignal.timeout()`.

## Try It

```sh
curl -i -X POST http://localhost:3000/signup \
  -H 'content-type: application/json' \
  -d '{"email":"demo@example.com","password":"correct horse battery staple"}'
```

The verification code is printed to stdout by the development email sender.

```sh
curl -i -X POST http://localhost:3000/verify-email \
  -H 'content-type: application/json' \
  -H 'cookie: auth_session=PASTE_COOKIE_VALUE' \
  -d '{"code":"12345678"}'
```

Check the current session with the cookie returned by sign-up or sign-in:

```sh
curl -i http://localhost:3000/me \
  -H 'cookie: auth_session=PASTE_COOKIE_VALUE'
```

## References

See [docs/pilcrow-reference.md](docs/pilcrow-reference.md) for the exact article sections this chapter follows.

See [docs/chapter-plan.md](docs/chapter-plan.md) for the suggested chapter order toward the full ideal implementation.

## Planned Passwordless Support

Passkey and passwordless auth are planned for a later chapter and should integrate with the existing session, SQLite, rate-limit, and identity-verification services instead of becoming a separate auth stack.

Reference implementation:

- [pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com](https://github.com/pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com)

Planned scope:

- Email code sign-in.
- Passkey registration.
- Passkey sign-in.
- Passkey deletion behind identity verification.
- WebAuthn challenge storage and cleanup.
- SQLite tables for passkeys, passkey sign-in attempts, and passkey registration/deletion sessions.
- Browser HTML pages that call the WebAuthn APIs and existing JSON actions.

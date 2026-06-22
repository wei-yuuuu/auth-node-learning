import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { EmailCodeService } from "./auth/email-code-service.js";
import { EmailCodeSigninService } from "./auth/email-code-signin-service.js";
import { hashPassword, validatePassword, verifyPassword } from "./auth/password-service.js";
import { PasswordResetService } from "./auth/password-reset-service.js";
import { randomBase64Url } from "./auth/random.js";
import { RateLimiter } from "./auth/rate-limit.js";
import { SessionService } from "./auth/session-service.js";
import {
  PASSKEY_CHALLENGE_TTL_MS,
  PASSKEY_LIMIT,
  WebAuthnError,
  buildPasskeyAuthenticationOptions,
  buildPasskeyCreationOptions,
  createPasskeyChallenge,
  getClientDataChallenge,
  hashPasskeyChallenge,
  validatePasskeyName,
  validatePasskeyRegistration,
  verifyPasskeyAuthentication
} from "./auth/webauthn.js";
import { parseCookies, serializeCookie } from "./http/cookies.js";
import { readJson, sendJson } from "./http/json.js";
import { requestOrigin } from "./http/origin.js";
import { CSRF_COOKIE, validateUnsafeBrowserRequest } from "./http/request-guards.js";
import { normalizeEmail, validateEmail } from "./store/email.js";
import { SQLiteStore } from "./store/sqlite-store.js";

const store = new SQLiteStore(process.env.AUTH_DB_PATH ?? "auth-node.sqlite");
const sessions = new SessionService(store);
const devEmailSender = {
  async sendEmailVerificationCode(email, code) {
    console.log(`[dev-email] Email verification code for ${email}: ${code}`);
  },
  async sendPasswordResetCode(email, code) {
    console.log(`[dev-email] Password reset code for ${email}: ${code}`);
  },
  async sendEmailCodeSigninCode(email, code) {
    console.log(`[dev-email] Sign-in code for ${email}: ${code}`);
  }
};
const emailCodes = new EmailCodeService(store, devEmailSender);
const passwordResets = new PasswordResetService(store, devEmailSender);
const emailCodeSignin = new EmailCodeSigninService(store, sessions, devEmailSender);
const passwordAttemptLimiter = new RateLimiter({
  name: "password-signin",
  capacity: 5,
  refillTokens: 1,
  refillIntervalMs: 1000 * 60
}, store);
const passwordVerificationLimiter = new RateLimiter({
  name: "password-verification",
  capacity: 5,
  refillTokens: 1,
  refillIntervalMs: 1000 * 60
}, store);

const AUTH_COOKIE = "auth_session";
const PASSWORD_UPDATE_COOKIE = "password_update_session";
const EMAIL_UPDATE_COOKIE = "email_update_session";
const ACCOUNT_DELETE_COOKIE = "account_delete_session";
const PASSKEY_MANAGE_COOKIE = "passkey_manage_session";
const EMAIL_CODE_SIGNIN_COOKIE = "email_code_signin_session";
const publicDirectory = fileURLToPath(new URL("../public", import.meta.url));

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, "http://localhost");
    const browserRequestError = validateUnsafeBrowserRequest(request);

    if (browserRequestError) {
      return sendJson(
        response,
        browserRequestError.statusCode,
        { error: browserRequestError.message }
      );
    }

    if (request.method === "GET" && url.pathname === "/") {
      return serveStaticFile(response, "index.html", setCsrfCookie(createCsrfToken()));
    }

    if (request.method === "GET" && url.pathname.startsWith("/assets/")) {
      return serveStaticFile(response, url.pathname.slice(1));
    }

    if (request.method === "GET" && url.pathname === "/health") {
      return sendJson(response, 200, { ok: true });
    }

    if (request.method === "POST" && url.pathname === "/signup") {
      return handleSignup(request, response);
    }

    if (request.method === "POST" && url.pathname === "/verify-email") {
      return withAuth(request, response, handleVerifyEmail);
    }

    if (request.method === "POST" && url.pathname === "/verify-email/resend") {
      return withAuth(request, response, handleResendEmailVerification);
    }

    if (request.method === "POST" && url.pathname === "/signin") {
      return handleSignin(request, response);
    }

    if (request.method === "POST" && url.pathname === "/email-code-signin/start") {
      return handleEmailCodeSigninStart(request, response);
    }

    if (request.method === "POST" && url.pathname === "/email-code-signin/verify") {
      return handleEmailCodeSigninVerify(request, response);
    }

    if (request.method === "POST" && url.pathname === "/passkeys/signin/options") {
      return handlePasskeySigninOptions(request, response);
    }

    if (request.method === "POST" && url.pathname === "/passkeys/signin") {
      return handlePasskeySignin(request, response);
    }

    if (request.method === "POST" && url.pathname === "/password/verify") {
      return withAuth(request, response, handlePasswordIdentityVerification);
    }

    if (request.method === "POST" && url.pathname === "/password/update") {
      return withAuth(request, response, handlePasswordUpdate);
    }

    if (request.method === "POST" && url.pathname === "/password-reset/start") {
      return handlePasswordResetStart(request, response);
    }

    if (request.method === "POST" && url.pathname === "/password-reset/finish") {
      return handlePasswordResetFinish(request, response);
    }

    if (request.method === "POST" && url.pathname === "/email-update/verify") {
      return withAuth(request, response, handleEmailUpdateIdentityVerification);
    }

    if (request.method === "POST" && url.pathname === "/email-update/start") {
      return withAuth(request, response, handleEmailUpdateStart);
    }

    if (request.method === "POST" && url.pathname === "/email-update/finish") {
      return withAuth(request, response, handleEmailUpdateFinish);
    }

    if (request.method === "POST" && url.pathname === "/account/delete/verify") {
      return withAuth(request, response, handleAccountDeletionIdentityVerification);
    }

    if (request.method === "POST" && url.pathname === "/account/delete") {
      return withAuth(request, response, handleAccountDeletion);
    }

    if (request.method === "POST" && url.pathname === "/passkeys/verify") {
      return withAuth(request, response, handlePasskeyIdentityVerification);
    }

    if (request.method === "POST" && url.pathname === "/passkeys/register/options") {
      return withAuth(request, response, handlePasskeyRegistrationOptions);
    }

    if (request.method === "POST" && url.pathname === "/passkeys/register") {
      return withAuth(request, response, handlePasskeyRegistration);
    }

    if (request.method === "POST" && url.pathname === "/passkeys/delete") {
      return withAuth(request, response, handlePasskeyDeletion);
    }

    if (request.method === "GET" && url.pathname === "/me") {
      return withAuth(request, response, handleMe);
    }

    if (request.method === "POST" && url.pathname === "/signout") {
      return withAuth(request, response, handleSignout);
    }

    if (request.method === "POST" && url.pathname === "/sessions/signout-all") {
      return withAuth(request, response, handleSignoutAll);
    }

    return sendJson(response, 404, { error: "Not found." });
  } catch (error) {
    // readJson() uses JSON.parse(). Invalid request JSON is client input, so it
    // should be a 400 response instead of an internal server error.
    if (error instanceof SyntaxError) {
      return sendJson(response, 400, { error: "Request body must be valid JSON." });
    }

    console.error(error);
    return sendJson(response, 500, { error: "Internal server error." });
  }
});

async function handleSignup(request, response) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const emailError = validateEmail(email);
  const passwordError = validatePassword(body.password);

  if (emailError) {
    return sendJson(response, 400, { error: emailError, field: "email" });
  }

  if (passwordError) {
    return sendJson(response, 400, { error: passwordError, field: "password" });
  }

  const passwordHash = await hashPassword(body.password);
  let user;

  try {
    user = await store.createUser({ email, passwordHash });
  } catch (error) {
    if (error.message !== "Email address is already registered.") {
      throw error;
    }

    return sendJson(response, 400, { error: error.message, field: "email" });
  }

  const token = await sessions.createAuthSession(user.id);
  const authSession = await sessions.validateAuthToken(token);

  await emailCodes.createEmailVerificationCode({
    sessionId: authSession.id,
    email: user.email
  });

  return sendJson(
    response,
    201,
    {
      user: publicUser(user),
      message: "Account created. Check stdout for the development verification email."
    },
    setAuthCookie(token)
  );
}

async function handleVerifyEmail(request, response, authSession) {
  const body = await readJson(request);
  const user = await store.getUserById(authSession.userId);

  const result = await emailCodes.verifyEmailCode({
    sessionId: authSession.id,
    email: user.email,
    code: body.code
  });

  if (!result.ok) {
    return sendJson(response, 400, { error: result.error, field: "code" });
  }

  await store.markEmailVerified(user.id);
  return sendJson(response, 200, { user: publicUser(await store.getUserById(user.id)) });
}

async function handleResendEmailVerification(_request, response, authSession) {
  const user = await store.getUserById(authSession.userId);

  if (user.emailVerified) {
    return sendJson(response, 200, {
      user: publicUser(user),
      message: "Email address is already verified."
    });
  }

  await emailCodes.createEmailVerificationCode({
    sessionId: authSession.id,
    email: user.email
  });

  return sendJson(response, 200, {
    user: publicUser(user),
    message: "A new verification code was printed to stdout."
  });
}

async function handleSignin(request, response) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const emailError = validateEmail(email);

  if (emailError) {
    return sendJson(response, 400, { error: emailError, field: "email" });
  }

  if (!(await passwordAttemptLimiter.consume(email))) {
    return sendJson(response, 429, {
      error: "Too many sign-in attempts. Try again later."
    });
  }

  const user = await store.getUserByEmail(email);

  if (!user) {
    // Pilcrow: preventing user enumeration entirely is difficult. Hashing even
    // when the account does not exist complicates rate limiting and still does
    // not fully eliminate timing inference; explicit errors are better UX here.
    // Reference: https://auth.pilcrowonpaper.com/passwords
    return sendJson(response, 400, {
      error: "No account exists for this email address.",
      field: "email"
    });
  }

  const validPassword = await verifyPassword(user.passwordHash, body.password ?? "");

  if (!validPassword) {
    return sendJson(response, 400, { error: "Password is incorrect.", field: "password" });
  }

  const token = await sessions.createAuthSession(user.id);
  return sendJson(response, 200, { user: publicUser(user) }, setAuthCookie(token));
}

async function handleEmailCodeSigninStart(request, response) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const emailError = validateEmail(email);

  if (emailError) {
    return sendJson(response, 400, { error: emailError, field: "email" });
  }

  const user = await store.getUserByEmail(email);

  if (!user) {
    return sendJson(response, 400, {
      error: "No account exists for this email address.",
      field: "email"
    });
  }

  const result = await emailCodeSignin.createSigninCode(user);

  if (!result.ok) {
    return sendJson(response, 429, { error: result.error });
  }

  return sendJson(
    response,
    200,
    { ok: true, message: "A sign-in code was printed to stdout." },
    setEmailCodeSigninCookie(result.token)
  );
}

async function handleEmailCodeSigninVerify(request, response) {
  const body = await readJson(request);
  const cookies = parseCookies(request.headers.cookie);
  const result = await emailCodeSignin.verifySigninCode(
    cookies.get(EMAIL_CODE_SIGNIN_COOKIE),
    body.code
  );

  if (!result.ok) {
    const headers = result.clearSession ? clearEmailCodeSigninCookie() : {};
    return sendJson(response, 400, { error: result.error, field: "code" }, headers);
  }

  const user = await store.getUserById(result.userId);

  return sendJson(
    response,
    200,
    { user: publicUser(user) },
    setCookieHeaders(setAuthCookie(result.authToken), clearEmailCodeSigninCookie())
  );
}

async function handlePasskeySigninOptions(request, response) {
  const relyingParty = relyingPartyForRequest(request);

  if (!relyingParty) {
    return sendJson(response, 400, { error: "Request host is required." });
  }

  const challenge = createPasskeyChallenge();

  await store.insertPasskeySigninAttempt({
    challengeHashHex: hashPasskeyChallenge(challenge),
    expiresAt: Date.now() + PASSKEY_CHALLENGE_TTL_MS
  });

  return sendJson(response, 200, {
    options: buildPasskeyAuthenticationOptions({
      challenge,
      rpId: relyingParty.id
    })
  });
}

async function handlePasskeySignin(request, response) {
  const body = await readJson(request);
  const relyingParty = relyingPartyForRequest(request);

  if (!relyingParty) {
    return sendJson(response, 400, { error: "Request host is required." });
  }

  try {
    const challenge = getClientDataChallenge(body.credential);
    const challengeHashHex = hashPasskeyChallenge(challenge);
    const attempt = await store.getPasskeySigninAttempt(challengeHashHex);

    await store.deletePasskeySigninAttempt(challengeHashHex);

    if (!attempt || attempt.expiresAt <= Date.now()) {
      return sendJson(response, 400, { error: "Passkey challenge expired." });
    }

    const passkey = await store.getPasskeyByCredentialId(body.credential?.rawId);

    if (!passkey) {
      return sendJson(response, 400, { error: "Passkey is not registered." });
    }

    const result = verifyPasskeyAuthentication({
      credential: body.credential,
      storedPasskey: passkey,
      expectedChallenge: challenge,
      expectedOrigin: relyingParty.origin,
      expectedRpId: relyingParty.id
    });

    if (result.signCount > passkey.signCount) {
      await store.updatePasskeySignCount(passkey.credentialId, result.signCount);
    }

    const token = await sessions.createAuthSession(passkey.userId);
    const user = await store.getUserById(passkey.userId);

    return sendJson(response, 200, { user: publicUser(user) }, setAuthCookie(token));
  } catch (error) {
    if (error instanceof WebAuthnError) {
      return sendJson(response, 400, { error: error.message });
    }

    throw error;
  }
}

async function handlePasswordIdentityVerification(request, response, authSession) {
  return handlePasswordBasedVerification(request, response, authSession, {
    action: "password-update",
    message: "Identity verified for password update.",
    setCookie: setPasswordUpdateCookie
  });
}

async function handlePasswordUpdate(request, response, authSession) {
  const body = await readJson(request);
  const cookies = parseCookies(request.headers.cookie);
  const verificationToken = cookies.get(PASSWORD_UPDATE_COOKIE);
  const verified = await sessions.consumeVerificationToken(verificationToken, {
    action: "password-update",
    userId: authSession.userId,
    authSessionId: authSession.id
  });

  if (!verified) {
    return sendJson(response, 401, { error: "Password update verification required." });
  }

  const passwordError = validatePassword(body.password);

  if (passwordError) {
    return sendJson(
      response,
      400,
      { error: passwordError, field: "password" },
      clearPasswordUpdateCookie()
    );
  }

  await store.updateUserPassword(authSession.userId, await hashPassword(body.password));

  if (body.signOutOtherDevices === true) {
    await sessions.invalidateOtherAuthSessions(authSession.userId, authSession.id);
  }

  return sendJson(
    response,
    200,
    { ok: true },
    clearPasswordUpdateCookie()
  );
}

async function handlePasswordResetStart(request, response) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const emailError = validateEmail(email);

  if (emailError) {
    return sendJson(response, 400, { error: emailError, field: "email" });
  }

  const result = await passwordResets.createPasswordResetCode(email);

  if (!result.ok) {
    return sendJson(response, 429, { error: result.error });
  }

  return sendJson(response, 200, {
    ok: true,
    message: "If an account exists for this email, a reset code was sent."
  });
}

async function handlePasswordResetFinish(request, response) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const emailError = validateEmail(email);
  const passwordError = validatePassword(body.password);

  if (emailError) {
    return sendJson(response, 400, { error: emailError, field: "email" });
  }

  if (passwordError) {
    return sendJson(response, 400, { error: passwordError, field: "password" });
  }

  const result = await passwordResets.verifyPasswordResetCode({
    email,
    code: body.code
  });

  if (!result.ok) {
    return sendJson(response, 400, { error: result.error, field: "code" });
  }

  const user = await store.getUserByEmail(email);

  if (!user) {
    return sendJson(response, 400, { error: "Password reset code expired.", field: "code" });
  }

  await store.updateUserPassword(user.id, await hashPassword(body.password));

  if (body.signOutAllDevices === true) {
    await sessions.invalidateAllAuthSessions(user.id);
  }

  return sendJson(response, 200, { ok: true });
}

async function handleEmailUpdateIdentityVerification(request, response, authSession) {
  return handlePasswordBasedVerification(request, response, authSession, {
    action: "email-update",
    message: "Identity verified for email update.",
    setCookie: setEmailUpdateCookie
  });
}

async function handleEmailUpdateStart(request, response, authSession) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const emailError = validateEmail(email);
  const cookies = parseCookies(request.headers.cookie);
  const verificationToken = cookies.get(EMAIL_UPDATE_COOKIE);
  const verificationSession = await sessions.validateVerificationToken(verificationToken, {
    action: "email-update",
    userId: authSession.userId,
    authSessionId: authSession.id
  });

  if (!verificationSession) {
    return sendJson(response, 401, { error: "Email update verification required." });
  }

  if (emailError) {
    return sendJson(response, 400, { error: emailError, field: "email" });
  }

  const existingUser = await store.getUserByEmail(email);

  if (existingUser && existingUser.id !== authSession.userId) {
    return sendJson(response, 400, {
      error: "Email address is already registered.",
      field: "email"
    });
  }

  await emailCodes.createEmailVerificationCode({
    sessionId: verificationSession.id,
    email
  });

  return sendJson(response, 200, {
    ok: true,
    message: "A verification code was printed to stdout for the new email address."
  });
}

async function handleEmailUpdateFinish(request, response, authSession) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const emailError = validateEmail(email);
  const cookies = parseCookies(request.headers.cookie);
  const verificationToken = cookies.get(EMAIL_UPDATE_COOKIE);
  const verificationSession = await sessions.validateVerificationToken(verificationToken, {
    action: "email-update",
    userId: authSession.userId,
    authSessionId: authSession.id
  });

  if (!verificationSession) {
    return sendJson(response, 401, { error: "Email update verification required." });
  }

  if (emailError) {
    return sendJson(response, 400, { error: emailError, field: "email" });
  }

  const result = await emailCodes.verifyEmailCode({
    sessionId: verificationSession.id,
    email,
    code: body.code
  });

  if (!result.ok) {
    return sendJson(response, 400, { error: result.error, field: "code" });
  }

  await sessions.consumeVerificationToken(verificationToken, {
    action: "email-update",
    userId: authSession.userId,
    authSessionId: authSession.id
  });

  try {
    await store.updateUserEmail(authSession.userId, email);
  } catch (error) {
    return sendJson(
      response,
      400,
      { error: error.message, field: "email" },
      clearEmailUpdateCookie()
    );
  }

  return sendJson(
    response,
    200,
    { user: publicUser(await store.getUserById(authSession.userId)) },
    clearEmailUpdateCookie()
  );
}

async function handleAccountDeletionIdentityVerification(request, response, authSession) {
  return handlePasswordBasedVerification(request, response, authSession, {
    action: "account-delete",
    message: "Identity verified for account deletion.",
    setCookie: setAccountDeleteCookie
  });
}

async function handlePasskeyIdentityVerification(request, response, authSession) {
  return handlePasswordBasedVerification(request, response, authSession, {
    action: "passkey-manage",
    message: "Identity verified for passkey management.",
    setCookie: setPasskeyManageCookie
  });
}

async function handlePasswordBasedVerification(
  request,
  response,
  authSession,
  { action, message, setCookie }
) {
  const body = await readJson(request);
  const user = await store.getUserById(authSession.userId);

  if (!(await passwordVerificationLimiter.consume(user.id))) {
    return sendJson(response, 429, {
      error: "Too many password verification attempts. Try again later."
    });
  }

  const validPassword = await verifyPassword(user.passwordHash, body.password ?? "");

  if (!validPassword) {
    return sendJson(response, 400, { error: "Password is incorrect.", field: "password" });
  }

  const verificationToken = await sessions.createVerificationSession({
    userId: user.id,
    action,
    authSessionId: authSession.id
  });

  return sendJson(
    response,
    200,
    { ok: true, message },
    setCookie(verificationToken)
  );
}

async function handlePasskeyRegistrationOptions(request, response, authSession) {
  const user = await store.getUserById(authSession.userId);
  const verificationSession = await validatePasskeyManageSession(request, authSession);
  const relyingParty = relyingPartyForRequest(request);

  if (!verificationSession) {
    return sendJson(response, 401, { error: "Passkey management verification required." });
  }

  if (!relyingParty) {
    return sendJson(response, 400, { error: "Request host is required." });
  }

  const existingPasskeys = await store.listPasskeysByUserId(user.id);

  if (existingPasskeys.length >= PASSKEY_LIMIT) {
    return sendJson(response, 400, {
      error: `A user can register at most ${PASSKEY_LIMIT} passkeys.`
    });
  }

  return sendJson(response, 200, {
    options: buildPasskeyCreationOptions({
      rpId: relyingParty.id,
      user,
      existingPasskeys
    })
  });
}

async function handlePasskeyRegistration(request, response, authSession) {
  const body = await readJson(request);
  const user = await store.getUserById(authSession.userId);
  const cookies = parseCookies(request.headers.cookie);
  const verificationToken = cookies.get(PASSKEY_MANAGE_COOKIE);
  const passkeyName = body.name ?? "Passkey";
  const nameError = validatePasskeyName(passkeyName);

  if (nameError) {
    return sendJson(response, 400, { error: nameError, field: "name" });
  }

  const existingPasskeyCount = await store.countPasskeysByUserId(user.id);

  if (existingPasskeyCount >= PASSKEY_LIMIT) {
    return sendJson(response, 400, {
      error: `A user can register at most ${PASSKEY_LIMIT} passkeys.`
    });
  }

  const verified = await sessions.consumeVerificationToken(verificationToken, {
    action: "passkey-manage",
    userId: authSession.userId,
    authSessionId: authSession.id
  });

  if (!verified) {
    return sendJson(response, 401, { error: "Passkey management verification required." });
  }

  try {
    const relyingParty = relyingPartyForRequest(request);

    if (!relyingParty) {
      return sendJson(
        response,
        400,
        { error: "Request host is required." },
        clearPasskeyManageCookie()
      );
    }

    const registration = validatePasskeyRegistration({
      credential: body.credential,
      expectedOrigin: relyingParty.origin,
      expectedRpId: relyingParty.id
    });

    await store.insertPasskey({
      ...registration,
      userId: user.id,
      name: passkeyName,
      createdAt: Date.now()
    });

    return sendJson(
      response,
      201,
      {
        ok: true,
        message: "Passkey registered.",
        passkeys: publicPasskeys(await store.listPasskeysByUserId(user.id))
      },
      clearPasskeyManageCookie()
    );
  } catch (error) {
    if (error instanceof WebAuthnError) {
      return sendJson(
        response,
        400,
        { error: error.message },
        clearPasskeyManageCookie()
      );
    }

    if (error.message === "Passkey is already registered.") {
      return sendJson(
        response,
        400,
        { error: error.message },
        clearPasskeyManageCookie()
      );
    }

    throw error;
  }
}

async function handlePasskeyDeletion(request, response, authSession) {
  const body = await readJson(request);
  const cookies = parseCookies(request.headers.cookie);
  const verificationToken = cookies.get(PASSKEY_MANAGE_COOKIE);
  const verified = await sessions.consumeVerificationToken(verificationToken, {
    action: "passkey-manage",
    userId: authSession.userId,
    authSessionId: authSession.id
  });

  if (!verified) {
    return sendJson(response, 401, { error: "Passkey management verification required." });
  }

  const passkey = await store.getPasskeyByCredentialId(body.credentialId);

  if (!passkey || passkey.userId !== authSession.userId) {
    return sendJson(
      response,
      400,
      { error: "Passkey is not registered.", field: "credentialId" },
      clearPasskeyManageCookie()
    );
  }

  await store.deletePasskeyByCredentialId(authSession.userId, passkey.credentialId);

  return sendJson(
    response,
    200,
    {
      ok: true,
      message: "Passkey deleted.",
      passkeys: publicPasskeys(await store.listPasskeysByUserId(authSession.userId))
    },
    clearPasskeyManageCookie()
  );
}

async function handleAccountDeletion(request, response, authSession) {
  const body = await readJson(request);
  const user = await store.getUserById(authSession.userId);

  if (!user) {
    return sendJson(response, 401, { error: "Authentication required." }, clearAuthCookie());
  }

  if (normalizeEmail(body.confirmationEmail) !== user.email) {
    return sendJson(response, 400, {
      error: "Type the current account email to confirm deletion.",
      field: "confirmationEmail"
    });
  }

  const cookies = parseCookies(request.headers.cookie);
  const verificationToken = cookies.get(ACCOUNT_DELETE_COOKIE);
  const verified = await sessions.consumeVerificationToken(verificationToken, {
    action: "account-delete",
    userId: authSession.userId,
    authSessionId: authSession.id
  });

  if (!verified) {
    return sendJson(response, 401, { error: "Account deletion verification required." });
  }

  await store.deleteUser(authSession.userId);

  return sendJson(
    response,
    200,
    { ok: true, message: "Account deleted." },
    setCookieHeaders(
      clearAuthCookie(),
      clearPasswordUpdateCookie(),
      clearEmailUpdateCookie(),
      clearAccountDeleteCookie(),
      clearPasskeyManageCookie()
    )
  );
}

async function handleMe(_request, response, authSession) {
  const user = await store.getUserById(authSession.userId);
  const passkeys = await store.listPasskeysByUserId(authSession.userId);

  return sendJson(response, 200, {
    user: publicUser(user),
    passkeys: publicPasskeys(passkeys)
  });
}

async function handleSignout(_request, response, authSession) {
  await sessions.invalidateSession(authSession.id);
  return sendJson(response, 200, { ok: true }, clearAuthCookie());
}

async function handleSignoutAll(_request, response, authSession) {
  await sessions.invalidateAllAuthSessions(authSession.userId);
  return sendJson(response, 200, { ok: true }, clearAuthCookie());
}

async function withAuth(request, response, handler) {
  const cookies = parseCookies(request.headers.cookie);
  const token = cookies.get(AUTH_COOKIE);
  const authSession = await sessions.validateAuthToken(token);

  if (!authSession) {
    return sendJson(response, 401, { error: "Authentication required." }, clearAuthCookie());
  }

  return handler(request, response, authSession);
}

async function validatePasskeyManageSession(request, authSession) {
  const cookies = parseCookies(request.headers.cookie);
  const verificationToken = cookies.get(PASSKEY_MANAGE_COOKIE);

  return sessions.validateVerificationToken(verificationToken, {
    action: "passkey-manage",
    userId: authSession.userId,
    authSessionId: authSession.id
  });
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    emailVerified: user.emailVerified
  };
}

function publicPasskeys(passkeys) {
  return passkeys.map((passkey) => ({
    credentialId: passkey.credentialId,
    name: passkey.name,
    authenticatorId: passkey.authenticatorId,
    createdAt: passkey.createdAt
  }));
}

function setAuthCookie(token) {
  return {
    "set-cookie": serializeCookie(AUTH_COOKIE, token, {
      maxAge: 60 * 60 * 24 * 30,
      secure: process.env.NODE_ENV === "production"
    })
  };
}

function clearAuthCookie() {
  return {
    "set-cookie": serializeCookie(AUTH_COOKIE, "", { maxAge: 0 })
  };
}

function setPasswordUpdateCookie(token) {
  return {
    "set-cookie": serializeCookie(PASSWORD_UPDATE_COOKIE, token, {
      maxAge: 60 * 10,
      secure: process.env.NODE_ENV === "production"
    })
  };
}

function clearPasswordUpdateCookie() {
  return {
    "set-cookie": serializeCookie(PASSWORD_UPDATE_COOKIE, "", { maxAge: 0 })
  };
}

function setEmailUpdateCookie(token) {
  return {
    "set-cookie": serializeCookie(EMAIL_UPDATE_COOKIE, token, {
      maxAge: 60 * 10,
      secure: process.env.NODE_ENV === "production"
    })
  };
}

function clearEmailUpdateCookie() {
  return {
    "set-cookie": serializeCookie(EMAIL_UPDATE_COOKIE, "", { maxAge: 0 })
  };
}

function setAccountDeleteCookie(token) {
  return {
    "set-cookie": serializeCookie(ACCOUNT_DELETE_COOKIE, token, {
      maxAge: 60 * 10,
      secure: process.env.NODE_ENV === "production"
    })
  };
}

function clearAccountDeleteCookie() {
  return {
    "set-cookie": serializeCookie(ACCOUNT_DELETE_COOKIE, "", { maxAge: 0 })
  };
}

function setPasskeyManageCookie(token) {
  return {
    "set-cookie": serializeCookie(PASSKEY_MANAGE_COOKIE, token, {
      maxAge: 60 * 10,
      secure: process.env.NODE_ENV === "production"
    })
  };
}

function clearPasskeyManageCookie() {
  return {
    "set-cookie": serializeCookie(PASSKEY_MANAGE_COOKIE, "", { maxAge: 0 })
  };
}

function setEmailCodeSigninCookie(token) {
  return {
    "set-cookie": serializeCookie(EMAIL_CODE_SIGNIN_COOKIE, token, {
      maxAge: 60 * 60,
      secure: process.env.NODE_ENV === "production"
    })
  };
}

function clearEmailCodeSigninCookie() {
  return {
    "set-cookie": serializeCookie(EMAIL_CODE_SIGNIN_COOKIE, "", { maxAge: 0 })
  };
}

function setCookieHeaders(...headers) {
  return {
    "set-cookie": headers.flatMap((header) => header["set-cookie"])
  };
}

function createCsrfToken() {
  return randomBase64Url(32);
}

function setCsrfCookie(token) {
  return {
    "set-cookie": serializeCookie(CSRF_COOKIE, token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production"
    })
  };
}

// In WebAuthn, the relying party is this website/auth server. For local
// development at http://localhost:3000, the origin is "http://localhost:3000"
// and the RP ID is "localhost". Passkeys are scoped to the RP ID, so a passkey
// created for localhost cannot be used by another domain.
function relyingPartyForRequest(request) {
  const origin = requestOrigin(request);

  if (origin === null) {
    return null;
  }

  return {
    origin,
    id: new URL(origin).hostname
  };
}

async function serveStaticFile(response, relativePath, headers = {}) {
  const safeRelativePath = normalize(relativePath).replace(/^(\.\.(\/|\\|$))+/, "");
  const filePath = join(publicDirectory, safeRelativePath);

  try {
    const body = await readFile(filePath);

    response.writeHead(200, {
      "content-type": contentTypeFor(filePath),
      ...headers
    });
    response.end(body);
  } catch {
    sendJson(response, 404, { error: "Not found." });
  }
}

function contentTypeFor(filePath) {
  const extension = extname(filePath);

  if (extension === ".css") {
    return "text/css; charset=utf-8";
  }

  if (extension === ".js") {
    return "text/javascript; charset=utf-8";
  }

  return "text/html; charset=utf-8";
}

const port = Number.parseInt(process.env.PORT ?? "3000", 10);
const cleanupIntervalMs = Number.parseInt(process.env.AUTH_CLEANUP_INTERVAL_MS ?? "300000", 10);

await store.deleteExpiredRecords();

setInterval(async () => {
  try {
    await store.deleteExpiredRecords();
  } catch (error) {
    console.error("Failed to delete expired auth records.", error);
  }
}, cleanupIntervalMs).unref();

server.listen(port, () => {
  console.log(`Auth learning server listening on http://localhost:${port}`);
});

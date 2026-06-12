import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { EmailCodeService } from "./auth/email-code-service.js";
import { hashPassword, validatePassword, verifyPassword } from "./auth/password-service.js";
import { PasswordResetService } from "./auth/password-reset-service.js";
import { RateLimiter } from "./auth/rate-limit.js";
import { SessionService } from "./auth/session-service.js";
import { parseCookies, serializeCookie } from "./http/cookies.js";
import { readJson, sendJson } from "./http/json.js";
import { validateUnsafeBrowserRequest } from "./http/request-guards.js";
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
  }
};
const emailCodes = new EmailCodeService(store, devEmailSender);
const passwordResets = new PasswordResetService(store, devEmailSender);
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
      return serveStaticFile(response, "index.html");
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
    return sendJson(response, 400, { error: emailError });
  }

  if (passwordError) {
    return sendJson(response, 400, { error: passwordError });
  }

  const passwordHash = await hashPassword(body.password);
  let user;

  try {
    user = await store.createUser({ email, passwordHash });
  } catch (error) {
    if (error.message !== "Email address is already registered.") {
      throw error;
    }

    return sendJson(response, 400, { error: error.message });
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
    return sendJson(response, 400, { error: result.error });
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
    return sendJson(response, 400, { error: emailError });
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
    return sendJson(response, 400, { error: "No account exists for this email address." });
  }

  const validPassword = await verifyPassword(user.passwordHash, body.password ?? "");

  if (!validPassword) {
    return sendJson(response, 400, { error: "Password is incorrect." });
  }

  const token = await sessions.createAuthSession(user.id);
  return sendJson(response, 200, { user: publicUser(user) }, setAuthCookie(token));
}

async function handlePasswordIdentityVerification(request, response, authSession) {
  const body = await readJson(request);
  const user = await store.getUserById(authSession.userId);

  if (!(await passwordVerificationLimiter.consume(user.id))) {
    return sendJson(response, 429, {
      error: "Too many password verification attempts. Try again later."
    });
  }

  const validPassword = await verifyPassword(user.passwordHash, body.password ?? "");

  if (!validPassword) {
    return sendJson(response, 400, { error: "Password is incorrect." });
  }

  const verificationToken = await sessions.createVerificationSession({
    userId: user.id,
    action: "password-update",
    authSessionId: authSession.id
  });

  return sendJson(
    response,
    200,
    { ok: true, message: "Identity verified for password update." },
    setPasswordUpdateCookie(verificationToken)
  );
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
    return sendJson(response, 400, { error: passwordError }, clearPasswordUpdateCookie());
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
    return sendJson(response, 400, { error: emailError });
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
    return sendJson(response, 400, { error: emailError });
  }

  if (passwordError) {
    return sendJson(response, 400, { error: passwordError });
  }

  const result = await passwordResets.verifyPasswordResetCode({
    email,
    code: body.code
  });

  if (!result.ok) {
    return sendJson(response, 400, { error: result.error });
  }

  const user = await store.getUserByEmail(email);

  if (!user) {
    return sendJson(response, 400, { error: "Password reset code expired." });
  }

  await store.updateUserPassword(user.id, await hashPassword(body.password));

  if (body.signOutAllDevices === true) {
    await sessions.invalidateAllAuthSessions(user.id);
  }

  return sendJson(response, 200, { ok: true });
}

async function handleEmailUpdateIdentityVerification(request, response, authSession) {
  const body = await readJson(request);
  const user = await store.getUserById(authSession.userId);

  if (!(await passwordVerificationLimiter.consume(user.id))) {
    return sendJson(response, 429, {
      error: "Too many password verification attempts. Try again later."
    });
  }

  const validPassword = await verifyPassword(user.passwordHash, body.password ?? "");

  if (!validPassword) {
    return sendJson(response, 400, { error: "Password is incorrect." });
  }

  const verificationToken = await sessions.createVerificationSession({
    userId: user.id,
    action: "email-update",
    authSessionId: authSession.id
  });

  return sendJson(
    response,
    200,
    { ok: true, message: "Identity verified for email update." },
    setEmailUpdateCookie(verificationToken)
  );
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
    return sendJson(response, 400, { error: emailError });
  }

  const existingUser = await store.getUserByEmail(email);

  if (existingUser && existingUser.id !== authSession.userId) {
    return sendJson(response, 400, { error: "Email address is already registered." });
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
    return sendJson(response, 400, { error: emailError });
  }

  const result = await emailCodes.verifyEmailCode({
    sessionId: verificationSession.id,
    email,
    code: body.code
  });

  if (!result.ok) {
    return sendJson(response, 400, { error: result.error });
  }

  await sessions.consumeVerificationToken(verificationToken, {
    action: "email-update",
    userId: authSession.userId,
    authSessionId: authSession.id
  });

  try {
    await store.updateUserEmail(authSession.userId, email);
  } catch (error) {
    return sendJson(response, 400, { error: error.message }, clearEmailUpdateCookie());
  }

  return sendJson(
    response,
    200,
    { user: publicUser(await store.getUserById(authSession.userId)) },
    clearEmailUpdateCookie()
  );
}

async function handleMe(_request, response, authSession) {
  const user = await store.getUserById(authSession.userId);
  return sendJson(response, 200, { user: publicUser(user) });
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

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    emailVerified: user.emailVerified
  };
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

async function serveStaticFile(response, relativePath) {
  const safeRelativePath = normalize(relativePath).replace(/^(\.\.(\/|\\|$))+/, "");
  const filePath = join(publicDirectory, safeRelativePath);

  try {
    const body = await readFile(filePath);

    response.writeHead(200, {
      "content-type": contentTypeFor(filePath)
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

const accountSummary = document.querySelector("#account-summary");
const accountAvatar = document.querySelector("#account-avatar");
const accountEmail = document.querySelector("#account-email");
const accountId = document.querySelector("#account-id");
const accountVerified = document.querySelector("#account-verified");
const accountMenu = document.querySelector("#account-menu");
const notice = document.querySelector("#notice");
const signupForm = document.querySelector("#signup-form");
const signinForm = document.querySelector("#signin-form");
const verifyForm = document.querySelector("#verify-form");
const passwordChangeForm = document.querySelector("#password-change-form");
const passwordResetStartForm = document.querySelector("#password-reset-start-form");
const passwordResetFinishForm = document.querySelector("#password-reset-finish-form");
const passkeySigninButton = document.querySelector("#passkey-signin-button");
const passkeyVerifyForm = document.querySelector("#passkey-verify-form");
const passkeyRegisterForm = document.querySelector("#passkey-register-form");
const passkeyDeleteForm = document.querySelector("#passkey-delete-form");
const passkeyList = document.querySelector("#passkey-list");
const passkeySelect = document.querySelector("#passkey-select");
const emailUpdateVerifyForm = document.querySelector("#email-update-verify-form");
const emailUpdateStartForm = document.querySelector("#email-update-start-form");
const emailUpdateFinishForm = document.querySelector("#email-update-finish-form");
const accountDeleteVerifyForm = document.querySelector("#account-delete-verify-form");
const accountDeleteForm = document.querySelector("#account-delete-form");

let currentUser = null;
let conditionalPasskeyStarted = false;

signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await postJson("/signup", formJson(signupForm), { form: signupForm });

  if (!result.ok) {
    return;
  }

  signupForm.reset();
  await refreshSession();
});

signinForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await postJson("/signin", formJson(signinForm), { form: signinForm });

  if (!result.ok) {
    return;
  }

  signinForm.reset();
  await refreshSession();
});

verifyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await postJson("/verify-email", formJson(verifyForm), { form: verifyForm });

  if (!result.ok) {
    return;
  }

  verifyForm.reset();
  await refreshSession();
});

passwordChangeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = formJson(passwordChangeForm);

  const verifyResult = await postJson(
    "/password/verify",
    { password: data.currentPassword },
    {
      form: passwordChangeForm,
      fieldAliases: { password: "currentPassword" }
    }
  );

  if (!verifyResult.ok) {
    return;
  }

  const updateResult = await postJson(
    "/password/update",
    {
      password: data.newPassword,
      signOutOtherDevices: data.signOutOtherDevices
    },
    {
      form: passwordChangeForm,
      fieldAliases: { password: "newPassword" }
    }
  );

  if (!updateResult.ok) {
    return;
  }

  passwordChangeForm.reset();
  await refreshSession();
});

passwordResetStartForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await postJson(
    "/password-reset/start",
    formJson(passwordResetStartForm),
    { form: passwordResetStartForm }
  );
});

passwordResetFinishForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await postJson(
    "/password-reset/finish",
    formJson(passwordResetFinishForm),
    { form: passwordResetFinishForm }
  );

  if (!result.ok) {
    return;
  }

  passwordResetFinishForm.reset();
});

passkeySigninButton.addEventListener("click", async () => {
  await signInWithPasskey(signinForm);
});

passkeyVerifyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await postJson(
    "/passkeys/verify",
    formJson(passkeyVerifyForm),
    { form: passkeyVerifyForm }
  );

  if (!result.ok) {
    return;
  }

  passkeyVerifyForm.reset();
});

passkeyRegisterForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await registerPasskey(passkeyRegisterForm);
});

passkeyDeleteForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await postJson(
    "/passkeys/delete",
    formJson(passkeyDeleteForm),
    { form: passkeyDeleteForm }
  );

  if (!result.ok) {
    return;
  }

  await refreshSession();
});

emailUpdateVerifyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await postJson(
    "/email-update/verify",
    formJson(emailUpdateVerifyForm),
    { form: emailUpdateVerifyForm }
  );

  if (!result.ok) {
    return;
  }

  emailUpdateVerifyForm.reset();
});

emailUpdateStartForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await postJson(
    "/email-update/start",
    formJson(emailUpdateStartForm),
    { form: emailUpdateStartForm }
  );
});

emailUpdateFinishForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await postJson(
    "/email-update/finish",
    formJson(emailUpdateFinishForm),
    { form: emailUpdateFinishForm }
  );

  if (!result.ok) {
    return;
  }

  emailUpdateFinishForm.reset();
  await refreshSession();
});

accountDeleteVerifyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await postJson(
    "/account/delete/verify",
    formJson(accountDeleteVerifyForm),
    { form: accountDeleteVerifyForm }
  );

  if (!result.ok) {
    return;
  }

  accountDeleteVerifyForm.reset();
});

accountDeleteForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await postJson(
    "/account/delete",
    formJson(accountDeleteForm),
    { form: accountDeleteForm }
  );

  if (!result.ok) {
    return;
  }

  accountDeleteForm.reset();
});

document.querySelector("#resend-button").addEventListener("click", async () => {
  const result = await postJson("/verify-email/resend", {}, { form: verifyForm });

  if (!result.ok) {
    return;
  }

  await refreshSession();
});
accountSummary.addEventListener("click", (event) => {
  if (accountSummary.dataset.state !== "signed-in") {
    event.preventDefault();
    accountMenu.open = false;
  }
});
document.querySelector("#signout-button").addEventListener("click", async () => {
  accountMenu.open = false;
  await postJson("/signout", {});
});
document.querySelector("#signout-all-button").addEventListener("click", async () => {
  accountMenu.open = false;
  await postJson("/sessions/signout-all", {});
});

await refreshSession();
startConditionalPasskeySignin();

async function refreshSession() {
  const response = await fetch("/me", {
    credentials: "same-origin"
  });
  const body = await response.json();

  render(response.ok ? body : { signedIn: false, ...body });
}

async function signInWithPasskey(form) {
  if (!passkeysSupported()) {
    renderClientError(form, "This browser does not support passkeys.");
    return;
  }

  const optionsResult = await postJson("/passkeys/signin/options", {}, { form });

  if (!optionsResult.ok) {
    return;
  }

  let credential;

  try {
    credential = await navigator.credentials.get({
      publicKey: publicKeyAuthenticationOptions(optionsResult.body.options)
    });
  } catch (error) {
    renderClientError(form, webauthnErrorMessage(error, "sign-in"));
    return;
  }

  const result = await postJson(
    "/passkeys/signin",
    { credential: assertionCredentialJson(credential) },
    { form }
  );

  if (result.ok) {
    await refreshSession();
  }
}

async function registerPasskey(form) {
  if (!passkeysSupported()) {
    renderClientError(form, "This browser does not support passkeys.");
    return;
  }

  const data = formJson(form);
  const optionsResult = await postJson("/passkeys/register/options", {}, { form });

  if (!optionsResult.ok) {
    return;
  }

  let credential;

  try {
    credential = await navigator.credentials.create({
      publicKey: publicKeyCreationOptions(optionsResult.body.options)
    });
  } catch (error) {
    renderClientError(form, webauthnErrorMessage(error, "registration"));
    return;
  }

  let credentialJson;

  try {
    credentialJson = attestationCredentialJson(credential);
  } catch (error) {
    renderClientError(form, error.message);
    return;
  }

  const result = await postJson(
    "/passkeys/register",
    {
      name: data.name,
      credential: credentialJson
    },
    { form }
  );

  if (!result.ok) {
    return;
  }

  form.reset();
  await refreshSession();
}

async function startConditionalPasskeySignin() {
  if (conditionalPasskeyStarted || currentUser || !passkeysSupported()) {
    return;
  }

  const available = await PublicKeyCredential.isConditionalMediationAvailable?.();

  if (!available) {
    return;
  }

  conditionalPasskeyStarted = true;
  const optionsResult = await postJson("/passkeys/signin/options", {});

  if (!optionsResult.ok) {
    return;
  }

  const controller = new AbortController();

  window.setTimeout(() => controller.abort(), 1000 * 60 * 4);

  try {
    const credential = await navigator.credentials.get({
      mediation: "conditional",
      signal: controller.signal,
      publicKey: publicKeyAuthenticationOptions(optionsResult.body.options)
    });

    if (!credential) {
      return;
    }

    const result = await postJson("/passkeys/signin", {
      credential: assertionCredentialJson(credential)
    });

    if (result.ok) {
      await refreshSession();
    }
  } catch {
    // Conditional mediation can remain pending or be canceled by the user.
  }
}

async function postJson(path, body, { form = null, fieldAliases = {} } = {}) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-csrf-token": readCookie("csrf_token") ?? ""
    },
    credentials: "same-origin",
    body: JSON.stringify(body)
  });
  const responseBody = await response.json();

  render(responseBody, {
    form,
    fieldAliases,
    clearAccount: path === "/signout" ||
      path === "/sessions/signout-all" ||
      (path === "/account/delete" && response.ok)
  });
  return {
    ok: response.ok,
    status: response.status,
    body: responseBody
  };
}

function publicKeyCreationOptions(options) {
  return {
    challenge: base64UrlToArrayBuffer(options.challenge),
    rp: {
      id: options.rpId,
      name: "Auth Node Learning"
    },
    user: {
      id: base64UrlToArrayBuffer(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName
    },
    pubKeyCredParams: options.pubKeyCredParams,
    excludeCredentials: options.excludeCredentials.map((credential) => ({
      type: credential.type,
      id: base64UrlToArrayBuffer(credential.id)
    })),
    authenticatorSelection: options.authenticatorSelection,
    attestation: options.attestation,
    extensions: options.extensions
  };
}

function publicKeyAuthenticationOptions(options) {
  return {
    challenge: base64UrlToArrayBuffer(options.challenge),
    rpId: options.rpId,
    userVerification: options.userVerification
  };
}

function attestationCredentialJson(credential) {
  const response = credential.response;
  // `getPublicKey()` lets this learning app send a DER SubjectPublicKeyInfo key
  // to the server instead of parsing the COSE key map from authenticator data.
  // `getPublicKeyAlgorithm()` still carries the COSE algorithm ID.
  const publicKey = response.getPublicKey();
  const authenticatorData = response.getAuthenticatorData();

  if (!publicKey || !authenticatorData) {
    throw new Error("This browser did not expose the passkey public key.");
  }

  return {
    id: credential.id,
    rawId: arrayBufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
      authenticatorData: arrayBufferToBase64Url(authenticatorData),
      publicKey: arrayBufferToBase64Url(publicKey),
      publicKeyAlgorithm: response.getPublicKeyAlgorithm()
    }
  };
}

function assertionCredentialJson(credential) {
  const response = credential.response;

  return {
    id: credential.id,
    rawId: arrayBufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: arrayBufferToBase64Url(response.authenticatorData),
      clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
      signature: arrayBufferToBase64Url(response.signature),
      userHandle: response.userHandle ? arrayBufferToBase64Url(response.userHandle) : null
    }
  };
}

// Browser equivalent of Node's Buffer.from(value, "base64url"). The WebAuthn
// API needs ArrayBuffer values, but this file runs in the browser where Node's
// Buffer global is not available.
function base64UrlToArrayBuffer(value) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padding = "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(base64 + padding);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes.buffer;
}

// Browser equivalent of Buffer.from(arrayBuffer).toString("base64url"). This
// converts WebAuthn ArrayBuffer fields into JSON-safe strings for fetch().
function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function passkeysSupported() {
  return "PublicKeyCredential" in window && "credentials" in navigator;
}

function webauthnErrorMessage(error, action) {
  // navigator.credentials.create/get rejects with DOMException names that are
  // useful to distinguish in the UI: NotAllowedError usually means the user
  // canceled or the operation timed out, while NotSupportedError means the
  // authenticator cannot satisfy requirements such as algorithm or user
  // verification support.
  if (error instanceof DOMException) {
    if (error.name === "NotAllowedError") {
      return `Passkey ${action} was canceled or timed out.`;
    }

    if (error.name === "NotSupportedError") {
      return `This authenticator cannot satisfy the passkey ${action} requirements.`;
    }
  }

  return `Passkey ${action} failed.`;
}

function formJson(form) {
  const data = Object.fromEntries(new FormData(form));

  for (const checkbox of form.querySelectorAll('input[type="checkbox"]')) {
    data[checkbox.name] = checkbox.checked;
  }

  return data;
}

function readCookie(name) {
  for (const part of document.cookie.split(";")) {
    const [cookieName, ...valueParts] = part.trim().split("=");

    if (cookieName === name) {
      return decodeURIComponent(valueParts.join("="));
    }
  }

  return null;
}

function render(value, { clearAccount = false, form = null, fieldAliases = {} } = {}) {
  if (clearAccount || value.signedIn === false || Object.hasOwn(value, "user")) {
    renderAccount(value.user);
  }

  if (clearAccount || value.signedIn === false) {
    renderPasskeys([]);
  } else if (Object.hasOwn(value, "passkeys")) {
    renderPasskeys(value.passkeys);
  }

  clearFormFeedback(form);

  const fieldName = fieldAliases[value.field] ?? value.field;

  if (value.error && form) {
    renderFieldError(form, fieldName, value.error);
  }

  if (form && value.error) {
    renderFormAlert(form, {
      message: value.error,
      tone: "error"
    });
    clearGlobalNotice();
    return;
  }

  if (form && value.message) {
    renderFormAlert(form, {
      message: value.message,
      tone: "info"
    });
    clearGlobalNotice();
    return;
  }

  const text = clearAccount && value.ok && !value.message ? "" : statusText(value);

  notice.textContent = text;
  notice.hidden = text === "";
  notice.dataset.tone = value.error ? "error" : "info";
}

function renderClientError(form, message) {
  clearFormFeedback(form);
  renderFormAlert(form, {
    message,
    tone: "error"
  });
  clearGlobalNotice();
}

function clearGlobalNotice() {
  notice.textContent = "";
  notice.hidden = true;
  notice.dataset.tone = "info";
}

function clearFormFeedback(form) {
  if (!form) {
    return;
  }

  for (const alert of form.querySelectorAll(".form-alert")) {
    alert.remove();
  }

  for (const error of form.querySelectorAll(".field-error")) {
    error.remove();
  }

  for (const control of form.querySelectorAll("[aria-invalid='true']")) {
    control.removeAttribute("aria-invalid");
    control.removeAttribute("aria-describedby");
  }
}

function renderFieldError(form, fieldName, message) {
  const control = Array.from(form.elements).find((element) => element.name === fieldName);
  const label = control?.closest("label");

  if (!control || !label) {
    return false;
  }

  const error = document.createElement("p");

  error.id = `${form.id}-${fieldName}-error`;
  error.className = "field-error";
  error.textContent = message;

  control.setAttribute("aria-invalid", "true");
  control.setAttribute("aria-describedby", error.id);
  label.append(error);
  return true;
}

function renderFormAlert(form, { message, tone }) {
  const alert = document.createElement("div");
  alert.className = "form-alert";
  alert.dataset.tone = tone;
  alert.setAttribute("role", "alert");
  alert.setAttribute("tabindex", "-1");

  const body = document.createElement("p");
  body.className = "form-alert-message";
  body.textContent = message;
  alert.append(body);
  const heading = form.querySelector("h2");

  if (heading) {
    heading.after(alert);
  } else {
    form.prepend(alert);
  }

  alert.focus();
}

function renderAccount(user) {
  currentUser = user ?? null;

  if (!user) {
    accountSummary.dataset.state = "signed-out";
    accountMenu.open = false;
    accountAvatar.textContent = "?";
    accountEmail.textContent = "Please sign in";
    accountId.hidden = true;
    accountVerified.hidden = true;
    accountVerified.dataset.verified = "false";
    accountVerified.textContent = "×";
    accountVerified.setAttribute("aria-label", "Email not verified");
    return;
  }

  accountSummary.dataset.state = "signed-in";
  accountAvatar.textContent = user.email.slice(0, 1).toUpperCase();
  accountEmail.textContent = user.email;
  accountId.textContent = `ID ${user.id}`;
  accountId.hidden = false;
  accountVerified.hidden = false;
  accountVerified.dataset.verified = String(user.emailVerified);
  accountVerified.textContent = user.emailVerified ? "✓" : "×";
  accountVerified.setAttribute(
    "aria-label",
    user.emailVerified ? "Email verified" : "Email not verified"
  );
}

function renderPasskeys(passkeys) {
  passkeyList.replaceChildren();
  passkeySelect.replaceChildren();

  if (passkeys.length === 0) {
    const empty = document.createElement("p");
    empty.className = "passkey-empty";
    empty.textContent = "No passkeys registered.";
    passkeyList.append(empty);
    passkeySelect.disabled = true;
    passkeyDeleteForm.querySelector("button").disabled = true;
    return;
  }

  const list = document.createElement("ul");
  list.className = "passkey-items";

  for (const passkey of passkeys) {
    const item = document.createElement("li");
    const name = document.createElement("span");
    const createdAt = document.createElement("time");
    const option = document.createElement("option");

    name.textContent = passkey.name;
    createdAt.dateTime = new Date(passkey.createdAt).toISOString();
    createdAt.textContent = new Date(passkey.createdAt).toLocaleString();
    item.append(name, createdAt);
    list.append(item);

    option.value = passkey.credentialId;
    option.textContent = passkey.name;
    passkeySelect.append(option);
  }

  passkeyList.append(list);
  passkeySelect.disabled = false;
  passkeyDeleteForm.querySelector("button").disabled = false;
}

function statusText(value) {
  if (value.signedIn === false) {
    return "";
  }

  if (value.error) {
    return value.error;
  }

  if (value.message) {
    return value.message;
  }

  if (value.user) {
    return "";
  }

  if (value.ok) {
    return "Done";
  }

  return "";
}

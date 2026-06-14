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
const emailUpdateVerifyForm = document.querySelector("#email-update-verify-form");
const emailUpdateStartForm = document.querySelector("#email-update-start-form");
const emailUpdateFinishForm = document.querySelector("#email-update-finish-form");
const accountDeleteVerifyForm = document.querySelector("#account-delete-verify-form");
const accountDeleteForm = document.querySelector("#account-delete-form");

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

async function refreshSession() {
  const response = await fetch("/me", {
    credentials: "same-origin"
  });
  const body = await response.json();

  render(response.ok ? body : { signedIn: false, ...body });
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

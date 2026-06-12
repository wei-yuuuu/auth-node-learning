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

signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await postJson("/signup", formJson(signupForm));
  signupForm.reset();
  await refreshSession();
});

signinForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await postJson("/signin", formJson(signinForm));
  signinForm.reset();
  await refreshSession();
});

verifyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await postJson("/verify-email", formJson(verifyForm));
  verifyForm.reset();
  await refreshSession();
});

passwordChangeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = formJson(passwordChangeForm);

  await postJson("/password/verify", {
    password: data.currentPassword
  });
  await postJson("/password/update", {
    password: data.newPassword,
    signOutOtherDevices: data.signOutOtherDevices
  });
  passwordChangeForm.reset();
  await refreshSession();
});

passwordResetStartForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await postJson("/password-reset/start", formJson(passwordResetStartForm));
});

passwordResetFinishForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await postJson("/password-reset/finish", formJson(passwordResetFinishForm));
  passwordResetFinishForm.reset();
});

emailUpdateVerifyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await postJson("/email-update/verify", formJson(emailUpdateVerifyForm));
  emailUpdateVerifyForm.reset();
});

emailUpdateStartForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await postJson("/email-update/start", formJson(emailUpdateStartForm));
});

emailUpdateFinishForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await postJson("/email-update/finish", formJson(emailUpdateFinishForm));
  emailUpdateFinishForm.reset();
  await refreshSession();
});

document.querySelector("#resend-button").addEventListener("click", async () => {
  await postJson("/verify-email/resend", {});
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

async function postJson(path, body) {
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
    clearAccount: path === "/signout" || path === "/sessions/signout-all"
  });
  return responseBody;
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

function render(value, { clearAccount = false } = {}) {
  if (clearAccount || value.signedIn === false || Object.hasOwn(value, "user")) {
    renderAccount(value.user);
  }

  const text = clearAccount && value.ok ? "" : statusText(value);

  notice.textContent = text;
  notice.hidden = text === "";
  notice.dataset.tone = value.error ? "error" : "info";
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

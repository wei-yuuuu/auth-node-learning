const output = document.querySelector("#output");
const signupForm = document.querySelector("#signup-form");
const signinForm = document.querySelector("#signin-form");
const verifyForm = document.querySelector("#verify-form");
const passwordChangeForm = document.querySelector("#password-change-form");
const passwordResetStartForm = document.querySelector("#password-reset-start-form");
const passwordResetFinishForm = document.querySelector("#password-reset-finish-form");

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

document.querySelector("#refresh-button").addEventListener("click", refreshSession);
document.querySelector("#resend-button").addEventListener("click", async () => {
  await postJson("/verify-email/resend", {});
  await refreshSession();
});
document.querySelector("#signout-button").addEventListener("click", async () => {
  await postJson("/signout", {});
  await refreshSession();
});
document.querySelector("#signout-all-button").addEventListener("click", async () => {
  await postJson("/sessions/signout-all", {});
  await refreshSession();
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
      "content-type": "application/json"
    },
    credentials: "same-origin",
    body: JSON.stringify(body)
  });
  const responseBody = await response.json();

  render(responseBody);
  return responseBody;
}

function formJson(form) {
  const data = Object.fromEntries(new FormData(form));

  for (const checkbox of form.querySelectorAll('input[type="checkbox"]')) {
    data[checkbox.name] = checkbox.checked;
  }

  return data;
}

function render(value) {
  output.textContent = JSON.stringify(value, null, 2);
}

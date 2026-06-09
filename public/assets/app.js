const output = document.querySelector("#output");
const signupForm = document.querySelector("#signup-form");
const signinForm = document.querySelector("#signin-form");
const verifyForm = document.querySelector("#verify-form");

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
  return Object.fromEntries(new FormData(form));
}

function render(value) {
  output.textContent = JSON.stringify(value, null, 2);
}

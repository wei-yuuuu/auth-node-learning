const MAX_EMAIL_LENGTH = 100;
const EMAIL_USERNAME_PATTERN = /^[a-z0-9.+_-]+$/;
const EMAIL_DOMAIN_PATTERN = /^[a-z0-9.-]+$/;

export function normalizeEmail(email) {
  if (typeof email !== "string") {
    return "";
  }

  return email.trim().toLowerCase();
}

export function validateEmail(email) {
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail) {
    return "Email address is required.";
  }

  if (normalizedEmail.length > MAX_EMAIL_LENGTH) {
    return `Email address must be at most ${MAX_EMAIL_LENGTH} characters.`;
  }

  const parts = normalizedEmail.split("@");

  if (parts.length !== 2) {
    return 'Email address must contain exactly one "@".';
  }

  const [username, domain] = parts;

  if (!username || !domain) {
    return "Email username and domain are required.";
  }

  if (!EMAIL_USERNAME_PATTERN.test(username)) {
    return "Email username can only use lowercase letters, numbers, periods, plus signs, underscores, and hyphens.";
  }

  if (!domain.includes(".")) {
    return 'Email domain must contain at least one ".".';
  }

  if (!EMAIL_DOMAIN_PATTERN.test(domain)) {
    return "Email domain can only use lowercase letters, numbers, hyphens, and periods.";
  }

  return null;
}

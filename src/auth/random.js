import { randomBytes } from "node:crypto";

const EMAIL_SIGNIN_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function randomBase64Url(byteLength) {
  return randomBytes(byteLength).toString("base64url");
}

export function randomSessionId() {
  // The ID is not treated as a secret, but it should still be unguessable.
  return randomBase64Url(16);
}

export function randomSessionSecret() {
  // Pilcrow recommends a 32-byte session secret hashed with SHA-256.
  return randomBytes(32);
}

export function generateUnbiasedEightDigitCode() {
  while (true) {
    const bytes = randomBytes(4);
    // `readUInt32BE()` reads 4 random bytes as an unsigned 32-bit big-endian
    // integer. `>>> 5` keeps the top 27 random bits, making the range small
    // enough to reject values above 99,999,999 without modulo bias.
    const value = bytes.readUInt32BE() >>> 5;

    if (value < 100_000_000) {
      return value.toString().padStart(8, "0");
    }
  }
}

export function validateEightDigitCode(code) {
  if (typeof code !== "string") {
    return "Code is required.";
  }

  if (!/^\d{8}$/.test(code)) {
    return "Code must be an 8-digit number.";
  }

  return null;
}

export function generateEmailSigninCode() {
  const bytes = randomBytes(8);

  // A 32-character alphabet maps exactly to the lower 5 random bits. Eight
  // characters therefore carry 40 bits of entropy without modulo bias.
  return Array.from(bytes, (byte) => EMAIL_SIGNIN_CODE_ALPHABET[byte & 0b1_1111]).join("");
}

export function validateEmailSigninCode(code) {
  if (typeof code !== "string") {
    return "Sign-in code is required.";
  }

  if (!/^[A-HJ-NP-Z2-9]{8}$/.test(code)) {
    return "Sign-in code must use 8 uppercase letters or numbers.";
  }

  return null;
}

export function normalizeEmailSigninCode(code) {
  if (typeof code === "string") {
    return code.replaceAll(" ", "").replaceAll("-", "").toUpperCase();
  }

  return code;
}

export function formatEmailSigninCode(code) {
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

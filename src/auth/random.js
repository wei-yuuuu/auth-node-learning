import { randomBytes } from "node:crypto";

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

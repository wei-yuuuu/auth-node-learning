import { hashArgon2id, verifyArgon2id } from "./argon2.js";

const MIN_PASSWORD_LENGTH = 10;
const MAX_PASSWORD_LENGTH = 100;
const ARGON2_MEMORY_KIB = 19 * 1024;
const ARGON2_PASSES = 3;
const ARGON2_PARALLELISM = 1;
const ARGON2_TAG_LENGTH = 32;
const HASH_FORMAT = "node-argon2id";
const ARGON2_PARAMETERS = {
  memory: ARGON2_MEMORY_KIB,
  passes: ARGON2_PASSES,
  parallelism: ARGON2_PARALLELISM,
  tagLength: ARGON2_TAG_LENGTH
};

export function validatePassword(password) {
  if (typeof password !== "string") {
    return "Password is required.";
  }

  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  }

  if (password.length > MAX_PASSWORD_LENGTH) {
    return `Password must be at most ${MAX_PASSWORD_LENGTH} characters.`;
  }

  if (password.startsWith(" ") || password.endsWith(" ")) {
    return "Password cannot start or end with a space.";
  }

  for (const character of password) {
    const codePoint = character.codePointAt(0);

    if (codePoint < 0x20 || codePoint > 0x7e) {
      return "Password must use printable ASCII characters.";
    }
  }

  return null;
}

export async function hashPassword(password) {
  const validationError = validatePassword(password);

  if (validationError) {
    throw new Error(validationError);
  }

  // Node's native Argon2 API returns a raw derived key, so the helper stores
  // the parameters beside the salt and hash for future verification.
  return hashArgon2id(password, {
    format: HASH_FORMAT,
    parameters: ARGON2_PARAMETERS
  });
}

export async function verifyPassword(hash, password) {
  return verifyArgon2id(hash, password, { format: HASH_FORMAT });
}

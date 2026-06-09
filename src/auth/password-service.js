import { argon2, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { Semaphore } from "./semaphore.js";

const MIN_PASSWORD_LENGTH = 10;
const MAX_PASSWORD_LENGTH = 100;
const ARGON2_ALGORITHM = "argon2id";
const ARGON2_MEMORY_KIB = 19 * 1024;
const ARGON2_PASSES = 3;
const ARGON2_PARALLELISM = 1;
const ARGON2_TAG_LENGTH = 32;
const ARGON2_SALT_LENGTH = 16;
const HASH_FORMAT = "node-argon2id";
const HASH_VERSION = "1";

const passwordHashSemaphore = new Semaphore(2);
const argon2Async = promisify(argon2);

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

  const salt = randomBytes(ARGON2_SALT_LENGTH);
  const parameters = {
    memory: ARGON2_MEMORY_KIB,
    passes: ARGON2_PASSES,
    parallelism: ARGON2_PARALLELISM,
    tagLength: ARGON2_TAG_LENGTH
  };
  const derivedKey = await derivePasswordKey(password, salt, parameters);

  // Node's native Argon2 API returns a raw derived key, so this project stores
  // the parameters beside the salt and hash to make future verification possible.
  return [
    HASH_FORMAT,
    `v=${HASH_VERSION}`,
    encodeArgon2Parameters(parameters),
    salt.toString("base64url"),
    derivedKey.toString("base64url")
  ].join("$");
}

export async function verifyPassword(hash, password) {
  const parsedHash = parsePasswordHash(hash);

  if (!parsedHash) {
    return false;
  }

  const derivedKey = await derivePasswordKey(password, parsedHash.salt, parsedHash.parameters);

  if (derivedKey.length !== parsedHash.derivedKey.length) {
    return false;
  }

  return timingSafeEqual(derivedKey, parsedHash.derivedKey);
}

function derivePasswordKey(password, salt, parameters) {
  return passwordHashSemaphore.run(() =>
    argon2Async(ARGON2_ALGORITHM, {
      message: password,
      nonce: salt,
      memory: parameters.memory,
      passes: parameters.passes,
      parallelism: parameters.parallelism,
      tagLength: parameters.tagLength
    })
  );
}

function parsePasswordHash(hash) {
  if (typeof hash !== "string") {
    return null;
  }

  const [format, version, encodedParameters, encodedSalt, encodedDerivedKey, extra] = hash.split("$");

  if (
    format !== HASH_FORMAT ||
    version !== `v=${HASH_VERSION}` ||
    !encodedParameters ||
    !encodedSalt ||
    !encodedDerivedKey ||
    extra !== undefined
  ) {
    return null;
  }

  const parameters = parseArgon2Parameters(encodedParameters);

  if (!parameters) {
    return null;
  }

  try {
    return {
      parameters,
      salt: Buffer.from(encodedSalt, "base64url"),
      derivedKey: Buffer.from(encodedDerivedKey, "base64url")
    };
  } catch {
    return null;
  }
}

function encodeArgon2Parameters(parameters) {
  return [
    `m=${parameters.memory}`,
    `t=${parameters.passes}`,
    `p=${parameters.parallelism}`,
    `l=${parameters.tagLength}`
  ].join(",");
}

function parseArgon2Parameters(encodedParameters) {
  const values = Object.fromEntries(
    encodedParameters.split(",").map((pair) => {
      const [key, value] = pair.split("=");
      return [key, Number.parseInt(value, 10)];
    })
  );

  if (!values.m || !values.t || !values.p || !values.l) {
    return null;
  }

  return {
    memory: values.m,
    passes: values.t,
    parallelism: values.p,
    tagLength: values.l
  };
}

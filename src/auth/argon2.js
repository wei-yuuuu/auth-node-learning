import { argon2, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { Semaphore } from "./semaphore.js";

const ARGON2_ALGORITHM = "argon2id";
const ARGON2_SALT_LENGTH = 16;
const HASH_VERSION = "1";
const argon2Async = promisify(argon2);

// Keep expensive password and email-code derivations from saturating the event loop.
const argon2Semaphore = new Semaphore(2);

export async function hashArgon2id(secret, { format, parameters }) {
  const salt = randomBytes(ARGON2_SALT_LENGTH);
  const derivedKey = await deriveArgon2idKey(secret, salt, parameters);

  return [
    format,
    `v=${HASH_VERSION}`,
    encodeParameters(parameters),
    salt.toString("base64url"),
    derivedKey.toString("base64url")
  ].join("$");
}

export async function verifyArgon2id(secretHash, secret, { format }) {
  const parsed = parseArgon2idHash(secretHash, format);

  if (!parsed) {
    return false;
  }

  const derivedKey = await deriveArgon2idKey(secret, parsed.salt, parsed.parameters);

  return (
    derivedKey.length === parsed.derivedKey.length &&
    timingSafeEqual(derivedKey, parsed.derivedKey)
  );
}

async function deriveArgon2idKey(secret, salt, parameters) {
  return argon2Semaphore.run(() =>
    argon2Async(ARGON2_ALGORITHM, {
      message: secret,
      nonce: salt,
      memory: parameters.memory,
      passes: parameters.passes,
      parallelism: parameters.parallelism,
      tagLength: parameters.tagLength
    })
  );
}

function encodeParameters(parameters) {
  return [
    `m=${parameters.memory}`,
    `t=${parameters.passes}`,
    `p=${parameters.parallelism}`,
    `l=${parameters.tagLength}`
  ].join(",");
}

function parseArgon2idHash(hash, format) {
  if (typeof hash !== "string") {
    return null;
  }

  const [storedFormat, version, encodedParameters, encodedSalt, encodedDerivedKey, extra] = hash.split("$");

  if (
    storedFormat !== format ||
    version !== `v=${HASH_VERSION}` ||
    !encodedParameters ||
    !encodedSalt ||
    !encodedDerivedKey ||
    extra !== undefined
  ) {
    return null;
  }

  const parameters = parseParameters(encodedParameters);

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

function parseParameters(encodedParameters) {
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

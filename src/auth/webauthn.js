import { createPublicKey, verify } from "node:crypto";
import { sha256, sha256Hex } from "./hash.js";
import { randomBase64Url } from "./random.js";

export const EMPTY_REGISTRATION_CHALLENGE = "";
export const PASSKEY_CHALLENGE_TTL_MS = 1000 * 60 * 5;
export const PASSKEY_LIMIT = 10;
export const PASSKEY_PUB_KEY_CRED_PARAMS = [
  // COSE algorithm IDs used by WebAuthn. Pilcrow notes:
  // -7 (ES256): ECDSA with SHA-256. WebAuthn requires P-256;
  //     do not use -9 (ESP256).
  // -257 (RS256): RSASSA-PKCS1-v1_5 with SHA-256.
  // -8 (EdDSA): Ed25519 public keys/signatures; do not use -19.
  { type: "public-key", alg: -7 },
  { type: "public-key", alg: -257 },
  { type: "public-key", alg: -8 }
];

const SUPPORTED_ALGORITHMS = new Set(PASSKEY_PUB_KEY_CRED_PARAMS.map((param) => param.alg));
// Byte 32 of authenticatorData is the flags byte:
// bit 0 = user presence, bit 2 = user verification,
// bit 3 = backup eligible, bit 4 = currently backed up,
// bit 6 = attested credential data included, bit 7 = extensions included.
const FLAG_USER_PRESENT = 0b0000_0001;
const FLAG_USER_VERIFIED = 0b0000_0100;
const FLAG_BACKUP_ELIGIBLE = 0b0000_1000;
const FLAG_BACKED_UP = 0b0001_0000;
const FLAG_ATTESTED_CREDENTIAL_DATA = 0b0100_0000;
const MAX_CREDENTIAL_ID_BYTES = 1023;

export class WebAuthnError extends Error {
  constructor(message) {
    super(message);
    this.name = "WebAuthnError";
  }
}

export function createPasskeyChallenge() {
  return randomBase64Url(32);
}

export function hashPasskeyChallenge(challenge) {
  // Challenge values are not passwords, so the shared SHA-256 helper is
  // appropriate for storing an opaque lookup key.
  return sha256Hex(challenge);
}

export function buildPasskeyCreationOptions({ rpId, user, existingPasskeys }) {
  return {
    challenge: EMPTY_REGISTRATION_CHALLENGE,
    rpId,
    user: {
      id: Buffer.from(user.id).toString("base64url"),
      name: user.email,
      displayName: user.email
    },
    pubKeyCredParams: PASSKEY_PUB_KEY_CRED_PARAMS,
    excludeCredentials: existingPasskeys.map((passkey) => ({
      type: "public-key",
      id: passkey.credentialId
    })),
    authenticatorSelection: {
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required"
    },
    attestation: "none",
    extensions: {
      credentialProtectionPolicy: "userVerificationRequired",
      enforceCredentialProtectionPolicy: false
    }
  };
}

export function buildPasskeyAuthenticationOptions({ challenge, rpId }) {
  return {
    challenge,
    rpId,
    userVerification: "required"
  };
}

export function validatePasskeyRegistration({
  credential,
  expectedOrigin,
  expectedRpId
}) {
  const rawId = decodeBase64Url(credential?.rawId, "Credential ID");
  const clientDataJSON = decodeBase64Url(credential?.response?.clientDataJSON, "Client data");
  const authenticatorData = decodeBase64Url(
    credential?.response?.authenticatorData,
    "Authenticator data"
  );
  const publicKeyDer = decodeBase64Url(credential?.response?.publicKey, "Public key");
  const algorithm = credential?.response?.publicKeyAlgorithm;

  if (rawId.length < 1 || rawId.length > MAX_CREDENTIAL_ID_BYTES) {
    throw new WebAuthnError("Passkey credential ID length is invalid.");
  }

  validateClientData({
    clientDataJSON,
    expectedType: "webauthn.create",
    expectedChallenge: EMPTY_REGISTRATION_CHALLENGE,
    expectedOrigin
  });

  const parsedAuthenticatorData = validateAuthenticatorData({
    authenticatorData,
    expectedRpId,
    requireAttestedCredentialData: true
  });

  if (!parsedAuthenticatorData.attestedCredentialId.equals(rawId)) {
    throw new WebAuthnError("Passkey credential ID does not match authenticator data.");
  }

  validatePasskeyPublicKey(publicKeyDer, algorithm);

  return {
    credentialId: rawId.toString("base64url"),
    publicKeyDer,
    algorithm,
    authenticatorId: parsedAuthenticatorData.aaguid,
    signCount: parsedAuthenticatorData.signCount
  };
}

export function getClientDataChallenge(credential) {
  const clientDataJSON = decodeBase64Url(credential?.response?.clientDataJSON, "Client data");
  const clientData = parseClientData(clientDataJSON);

  if (typeof clientData.challenge !== "string") {
    throw new WebAuthnError("Client data challenge is invalid.");
  }

  return clientData.challenge;
}

export function verifyPasskeyAuthentication({
  credential,
  storedPasskey,
  expectedChallenge,
  expectedOrigin,
  expectedRpId
}) {
  const rawId = decodeBase64Url(credential?.rawId, "Credential ID");
  const clientDataJSON = decodeBase64Url(credential?.response?.clientDataJSON, "Client data");
  const authenticatorData = decodeBase64Url(
    credential?.response?.authenticatorData,
    "Authenticator data"
  );
  const signature = decodeBase64Url(credential?.response?.signature, "Signature");
  const userHandle = credential?.response?.userHandle === null
    ? null
    : credential?.response?.userHandle;

  if (rawId.toString("base64url") !== storedPasskey.credentialId) {
    throw new WebAuthnError("Passkey credential ID does not match.");
  }

  validateClientData({
    clientDataJSON,
    expectedType: "webauthn.get",
    expectedChallenge,
    expectedOrigin
  });

  const parsedAuthenticatorData = validateAuthenticatorData({
    authenticatorData,
    expectedRpId,
    requireAttestedCredentialData: false
  });

  if (typeof userHandle === "string" && userHandle !== "") {
    const decodedUserHandle = decodeBase64Url(userHandle, "User handle").toString();

    if (decodedUserHandle !== storedPasskey.userId) {
      throw new WebAuthnError("Passkey user handle does not match.");
    }
  }

  const publicKey = validatePasskeyPublicKey(
    storedPasskey.publicKeyDer,
    storedPasskey.algorithm
  );
  // Pilcrow: hash the client data JSON with SHA-256, then concatenate the
  // authenticator data first and the client data hash second. The authenticator
  // signature is verified against that signed message.
  const clientDataHash = sha256(clientDataJSON);
  const signedMessage = Buffer.concat([authenticatorData, clientDataHash]);
  const signatureAlgorithm = storedPasskey.algorithm === -8 ? null : "sha256";

  if (!verify(signatureAlgorithm, signedMessage, publicKey, signature)) {
    throw new WebAuthnError("Passkey signature is invalid.");
  }

  return {
    signCount: parsedAuthenticatorData.signCount
  };
}

export function validatePasskeyName(name) {
  if (typeof name !== "string") {
    return "Passkey name is required.";
  }

  if (name.length < 1 || name.length > 60) {
    return "Passkey name must be 1 to 60 characters.";
  }

  return null;
}

function validateClientData({
  clientDataJSON,
  expectedType,
  expectedChallenge,
  expectedOrigin
}) {
  const clientData = parseClientData(clientDataJSON);

  if (clientData.type !== expectedType) {
    throw new WebAuthnError("Client data type is invalid.");
  }

  if (clientData.challenge !== expectedChallenge) {
    throw new WebAuthnError("Client data challenge is invalid.");
  }

  if (clientData.origin !== expectedOrigin) {
    throw new WebAuthnError("Client data origin is invalid.");
  }

  if (clientData.crossOrigin === true) {
    throw new WebAuthnError("Cross-origin WebAuthn requests are not allowed.");
  }
}

function parseClientData(clientDataJSON) {
  try {
    return JSON.parse(clientDataJSON.toString("utf8"));
  } catch {
    throw new WebAuthnError("Client data must be valid JSON.");
  }
}

function validateAuthenticatorData({
  authenticatorData,
  expectedRpId,
  requireAttestedCredentialData
}) {
  if (authenticatorData.length < 37) {
    throw new WebAuthnError("Authenticator data is too short.");
  }

  const rpIdHash = authenticatorData.subarray(0, 32);
  const expectedRpIdHash = sha256(expectedRpId);

  if (!rpIdHash.equals(expectedRpIdHash)) {
    throw new WebAuthnError("Relying party ID hash is invalid.");
  }

  const flags = authenticatorData[32];

  if ((flags & FLAG_USER_PRESENT) === 0) {
    throw new WebAuthnError("Passkey user presence is required.");
  }

  if ((flags & FLAG_USER_VERIFIED) === 0) {
    throw new WebAuthnError("Passkey user verification is required.");
  }

  if ((flags & FLAG_BACKED_UP) !== 0 && (flags & FLAG_BACKUP_ELIGIBLE) === 0) {
    throw new WebAuthnError("Passkey backup flags are invalid.");
  }

  const hasAttestedCredentialData = (flags & FLAG_ATTESTED_CREDENTIAL_DATA) !== 0;

  if (requireAttestedCredentialData && !hasAttestedCredentialData) {
    throw new WebAuthnError("Passkey registration is missing attested credential data.");
  }

  if (!requireAttestedCredentialData && hasAttestedCredentialData) {
    throw new WebAuthnError("Passkey authentication must not include attested credential data.");
  }

  // WebAuthn stores the signature counter as four big-endian bytes immediately
  // after the flags byte. `readUInt32BE(33)` reads bytes 33, 34, 35, and 36.
  const signCount = authenticatorData.readUInt32BE(33);

  if (!hasAttestedCredentialData) {
    return { signCount };
  }

  if (authenticatorData.length < 55) {
    throw new WebAuthnError("Attested credential data is too short.");
  }

  const aaguid = authenticatorData.subarray(37, 53).toString("hex");
  const credentialIdLength = authenticatorData.readUInt16BE(53);
  const credentialIdStart = 55;
  const credentialIdEnd = credentialIdStart + credentialIdLength;

  if (
    credentialIdLength < 1 ||
    credentialIdLength > MAX_CREDENTIAL_ID_BYTES ||
    authenticatorData.length < credentialIdEnd
  ) {
    throw new WebAuthnError("Attested credential ID length is invalid.");
  }

  if (authenticatorData.length === credentialIdEnd) {
    throw new WebAuthnError("Attested credential public key is missing.");
  }

  return {
    signCount,
    aaguid,
    attestedCredentialId: authenticatorData.subarray(credentialIdStart, credentialIdEnd)
  };
}

function validatePasskeyPublicKey(publicKeyDer, algorithm) {
  if (!SUPPORTED_ALGORITHMS.has(algorithm)) {
    throw new WebAuthnError("Passkey signature algorithm is not supported.");
  }

  let publicKey;

  try {
    // The browser sent DER SubjectPublicKeyInfo bytes from getPublicKey(), so
    // the server validates a normal public key instead of parsing COSE labels
    // like 1 (kty), 3 (alg), -1 (curve), -2 (x), and -3 (y).
    publicKey = createPublicKey({
      key: publicKeyDer,
      format: "der",
      type: "spki"
    });
  } catch {
    throw new WebAuthnError("Passkey public key is invalid.");
  }

  const details = publicKey.asymmetricKeyDetails ?? {};

  if (algorithm === -7) {
    if (publicKey.asymmetricKeyType !== "ec" || details.namedCurve !== "prime256v1") {
      throw new WebAuthnError("ES256 passkeys must use the P-256 curve.");
    }
  } else if (algorithm === -257) {
    if (
      publicKey.asymmetricKeyType !== "rsa" ||
      details.modulusLength < 2048 ||
      details.publicExponent !== 65537n
    ) {
      throw new WebAuthnError("RS256 passkeys must use an RSA key of at least 2048 bits.");
    }
  } else if (algorithm === -8 && publicKey.asymmetricKeyType !== "ed25519") {
    throw new WebAuthnError("EdDSA passkeys must use Ed25519.");
  }

  return publicKey;
}

function decodeBase64Url(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new WebAuthnError(`${label} must be base64url-encoded.`);
  }

  return Buffer.from(value, "base64url");
}

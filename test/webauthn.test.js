import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { sha256 } from "../src/auth/hash.js";
import {
  buildPasskeyAuthenticationOptions,
  buildPasskeyCreationOptions,
  createPasskeyChallenge,
  getClientDataChallenge,
  validatePasskeyRegistration,
  verifyPasskeyAuthentication
} from "../src/auth/webauthn.js";

const origin = "http://localhost:3000";
const rpId = "localhost";

test("buildPasskeyCreationOptions prepares browser WebAuthn options", () => {
  const options = buildPasskeyCreationOptions({
    rpId,
    user: {
      id: "user-1",
      email: "demo@example.com"
    },
    existingPasskeys: [
      {
        credentialId: "credential-1"
      }
    ]
  });

  assert.equal(options.rpId, rpId);
  assert.equal(options.challenge, "");
  assert.equal(options.user.name, "demo@example.com");
  assert.equal(options.user.displayName, "demo@example.com");
  assert.equal(options.authenticatorSelection.userVerification, "required");
  assert.equal(options.attestation, "none");
  assert.deepEqual(options.excludeCredentials, [
    {
      type: "public-key",
      id: "credential-1"
    }
  ]);
});

test("buildPasskeyAuthenticationOptions includes the relying party ID", () => {
  const challenge = createPasskeyChallenge();
  const options = buildPasskeyAuthenticationOptions({ challenge, rpId });

  assert.equal(options.challenge, challenge);
  assert.equal(options.rpId, rpId);
  assert.equal(options.userVerification, "required");
});

test("validatePasskeyRegistration accepts an ES256 discoverable credential", () => {
  const credentialId = Buffer.from("credential-1");
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const credential = {
    rawId: encode(credentialId),
    response: {
      clientDataJSON: encodeClientData({
        type: "webauthn.create",
        challenge: "",
        origin
      }),
      authenticatorData: encode(registrationAuthenticatorData({ credentialId })),
      publicKey: encode(publicKeyDer),
      publicKeyAlgorithm: -7
    }
  };

  const result = validatePasskeyRegistration({
    credential,
    expectedOrigin: origin,
    expectedRpId: rpId
  });

  assert.equal(result.credentialId, encode(credentialId));
  assert.equal(result.algorithm, -7);
  assert.equal(result.authenticatorId, "00000000000000000000000000000000");
  assert.deepEqual(result.publicKeyDer, publicKeyDer);
});

test("verifyPasskeyAuthentication validates challenge, flags, user handle, and signature", () => {
  const credentialId = Buffer.from("credential-1");
  const challenge = createPasskeyChallenge();
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const clientDataJSON = clientDataBytes({
    type: "webauthn.get",
    challenge,
    origin
  });
  const authenticatorData = authenticationAuthenticatorData({ signCount: 7 });
  const signedMessage = Buffer.concat([
    authenticatorData,
    sha256(clientDataJSON)
  ]);
  const credential = {
    rawId: encode(credentialId),
    response: {
      authenticatorData: encode(authenticatorData),
      clientDataJSON: encode(clientDataJSON),
      signature: encode(sign("sha256", signedMessage, privateKey)),
      userHandle: encode(Buffer.from("user-1"))
    }
  };

  assert.equal(getClientDataChallenge(credential), challenge);

  const result = verifyPasskeyAuthentication({
    credential,
    storedPasskey: {
      credentialId: encode(credentialId),
      userId: "user-1",
      publicKeyDer,
      algorithm: -7,
      signCount: 0
    },
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRpId: rpId
  });

  assert.equal(result.signCount, 7);
});

test("verifyPasskeyAuthentication rejects missing user verification", () => {
  const credentialId = Buffer.from("credential-1");
  const challenge = createPasskeyChallenge();
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const clientDataJSON = clientDataBytes({
    type: "webauthn.get",
    challenge,
    origin
  });
  const authenticatorData = authenticationAuthenticatorData({
    flags: 0b0000_0001,
    signCount: 1
  });
  const signedMessage = Buffer.concat([
    authenticatorData,
    sha256(clientDataJSON)
  ]);

  assert.throws(
    () => verifyPasskeyAuthentication({
      credential: {
        rawId: encode(credentialId),
        response: {
          authenticatorData: encode(authenticatorData),
          clientDataJSON: encode(clientDataJSON),
          signature: encode(sign("sha256", signedMessage, privateKey)),
          userHandle: encode(Buffer.from("user-1"))
        }
      },
      storedPasskey: {
        credentialId: encode(credentialId),
        userId: "user-1",
        publicKeyDer,
        algorithm: -7,
        signCount: 0
      },
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRpId: rpId
    }),
    /Passkey user verification is required\./
  );
});

function registrationAuthenticatorData({ credentialId }) {
  const flags = Buffer.from([0b0100_0101]);
  const signCount = Buffer.alloc(4);
  const aaguid = Buffer.alloc(16);
  const credentialIdLength = Buffer.alloc(2);
  const cosePublicKeyPlaceholder = Buffer.from([0xa0]);

  signCount.writeUInt32BE(1);
  credentialIdLength.writeUInt16BE(credentialId.length);

  return Buffer.concat([
    rpIdHash(),
    flags,
    signCount,
    aaguid,
    credentialIdLength,
    credentialId,
    cosePublicKeyPlaceholder
  ]);
}

function authenticationAuthenticatorData({
  flags = 0b0000_0101,
  signCount
}) {
  const counter = Buffer.alloc(4);

  counter.writeUInt32BE(signCount);
  return Buffer.concat([rpIdHash(), Buffer.from([flags]), counter]);
}

function rpIdHash() {
  return sha256(rpId);
}

function encodeClientData(data) {
  return encode(clientDataBytes(data));
}

function clientDataBytes(data) {
  return Buffer.from(JSON.stringify(data));
}

function encode(buffer) {
  return Buffer.from(buffer).toString("base64url");
}

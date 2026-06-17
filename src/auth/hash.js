import * as crypto from "node:crypto";

export function sha256(bufferOrString) {
  // `crypto.hash()` is the modern one-shot hash API in Node 24. It is clearer
  // than manually creating a Hash object for small complete inputs like tokens.
  return crypto.hash("sha256", bufferOrString, "buffer");
}

export function sha256Hex(bufferOrString) {
  return sha256(bufferOrString).toString("hex");
}

export function timingSafeEqualHex(leftHex, rightHex) {
  const left = Buffer.from(leftHex, "hex");
  const right = Buffer.from(rightHex, "hex");

  if (left.length !== right.length) {
    return false;
  }

  // Token secrets should not be compared with `===`: byte-by-byte timing can
  // reveal how much of the secret matched. `timingSafeEqual()` keeps valid and
  // invalid same-length hashes on the same comparison path.
  return crypto.timingSafeEqual(left, right);
}

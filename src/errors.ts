/**
 * Exception hierarchy, mirroring the Python package.
 *
 * Construction and decoding throw. Verification never does: `verify*` returns a
 * boolean and `verifyBallot` returns a verdict, so adversarial input can never
 * turn into an exception a caller forgets to catch.
 */

export class ZKTallyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Invalid input to a prove/encrypt/sign call. */
export class ValidationError extends ZKTallyError {}

/** Plaintext outside `[0, N)`, or a vote outside the permitted set. */
export class InvalidPlaintextError extends ValidationError {}

/** Ciphertext outside `Z*_{N^2}`. */
export class InvalidCiphertextError extends ValidationError {}

/** Ring is too small, unordered, contains duplicates, or omits the signer. */
export class InvalidRingError extends ValidationError {}

/** Malformed wire data. */
export class DecodingError extends ZKTallyError {}

/** `specVersion` names a wire format this build does not implement. */
export class UnsupportedVersionError extends DecodingError {}

/** Byte string does not decode to a valid curve point. */
export class InvalidPointError extends DecodingError {}

/** A threshold partial decryption failed its correctness proof. */
export class InvalidShareError extends ZKTallyError {
  readonly authority: number;

  constructor(authority: number, detail = '') {
    super(
      `partial decryption from authority ${authority} is invalid${detail ? `: ${detail}` : ''}`,
    );
    this.authority = authority;
  }
}

/** Impossible parameters, e.g. `bits < 2048` or `t > nAuth`. */
export class ConfigurationError extends ZKTallyError {}

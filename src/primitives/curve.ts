/**
 * secp256k1 group operations and the compressed SEC1 codec.
 *
 * Unlike the Python package -- which vendors the curve to avoid a runtime
 * dependency -- this port delegates to `@noble/curves`. That library is audited,
 * dependency-free, and implements RFC 9380 `hash_to_curve` for secp256k1, which
 * is precisely the primitive whose absence caused break C1. Reimplementing SSWU
 * by hand in a second language would be the single most likely source of silent
 * divergence between the two ports.
 *
 * @remarks
 * Scalar multiplication is not constant-time in any pure-JavaScript
 * implementation. Do not assume side-channel resistance.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';

import { InvalidPointError } from '../errors.js';
import { POINT_BYTES, i2osp, os2ip } from '../serialization/encoding.js';
import { randomBytes } from '../rng.js';

export type Point = InstanceType<typeof secp256k1.Point>;

export const FIELD_PRIME = secp256k1.Point.Fp.ORDER;
export const CURVE_ORDER = secp256k1.Point.Fn.ORDER;
export const CURVE_A = 0n;
export const CURVE_B = 7n;

/** The standard secp256k1 base point. */
export const G: Point = secp256k1.Point.BASE;

/** The group identity. Has no encoding and must never reach the wire. */
export const IDENTITY: Point = secp256k1.Point.ZERO;

export function isOnCurve(x: bigint, y: bigint): boolean {
  if (!(x >= 0n && x < FIELD_PRIME && y >= 0n && y < FIELD_PRIME)) return false;
  return (y * y - x * x * x - CURVE_B) % FIELD_PRIME === 0n;
}

/**
 * Uniform in `[1, q)` from the platform CSPRNG.
 *
 * Rejection sampling over 32 random bytes, matching the Python port exactly so
 * that a shared deterministic source produces identical keys in both.
 */
export function randomScalar(): bigint {
  for (;;) {
    const candidate = os2ip(randomBytes(32));
    if (candidate >= 1n && candidate < CURVE_ORDER) return candidate;
  }
}

/** Compressed SEC1: `0x02`/`0x03` prefix, then `I2OSP(x, 32)`. */
export function encodePoint(point: Point): Uint8Array {
  if (point.is0()) throw new InvalidPointError('the identity has no encoding');
  const affine = point.toAffine();
  const out = new Uint8Array(POINT_BYTES);
  out[0] = affine.y & 1n ? 0x03 : 0x02;
  out.set(i2osp(affine.x, 32), 1);
  return out;
}

/**
 * Decode compressed SEC1, validating everything.
 *
 * Rejects a wrong length, a wrong prefix, `x >= p`, a non-residue (the point is
 * not on the curve), and the identity. The research prototype used a
 * prefix-less 64-byte `x || y` base58 form with no on-curve validation at all.
 */
export function decodePoint(data: Uint8Array): Point {
  if (data.length !== POINT_BYTES) {
    throw new InvalidPointError(`expected ${POINT_BYTES} bytes, got ${data.length}`);
  }
  const prefix = data[0] as number;
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new InvalidPointError(
      `bad SEC1 prefix 0x${prefix.toString(16).padStart(2, '0')}; expected 0x02 or 0x03`,
    );
  }
  if (os2ip(data.subarray(1)) >= FIELD_PRIME) {
    throw new InvalidPointError('x coordinate is not a field element');
  }
  let point: Point;
  try {
    point = secp256k1.Point.fromBytes(data);
  } catch (cause) {
    throw new InvalidPointError(
      `x coordinate is not on the curve: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  if (point.is0()) throw new InvalidPointError('the identity has no encoding');
  return point;
}

/**
 * `q * P == identity` and `P != identity`.
 *
 * secp256k1 has cofactor 1, so any valid non-identity point is already in the
 * prime-order subgroup; the check is kept explicit because key images arrive
 * from untrusted input and the specification requires it.
 */
export function isInPrimeOrderSubgroup(point: Point): boolean {
  if (point.is0()) return false;
  try {
    point.assertValidity();
  } catch {
    return false;
  }
  return point.isTorsionFree();
}

/** Scalar multiplication that tolerates a zero scalar, yielding the identity. */
export function mul(point: Point, k: bigint): Point {
  const scalar = ((k % CURVE_ORDER) + CURVE_ORDER) % CURVE_ORDER;
  if (scalar === 0n || point.is0()) return IDENTITY;
  return point.multiplyUnsafe(scalar);
}

export function add(a: Point, b: Point): Point {
  return a.add(b);
}

export function pointsEqual(a: Point, b: Point): boolean {
  return a.equals(b);
}

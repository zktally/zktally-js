/**
 * Curve arithmetic, the SEC1 codec, and RFC 9380 hash-to-curve.
 *
 * The point decoder takes bytes straight off the wire, so most of this is about
 * malformed input.
 */

import { describe, expect, it } from 'vitest';

import { DST_H2C } from '../../src/domain.js';
import { InvalidPointError } from '../../src/errors.js';
import {
  CURVE_ORDER,
  FIELD_PRIME,
  G,
  IDENTITY,
  add,
  decodePoint,
  encodePoint,
  isInPrimeOrderSubgroup,
  isOnCurve,
  mul,
  randomScalar,
} from '../../src/primitives/curve.js';
import { hashToCurve } from '../../src/primitives/hashToCurve.js';
import { POINT_BYTES, bytesToHex, i2osp } from '../../src/serialization/encoding.js';

describe('group law', () => {
  it('has the expected order and field', () => {
    expect(FIELD_PRIME.toString(16)).toBe(
      'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
    );
    expect(CURVE_ORDER.toString(16)).toBe(
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
    );
  });

  it('puts the base point on the curve', () => {
    const affine = G.toAffine();
    expect(isOnCurve(affine.x, affine.y)).toBe(true);
  });

  it('treats the identity as the additive unit', () => {
    expect(add(G, IDENTITY).equals(G)).toBe(true);
    expect(mul(G, 0n).is0()).toBe(true);
  });

  it('is associative and distributive over scalars', () => {
    expect(add(mul(G, 3n), mul(G, 4n)).equals(mul(G, 7n))).toBe(true);
    expect(mul(mul(G, 3n), 5n).equals(mul(G, 15n))).toBe(true);
  });

  it('wraps scalars modulo the group order', () => {
    expect(mul(G, CURVE_ORDER).is0()).toBe(true);
    expect(mul(G, CURVE_ORDER + 5n).equals(mul(G, 5n))).toBe(true);
  });
});

describe('SEC1 codec', () => {
  it('round-trips', () => {
    for (const k of [1n, 2n, 12345n, CURVE_ORDER - 1n]) {
      const point = mul(G, k);
      expect(decodePoint(encodePoint(point)).equals(point)).toBe(true);
    }
  });

  it('is 33 bytes with a parity prefix', () => {
    const encoded = encodePoint(G);
    expect(encoded).toHaveLength(POINT_BYTES);
    expect([0x02, 0x03]).toContain(encoded[0]);
  });

  it('gives P and -P different encodings', () => {
    // The x-coordinate alone would collide, which is why the challenge hashes
    // the full compressed form.
    expect(bytesToHex(encodePoint(G))).not.toBe(bytesToHex(encodePoint(G.negate())));
  });

  it('refuses to encode the identity', () => {
    expect(() => encodePoint(IDENTITY)).toThrow(InvalidPointError);
  });

  it('rejects a wrong length', () => {
    expect(() => decodePoint(new Uint8Array(32))).toThrow(InvalidPointError);
    expect(() => decodePoint(new Uint8Array(65))).toThrow(InvalidPointError);
  });

  it('rejects a wrong prefix', () => {
    const bad = encodePoint(G).slice();
    bad[0] = 0x04;
    expect(() => decodePoint(bad)).toThrow(InvalidPointError);
  });

  it('rejects an x coordinate outside the field', () => {
    const bad = new Uint8Array([0x02, ...i2osp(FIELD_PRIME, 32)]);
    expect(() => decodePoint(bad)).toThrow(InvalidPointError);
  });

  it('rejects an x coordinate that is not on the curve', () => {
    // x = 5 makes x^3 + 7 a quadratic non-residue, so no such point exists.
    const bad = new Uint8Array([0x02, ...i2osp(5n, 32)]);
    expect(() => decodePoint(bad)).toThrow(InvalidPointError);
  });

  it('rejects the all-zero encoding', () => {
    expect(() => decodePoint(new Uint8Array(POINT_BYTES))).toThrow(InvalidPointError);
  });
});

describe('subgroup membership', () => {
  it('accepts a valid non-identity point', () => {
    expect(isInPrimeOrderSubgroup(mul(G, 7n))).toBe(true);
  });

  it('rejects the identity', () => {
    expect(isInPrimeOrderSubgroup(IDENTITY)).toBe(false);
  });
});

describe('randomScalar', () => {
  it('stays inside [1, q)', () => {
    for (let i = 0; i < 50; i++) {
      const k = randomScalar();
      expect(k >= 1n && k < CURVE_ORDER).toBe(true);
    }
  });

  it('does not repeat', () => {
    const seen = new Set(Array.from({ length: 50 }, () => randomScalar().toString()));
    expect(seen.size).toBe(50);
  });
});

describe('hashToCurve', () => {
  it('lands on the curve', () => {
    for (const msg of ['', 'abc', 'a'.repeat(200)]) {
      const point = hashToCurve(new TextEncoder().encode(msg), DST_H2C);
      const affine = point.toAffine();
      expect(isOnCurve(affine.x, affine.y)).toBe(true);
      expect(point.is0()).toBe(false);
    }
  });

  it('is deterministic', () => {
    const msg = new TextEncoder().encode('zktally');
    expect(hashToCurve(msg, DST_H2C).equals(hashToCurve(msg, DST_H2C))).toBe(true);
  });

  it('separates domains', () => {
    const msg = new TextEncoder().encode('zktally');
    const other = new TextEncoder().encode('some-other-dst');
    expect(hashToCurve(msg, DST_H2C).equals(hashToCurve(msg, other))).toBe(false);
  });

  it('has no discoverable discrete log relation to G (the C1 property)', () => {
    // The prototype's H_p(P) = SHA256(P)*G made log_G(H_p(P)) public. There is
    // no cheap positive test for "unknown", but the structural giveaway is that
    // small multiples of G never appear as outputs.
    const point = hashToCurve(new TextEncoder().encode('zktally'), DST_H2C);
    for (let k = 1n; k <= 64n; k++) {
      expect(point.equals(mul(G, k))).toBe(false);
    }
  });
});

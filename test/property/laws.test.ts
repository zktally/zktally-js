/**
 * Property-based tests.
 *
 * These check algebraic laws over generated inputs rather than fixed cases, so
 * they explore the edges -- zero, one, `N-1` -- that hand-written examples tend
 * to miss.
 */

import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { gcd, invert, powMod } from '../../src/math.js';
import { CURVE_ORDER, G, add, decodePoint, encodePoint, mul } from '../../src/primitives/curve.js';
import { canonicalRing, lsagSign, lsagVerify, ringHash } from '../../src/primitives/lsag.js';
import { proveBinary, verifyBinary } from '../../src/primitives/nizk.js';
import { aggregate, decrypt, encrypt, encryptWith } from '../../src/primitives/paillier.js';
import { b64uDecode, b64uEncode, i2osp, os2ip } from '../../src/serialization/encoding.js';
import { electionContext } from '../../src/protocol/params.js';
import { binaryParams, makeVoters, ringOf, signerFor, toyKeys } from '../helpers.js';

const [pk, sk] = toyKeys();
const RUNS = 40;

/** A plaintext in `[0, N)`. */
const plaintext = fc.bigInt({ min: 0n, max: pk.n - 1n });
/** A unit in `[1, N)`, which is what Paillier randomness must be. */
const unit = fc
  .bigInt({ min: 1n, max: pk.n - 1n })
  .filter((r) => gcd(r, pk.n) === 1n);

describe('Paillier', () => {
  it('round-trips every plaintext', () => {
    fc.assert(
      fc.property(plaintext, unit, (m, r) => {
        expect(decrypt(encryptWith(m, r, pk), pk, sk)).toBe(m);
      }),
      { numRuns: RUNS },
    );
  });

  it('is additively homomorphic', () => {
    fc.assert(
      fc.property(plaintext, plaintext, unit, unit, (m1, m2, r1, r2) => {
        const c = aggregate([encryptWith(m1, r1, pk), encryptWith(m2, r2, pk)], pk);
        expect(decrypt(c, pk, sk)).toBe((m1 + m2) % pk.n);
      }),
      { numRuns: RUNS },
    );
  });

  it('is randomized: the same plaintext gives different ciphertexts', () => {
    fc.assert(
      fc.property(plaintext, (m) => {
        const [c1] = encrypt(m, pk);
        const [c2] = encrypt(m, pk);
        expect(c1).not.toBe(c2);
        expect(decrypt(c1, pk, sk)).toBe(decrypt(c2, pk, sk));
      }),
      { numRuns: RUNS },
    );
  });

  it('aggregates in any order', () => {
    fc.assert(
      fc.property(fc.array(fc.tuple(plaintext, unit), { minLength: 2, maxLength: 6 }), (pairs) => {
        const cs = pairs.map(([m, r]) => encryptWith(m, r, pk));
        expect(aggregate(cs, pk)).toBe(aggregate([...cs].reverse(), pk));
      }),
      { numRuns: RUNS },
    );
  });
});

describe('modular arithmetic', () => {
  it('inverts every unit', () => {
    fc.assert(
      fc.property(unit, (r) => {
        expect((r * invert(r, pk.n)) % pk.n).toBe(1n);
      }),
      { numRuns: RUNS },
    );
  });

  it('exponentiates consistently with repeated multiplication', () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 2n, max: 1000n }), fc.integer({ min: 0, max: 20 }), (b, e) => {
        let expected = 1n;
        for (let i = 0; i < e; i++) expected = (expected * b) % pk.n;
        expect(powMod(b, BigInt(e), pk.n)).toBe(expected);
      }),
      { numRuns: RUNS },
    );
  });
});

describe('binary proofs', () => {
  const ctx = electionContext(binaryParams(pk, ringOf(makeVoters(3))));

  it('verifies for both votes', () => {
    fc.assert(
      fc.property(fc.constantFrom(0, 1), unit, (v, r) => {
        const c = encryptWith(BigInt(v), r, pk);
        expect(verifyBinary(c, proveBinary(c, r, v, pk, ctx), pk, ctx)).toBe(true);
      }),
      { numRuns: RUNS },
    );
  });

  it('hides the vote: the proof shape is identical either way', () => {
    fc.assert(
      fc.property(unit, unit, (r0, r1) => {
        const p0 = proveBinary(encryptWith(0n, r0, pk), r0, 0, pk, ctx);
        const p1 = proveBinary(encryptWith(1n, r1, pk), r1, 1, pk, ctx);
        expect(Object.keys(p0).sort()).toEqual(Object.keys(p1).sort());
      }),
      { numRuns: 10 },
    );
  });

  it('fails on any mutated field', () => {
    const r = 12345n;
    const c = encryptWith(1n, r, pk);
    const proof = proveBinary(c, r, 1, pk, ctx);
    for (const field of ['a0', 'a1', 'e0', 'e1', 'z0', 'z1'] as const) {
      const mutated = { ...proof, [field]: (proof[field] + 1n) % pk.n };
      expect(verifyBinary(c, mutated, pk, ctx), field).toBe(false);
    }
  });
});

describe('LSAG', () => {
  it('verifies from every signer index for every ring size', () => {
    for (let n = 2; n <= 10; n++) {
      const voters = makeVoters(n, `prop-${n}`);
      const ring = ringOf(voters);
      const message = i2osp(BigInt(n), 32);
      for (let index = 0; index < n; index++) {
        const sig = lsagSign(message, ring, index, signerFor(ring, voters, index));
        expect(lsagVerify(message, ring, sig), `n=${n} index=${index}`).toBe(true);
        expect(sig.responses).toHaveLength(n);
      }
    }
  });

  it('produces a ring hash that depends on membership and order', () => {
    const voters = makeVoters(4, 'hash');
    const ring = ringOf(voters);
    expect(ringHash(ring)).toEqual(ringHash(canonicalRing(ring)));
    expect(ringHash(ring)).not.toEqual(ringHash(ring.slice(0, 3)));
  });
});

describe('curve encoding', () => {
  it('round-trips every scalar multiple', () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 1n, max: CURVE_ORDER - 1n }), (k) => {
        const point = mul(G, k);
        expect(decodePoint(encodePoint(point)).equals(point)).toBe(true);
      }),
      { numRuns: RUNS },
    );
  });

  it('is a group homomorphism from scalar addition', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 1n, max: 1n << 64n }),
        fc.bigInt({ min: 1n, max: 1n << 64n }),
        (a, b) => {
          expect(add(mul(G, a), mul(G, b)).equals(mul(G, a + b))).toBe(true);
        },
      ),
      { numRuns: RUNS },
    );
  });
});

describe('base64url', () => {
  it('round-trips arbitrary bytes', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 300 }), (bytes) => {
        expect(b64uDecode(b64uEncode(bytes))).toEqual(bytes);
      }),
      { numRuns: RUNS * 2 },
    );
  });

  it('round-trips fixed-width integers', () => {
    fc.assert(
      fc.property(plaintext, (value) => {
        expect(os2ip(b64uDecode(b64uEncode(i2osp(value, 32)), 32))).toBe(value);
      }),
      { numRuns: RUNS },
    );
  });
});

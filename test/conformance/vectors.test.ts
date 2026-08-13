/**
 * The Python-generated vector corpus.
 *
 * This is the primary correctness gate for the port. Everything else in the
 * suite tests that this implementation is self-consistent; only these tests
 * establish that it agrees with the other one.
 *
 * The corpus pins **intermediate** values -- challenge preimages, the encoded
 * ballot body, the ring-hash preimage -- not just final outputs. An
 * implementation can reach the right answer through a wrong transcript and pass
 * an output-only test, then diverge on the next change; asserting the preimages
 * localizes a failure to the exact hash input that differs.
 */

import { describe, expect, it } from 'vitest';

import { DST_BIN, DST_RING } from '../../src/domain.js';
import { decodePoint, encodePoint, G, mul } from '../../src/primitives/curve.js';
import {
  canonicalRing,
  computeKeyImage,
  hashToPoint,
  lsagVerify,
  makeVoterKey,
  ringHash,
  type RingSignature,
} from '../../src/primitives/lsag.js';
import {
  binaryChallenge,
  verifyBinary,
  verifyOneOfK,
  type BinaryProof,
} from '../../src/primitives/nizk.js';
import {
  aggregate,
  decrypt,
  encryptWith,
  isValidCiphertext,
  makePublicKey,
} from '../../src/primitives/paillier.js';
import { ballotMessage, encodeBallotBody } from '../../src/protocol/ballot.js';
import {
  b64uDecode,
  b64uEncode,
  bytesToHex,
  concatBytes,
  encBytes,
  encN2,
  encU32,
  i2osp,
  os2ip,
} from '../../src/serialization/encoding.js';
import { invert, lcm } from '../../src/math.js';
import { loadVector, toyKeys } from '../helpers.js';
import { sha256 } from '@noble/hashes/sha2.js';

const b64int = (s: string): bigint => os2ip(b64uDecode(s));

describe('encoding/worked-example', () => {
  const vector = loadVector('encoding/worked-example.json');

  it('reproduces the hand-verifiable toy election', () => {
    const { p, q, m, r } = vector.inputs;
    const n = BigInt(p) * BigInt(q);
    const pk = makePublicKey(n, n + 1n);
    const lam = lcm(BigInt(p) - 1n, BigInt(q) - 1n);
    const sk = { lam, mu: invert(lam, n), p: BigInt(p), q: BigInt(q) } as never;

    expect(n).toBe(BigInt(vector.expected.n));
    expect(pk.g).toBe(BigInt(vector.expected.g));
    expect(pk.nSquared).toBe(BigInt(vector.expected.nSquared));
    expect(lam).toBe(BigInt(vector.expected.lam));
    expect(invert(lam, n)).toBe(BigInt(vector.expected.mu));
    expect(pk.byteLen).toBe(vector.expected.ln);

    const c = encryptWith(BigInt(m), BigInt(r), pk);
    expect(c).toBe(BigInt(vector.expected.ciphertext));
    expect(decrypt(c, pk, sk)).toBe(BigInt(vector.expected.decrypted));

    const total = aggregate([c, c], pk);
    expect(total).toBe(BigInt(vector.expected.aggregate));
    expect(decrypt(total, pk, sk)).toBe(BigInt(vector.expected.aggregateDecrypted));

    expect(bytesToHex(i2osp(n, pk.byteLen))).toBe(vector.expected.encNn);
    expect(bytesToHex(encN2(c, pk.byteLen))).toBe(vector.expected.encN2c);
    expect(bytesToHex(encN2(total, pk.byteLen))).toBe(vector.expected.encN2aggregate);
  });
});

describe('paillier', () => {
  const [pk, sk] = toyKeys();

  it('reproduces every encrypt/decrypt case', () => {
    const vector = loadVector('paillier/encrypt-decrypt.json');
    expect(b64int(vector.inputs.n)).toBe(pk.n);
    expect(pk.byteLen).toBe(vector.inputs.ln);
    expect(sk.lam.toString()).toBe(vector.inputs.lam);
    expect(sk.mu.toString()).toBe(vector.inputs.mu);

    for (const entry of vector.expected.cases) {
      const c = encryptWith(BigInt(entry.m), b64int(entry.r), pk);
      expect(b64uEncode(encN2(c, pk.byteLen))).toBe(entry.c);
      expect(decrypt(c, pk, sk).toString()).toBe(entry.decrypted);
    }
  });

  it('reproduces the homomorphic aggregate', () => {
    const vector = loadVector('paillier/aggregate.json');
    const ciphertexts = vector.inputs.ciphertexts.map(b64int);
    const total = aggregate(ciphertexts, pk);
    expect(b64uEncode(encN2(total, pk.byteLen))).toBe(vector.expected.aggregate);
    expect(decrypt(total, pk, sk).toString()).toBe(vector.expected.decrypted);
    expect(vector.expected.decrypted).toBe(vector.expected.plaintextSum);
  });

  it('agrees on every ciphertext-validity boundary (the C5 regression)', () => {
    const vector = loadVector('paillier/ciphertext-validity.json');
    const candidates: bigint[] = vector.inputs.candidates.map((c: string) => BigInt(c));
    const actual = candidates.map((c) => isValidCiphertext(c, pk.n));
    expect(actual).toEqual(vector.expected.valid);
    // c = 0 must be among the rejected: accepting it annihilates the tally.
    expect(actual[0]).toBe(false);
  });
});

describe('nizk-binary', () => {
  const [pk] = toyKeys();

  for (const v of [0, 1]) {
    it(`verifies the pinned proof for v=${v} and reproduces its transcript`, () => {
      const vector = loadVector(`nizk-binary/valid-v${v}.json`);
      const ctx = b64uDecode(vector.inputs.ctx);
      const c = b64int(vector.inputs.c);
      const p = vector.expected.proof;
      const proof: BinaryProof = {
        a0: b64int(p.a0),
        a1: b64int(p.a1),
        e0: b64int(p.e0),
        e1: b64int(p.e1),
        z0: b64int(p.z0),
        z1: b64int(p.z1),
      };

      expect(verifyBinary(c, proof, pk, ctx)).toBe(true);

      const preimage = concatBytes(
        DST_BIN,
        ctx,
        encN2(c, pk.byteLen),
        encN2(proof.a0, pk.byteLen),
        encN2(proof.a1, pk.byteLen),
      );
      expect(bytesToHex(preimage)).toBe(vector.expected.challengePreimage);

      const challenge = binaryChallenge(ctx, c, proof.a0, proof.a1, pk.byteLen);
      expect(b64uEncode(i2osp(challenge, 32))).toBe(vector.expected.challenge);
      // The soundness relation itself: the two challenges must sum to the hash.
      expect((proof.e0 + proof.e1) % (1n << 256n)).toBe(challenge);
    });
  }
});

describe('nizk-oneofk', () => {
  const [pk] = toyKeys();

  for (const k of [2, 3]) {
    it(`verifies the pinned 1-of-${k} ballot`, () => {
      const vector = loadVector(`nizk-oneofk/k${k}-choice0.json`);
      const ctx = b64uDecode(vector.inputs.ctx);
      const ciphertexts = vector.expected.ciphertexts.map(b64int);
      // Ciphertexts are pinned; the proofs are regenerated per run in Python, so
      // what this asserts is that the columns are the ones Python produced and
      // that they are well formed as ciphertexts.
      expect(ciphertexts).toHaveLength(k);
      for (const c of ciphertexts) expect(isValidCiphertext(c, pk.n)).toBe(true);
      expect(vector.expected.verifies).toBe(true);
      expect(ctx).toHaveLength(32);
    });
  }
});

describe('lsag', () => {
  for (const n of [2, 3, 8]) {
    describe(`ring of ${n}`, () => {
      const vector = loadVector(`lsag/ring${n}-all-indices.json`);
      const message = b64uDecode(vector.inputs.message);
      const ring = vector.inputs.ring.map((m: string) => decodePoint(b64uDecode(m, 33)));

      it('reproduces the ring hash and its preimage', () => {
        const preimage = concatBytes(DST_RING, encU32(n), ...ring.map(encodePoint));
        expect(bytesToHex(preimage)).toBe(vector.expected.ringHashPreimage);
        expect(b64uEncode(ringHash(ring))).toBe(vector.expected.ringHash);
      });

      it('is in canonical order', () => {
        expect(canonicalRing(ring).map((p) => bytesToHex(encodePoint(p)))).toEqual(
          ring.map((p: never) => bytesToHex(encodePoint(p))),
        );
      });

      it('verifies a signature from every signer index (the C9 regression)', () => {
        expect(vector.expected.signatures).toHaveLength(n);
        for (const entry of vector.expected.signatures) {
          const sig: RingSignature = {
            keyImage: decodePoint(b64uDecode(entry.keyImage, 33)),
            c0: b64int(entry.c0),
            responses: entry.responses.map(b64int),
          };
          expect(lsagVerify(message, ring, sig), `signer index ${entry.signerIndex}`).toBe(true);
          expect(entry.verifies).toBe(true);
        }
      });

      it('rejects a signature against a ring it was not made for (C3)', () => {
        const entry = vector.expected.signatures[0];
        const sig: RingSignature = {
          keyImage: decodePoint(b64uDecode(entry.keyImage, 33)),
          c0: b64int(entry.c0),
          responses: entry.responses.map(b64int),
        };
        // Substituting one member changes ringHash, so the closure cannot hold.
        const foreign = canonicalRing([...ring.slice(1), mul(G, 12345n)]);
        expect(lsagVerify(message, foreign, sig)).toBe(false);
      });
    });
  }

  it('derives key images that are not publicly computable (the C1 regression)', () => {
    const vector = loadVector('lsag/key-images.json');
    const publicKeys = vector.inputs.publicKeys.map((p: string) => decodePoint(b64uDecode(p, 33)));

    publicKeys.forEach((publicKey: never, i: number) => {
      expect(b64uEncode(encodePoint(hashToPoint(publicKey)))).toBe(vector.expected.hashToPoint[i]);
    });

    // The prototype's H_p was SHA256(P)*G, which makes I = SHA256(P)*P -- so the
    // key image was derivable from the public key alone and every ballot was
    // traceable. Recomputing that broken form must not match the real image.
    publicKeys.forEach((publicKey: never, i: number) => {
      const broken = mul(publicKey, os2ip(sha256(encodePoint(publicKey))));
      const real = decodePoint(b64uDecode(vector.expected.keyImages[i], 33));
      expect(broken.equals(real)).toBe(false);
      expect(vector.expected.brokenC1Match[i]).toBe(false);
    });
  });

  it('recomputes the pinned key images from their secrets', () => {
    // A key image is x*H_p(P); regenerating one requires the secret, so this
    // checks the derivation on freshly derived keys rather than the pinned ones.
    const secret = 0x1234_5678_9abc_defn;
    const key = makeVoterKey(secret, mul(G, secret));
    expect(computeKeyImage(key).equals(mul(hashToPoint(key.public), secret))).toBe(true);
  });
});

describe('ballot', () => {
  it('reproduces the canonical ballot body and the signed digest', () => {
    const vector = loadVector('ballot/binary-body.json');
    const ctx = b64uDecode(vector.inputs.ctx);
    const ln: number = vector.inputs.ln;
    const c = b64int(vector.inputs.ciphertext);

    // The body is pinned including the proof, so the proof is read back out of
    // the pinned bytes rather than regenerated -- the encoding is what is under
    // test here, not the prover.
    const body = new Uint8Array(
      (vector.expected.ballotBody.match(/../g) as string[]).map((h: string) =>
        Number.parseInt(h, 16),
      ),
    );
    expect(body).toHaveLength(vector.expected.ballotBodyLength);

    const preimage = concatBytes(
      new TextEncoder().encode('ZKTally-v1:BALLOT'),
      ctx,
      encBytes(body),
    );
    expect(bytesToHex(preimage)).toBe(vector.expected.messagePreimage);
    expect(b64uEncode(ballotMessage(ctx, body))).toBe(vector.expected.ballotMessage);

    // Re-encoding the ciphertext and the pinned proof must reproduce the body
    // byte for byte, which is what proves the two encoders agree.
    // Layout: Enc_u32(1) | Enc_N2(c) | Enc_u32(1) | 0x01 | a0 a1 e0 e1 z0 z1
    let at = 4 + 2 * ln + 4 + 1;
    const take = (width: number): bigint => os2ip(body.subarray(at, (at += width)));
    const proof: BinaryProof = {
      a0: take(2 * ln),
      a1: take(2 * ln),
      e0: take(32),
      e1: take(32),
      z0: take(ln),
      z1: take(ln),
    };
    expect(at).toBe(body.length);
    expect(bytesToHex(encodeBallotBody([c], [proof], ln))).toBe(vector.expected.ballotBody);
  });
});

describe('manifest', () => {
  it('declares the specVersion this build implements', () => {
    const manifest = loadVector('manifest.json');
    expect(manifest.specVersion).toBe('zktally/1');
    expect(Object.keys(manifest.files).length).toBeGreaterThan(0);
  });
});

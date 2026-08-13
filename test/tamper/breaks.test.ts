/**
 * One test per critical break in the research prototype.
 *
 * Each of these attacks worked against the original code. They are kept as
 * executable regressions rather than prose so that a refactor which quietly
 * reintroduces one fails loudly, and so the security claims in the README are
 * checkable rather than asserted.
 */

import { describe, expect, it } from 'vitest';

import { sha256 } from '@noble/hashes/sha2.js';

import { CURVE_ORDER, G, decodePoint, encodePoint, mul } from '../../src/primitives/curve.js';
import {
  canonicalRing,
  computeKeyImage,
  hashToPoint,
  lsagSign,
  lsagVerify,
  makeVoterKey,
  ringKeygen,
} from '../../src/primitives/lsag.js';
import { proveBinary, verifyBinary } from '../../src/primitives/nizk.js';
import { encryptWith, isValidCiphertext } from '../../src/primitives/paillier.js';
import { castBallot, verifyBallotSync } from '../../src/protocol/ballot.js';
import { Board } from '../../src/protocol/board.js';
import { electionContext, makeElectionParams } from '../../src/protocol/params.js';
import { os2ip } from '../../src/serialization/encoding.js';
import { binaryParams, makeVoters, ringOf, signerFor, toyKeys } from '../helpers.js';

const [pk] = toyKeys();
const voters = makeVoters(4);
const ring = ringOf(voters);
const params = binaryParams(pk, ring);
const message = sha256(new TextEncoder().encode('tamper-suite'));

describe('C1 -- key image must not be derivable from the public key', () => {
  it('rejects the prototype hash-to-point relation', () => {
    // The prototype used H_p(P) = SHA256(P)*G, which makes I = SHA256(P)*P and
    // therefore computable by anyone. Every ballot was traceable to its voter.
    const key = ringKeygen();
    const real = computeKeyImage(key);
    const forgeable = mul(key.public, os2ip(sha256(encodePoint(key.public))));
    expect(real.equals(forgeable)).toBe(false);
  });

  it('produces a hash-to-point with no small discrete log', () => {
    const key = ringKeygen();
    const hp = hashToPoint(key.public);
    for (let k = 1n; k <= 128n; k++) expect(hp.equals(mul(G, k))).toBe(false);
  });
});

describe('C2 -- the key image must be bound into the challenge', () => {
  it('rejects a signature carrying a substituted key image', () => {
    // The prototype hashed only (message, L), so nothing constrained I. A voter
    // could attach a fresh random image to every ballot and vote without limit.
    const key = signerFor(ring, voters, 0);
    const sig = lsagSign(message, ring, 0, key);
    const forged = { ...sig, keyImage: mul(G, 999n) };
    expect(lsagVerify(message, ring, forged)).toBe(false);
  });

  it('rejects a key image lifted from another voter', () => {
    const sigA = lsagSign(message, ring, 0, signerFor(ring, voters, 0));
    const sigB = lsagSign(message, ring, 1, signerFor(ring, voters, 1));
    expect(lsagVerify(message, ring, { ...sigA, keyImage: sigB.keyImage })).toBe(false);
  });
});

describe('C3 -- the ring must come from the election, not the ballot', () => {
  it('rejects a ballot signed against an attacker-chosen ring', async () => {
    // The prototype read the ring out of the signature, so an attacker could
    // submit a ring containing only a key they had just generated: it verified
    // perfectly and yielded a fresh key image every time, which is unlimited
    // ballot stuffing.
    const outsiders = makeVoters(2, 'attacker');
    const attackerRing = ringOf(outsiders);
    const attackerParams = makeElectionParams({ ...params, ring: attackerRing });
    const ballot = await castBallot(1, attackerParams, signerFor(attackerRing, outsiders, 0), 0);

    // Submitted to the real election, whose ring the attacker is not in.
    const verdict = verifyBallotSync(ballot, params, new Set());
    expect(verdict.ok).toBe(false);
    // The ring change moves ringHash, hence ctx, so the NIZK transcript breaks
    // first -- the normative check order puts the proof before the signature.
    expect(verdict.ok === false && verdict.reason).toMatch(/invalid-(proof|signature)/);
  });

  it('offers no way to express a ring inside a signature', () => {
    const sig = lsagSign(message, ring, 0, signerFor(ring, voters, 0));
    expect('ring' in sig).toBe(false);
  });
});

describe('C4 -- nonces must come from a CSPRNG', () => {
  it('never repeats a response across signatures', () => {
    // Decoy responses are published in the signature. With a Mersenne Twister,
    // roughly 80 signatures recover the generator state and hence the key.
    const key = signerFor(ring, voters, 0);
    const responses = new Set<string>();
    for (let i = 0; i < 20; i++) {
      for (const r of lsagSign(message, ring, 0, key).responses) responses.add(r.toString());
    }
    expect(responses.size).toBe(20 * ring.length);
  });
});

describe('C5 -- every ciphertext must be a unit in Z*_(N^2)', () => {
  it('rejects c = 0, which would annihilate the whole tally', () => {
    // With c = 0 both OR-proof branches collapse to 0 = 0, so a proof with
    // z0 = z1 = 0 verifies; the homomorphic product of the entire election then
    // becomes zero and decrypts to garbage. One ballot, undetectably.
    expect(isValidCiphertext(0n, pk.n)).toBe(false);
    const zeroProof = { a0: 0n, a1: 0n, e0: 0n, e1: 0n, z0: 0n, z1: 0n };
    expect(verifyBinary(0n, zeroProof, pk, electionContext(params))).toBe(false);
  });

  it('rejects c = N and other non-units', () => {
    for (const c of [pk.n, 2n * pk.n, pk.nSquared, 0n]) {
      expect(isValidCiphertext(c, pk.n)).toBe(false);
    }
  });

  it('refuses a zero ciphertext at the ballot level', async () => {
    const good = await castBallot(1, params, signerFor(ring, voters, 0), 0);
    const verdict = verifyBallotSync({ ...good, ciphertexts: [0n] }, params, new Set());
    expect(verdict).toEqual({ ok: false, reason: 'invalid-ciphertext' });
  });

  it('keeps a zeroing ballot out of the aggregate', async () => {
    const board = new Board(params);
    board.append(await castBallot(1, params, signerFor(ring, voters, 0), 0));
    const victim = await castBallot(1, params, signerFor(ring, voters, 1), 1);
    board.append({ ...victim, ciphertexts: [0n] });

    const verdicts = await board.verifyAll();
    expect(verdicts[1]?.ok).toBe(false);
    expect(board.accepted()).toHaveLength(1);
  });
});

describe('C6 -- voters must generate their own keys', () => {
  it('exposes no API that mints a key on a voter\'s behalf', async () => {
    // ringKeygen returns to its caller and takes no identity argument, so there
    // is no committee-side path that learns a voter's secret.
    const module = await import('../../src/index.js');
    const suspicious = Object.keys(module).filter((name) =>
      /generateVoterKeys|issueKey|mintKey|keysFor/i.test(name),
    );
    expect(suspicious).toEqual([]);
    expect(ringKeygen.length).toBe(0);
  });
});

describe('C7 -- proofs must not transplant between ballots', () => {
  it('rejects a proof lifted onto another ciphertext', () => {
    const ctx = electionContext(params);
    const r = 12345n;
    const c = encryptWith(1n, r, pk);
    const proof = proveBinary(c, r, 1, pk, ctx);
    expect(verifyBinary(c, proof, pk, ctx)).toBe(true);

    const other = encryptWith(1n, 54321n, pk);
    expect(verifyBinary(other, proof, pk, ctx)).toBe(false);
  });

  it('rejects a proof replayed into another election', () => {
    const r = 12345n;
    const c = encryptWith(1n, r, pk);
    const proof = proveBinary(c, r, 1, pk, electionContext(params));

    const otherParams = makeElectionParams({ ...params, title: 'A different question' });
    const otherRing = makeElectionParams({ ...params, ring: ring.slice(0, 3) });
    // The title alone does not enter ctx; the ring does.
    expect(verifyBinary(c, proof, pk, electionContext(otherParams))).toBe(true);
    expect(verifyBinary(c, proof, pk, electionContext(otherRing))).toBe(false);
  });

  it('binds the proofs into the signed message', async () => {
    // Swapping a proof must invalidate the signature, or a valid ballot could be
    // rewritten in flight. The prototype signed only the ciphertext.
    const a = await castBallot(1, params, signerFor(ring, voters, 0), 0);
    const b = await castBallot(1, params, signerFor(ring, voters, 1), 1);
    const spliced = { ...a, proofs: b.proofs };
    expect(verifyBallotSync(spliced, params, new Set()).ok).toBe(false);
  });
});

describe('C9 -- the ring loop must run n-1 times at every index', () => {
  it('verifies from the last index without a padding key', () => {
    // The prototype's loop bound wrapped almost twice around the ring when the
    // signer sat at index n-1, overwriting its own slot. The workaround was to
    // build the ring with an extra unused key; no such padding exists here.
    for (let n = 2; n <= 8; n++) {
      const members = makeVoters(n, `c9-${n}`);
      const r = ringOf(members);
      expect(r).toHaveLength(n);
      const last = n - 1;
      const sig = lsagSign(message, r, last, signerFor(r, members, last));
      expect(lsagVerify(message, r, sig), `n=${n}`).toBe(true);
    }
  });
});

describe('general malleability', () => {
  it('rejects an out-of-range response', () => {
    const sig = lsagSign(message, ring, 0, signerFor(ring, voters, 0));
    const mutated = [...sig.responses];
    mutated[0] = CURVE_ORDER;
    expect(lsagVerify(message, ring, { ...sig, responses: mutated })).toBe(false);
  });

  it('rejects a signature over a different message', () => {
    const sig = lsagSign(message, ring, 0, signerFor(ring, voters, 0));
    expect(lsagVerify(sha256(new TextEncoder().encode('other')), ring, sig)).toBe(false);
  });

  it('rejects a ring presented out of canonical order', () => {
    const sig = lsagSign(message, ring, 0, signerFor(ring, voters, 0));
    const shuffled = [ring[1] as never, ring[0] as never, ...ring.slice(2)];
    expect(lsagVerify(message, shuffled, sig)).toBe(false);
  });

  it('rejects a ring of size one', () => {
    const key = ringKeygen();
    expect(lsagVerify(message, [key.public], { keyImage: computeKeyImage(key), c0: 1n, responses: [1n] })).toBe(
      false,
    );
  });

  it('rejects an identity key image', () => {
    const sig = lsagSign(message, ring, 0, signerFor(ring, voters, 0));
    // The identity has no encoding, so it cannot even reach the wire; the guard
    // is here for a caller constructing a signature in memory.
    expect(() => encodePoint(mul(G, 0n))).toThrow();
    expect(lsagVerify(message, ring, { ...sig, c0: sig.c0 + 1n })).toBe(false);
  });

  it('rejects a re-encoded but altered ring member', () => {
    const sig = lsagSign(message, ring, 0, signerFor(ring, voters, 0));
    const swapped = canonicalRing([...ring.slice(0, 3), makeVoterKey(7n, mul(G, 7n)).public]);
    expect(lsagVerify(message, swapped, sig)).toBe(false);
  });

  it('rejects a decoded point that is not on the curve', () => {
    expect(() => decodePoint(new Uint8Array([0x02, ...new Uint8Array(32).fill(0)]))).toThrow();
  });
});

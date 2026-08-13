/**
 * Threshold Paillier.
 *
 * The setup uses the same small safe primes as the Python suite so both ports
 * exercise the identical construction. Real safe-prime generation at 3072 bits
 * takes minutes and is not viable in a browser at all -- which is exactly why
 * the demo ships pre-generated parameters.
 */

import { describe, expect, it } from 'vitest';

import { ConfigurationError, InvalidShareError } from '../../src/errors.js';
import { encryptWith } from '../../src/primitives/paillier.js';
import {
  blindingBits,
  combineShares,
  fromSafePrimes,
  partialDecrypt,
  responseByteLen,
  thresholdKeygen,
  verifyPartial,
} from '../../src/primitives/threshold.js';
import { castBallot } from '../../src/protocol/ballot.js';
import { Board } from '../../src/protocol/board.js';
import { electionContext, makeElectionParams } from '../../src/protocol/params.js';
import { auditTally, tally } from '../../src/protocol/tally.js';
import { bitLength } from '../../src/math.js';
import { makeVoters, ringOf, signerFor } from '../helpers.js';

const SAFE_P = 0xe1e3c5f1b2a7d8c3e9f0a1b2c3d50f07n;
const SAFE_Q = 0xc7d8e9f0a1b2c3d4e5f60718293a991fn;

const setup = fromSafePrimes(SAFE_P, SAFE_Q, 2, 3);
const { publicKey: pk, shares, verificationKeys: vk } = setup;
const ctx = new Uint8Array(32).fill(7);

describe('setup', () => {
  it('produces one share per authority', () => {
    expect(shares).toHaveLength(3);
    expect(vk.keys).toHaveLength(3);
    expect(vk.t).toBe(2);
    expect(vk.delta).toBe(6n); // 3!
  });

  it('rejects an impossible threshold', async () => {
    await expect(thresholdKeygen(3072, 4, 3)).rejects.toThrow(ConfigurationError);
    await expect(thresholdKeygen(3072, 1, 3)).rejects.toThrow(ConfigurationError);
  });

  it('rejects a modulus below the threshold floor', async () => {
    await expect(thresholdKeygen(2048, 2, 3)).rejects.toThrow(ConfigurationError);
  });
});

describe('blinding bound', () => {
  it('exceeds the witness it has to hide', () => {
    // An earlier draft bounded the blinding factor by 2^(bits + 512), which is
    // *smaller* than e * Delta * f(i) -- subtracting the challenge term would
    // then recover the share outright. The bound must beat the witness by the
    // statistical margin.
    const bound = blindingBits(pk, vk);
    const witness = shares[0] as (typeof shares)[number];
    const worstCase = bitLength(256n * vk.delta * witness.value);
    expect(bound).toBeGreaterThan(worstCase + 100);
  });

  it('sizes the response field from public values only', () => {
    expect(responseByteLen(pk, vk)).toBe(Math.floor((blindingBits(pk, vk) + 2 + 7) / 8));
  });
});

describe('partial decryption', () => {
  const c = encryptWith(5n, 12345n, pk);

  it('verifies its own correctness proof', () => {
    for (const share of shares) {
      const partial = partialDecrypt(c, share, pk, vk, ctx);
      expect(verifyPartial(c, partial, pk, vk, ctx)).toBe(true);
    }
  });

  it('rejects a proof bound to another context', () => {
    const partial = partialDecrypt(c, shares[0] as never, pk, vk, ctx);
    expect(verifyPartial(c, partial, pk, vk, new Uint8Array(32).fill(9))).toBe(false);
  });

  it('rejects a proof bound to another ciphertext', () => {
    const partial = partialDecrypt(c, shares[0] as never, pk, vk, ctx);
    expect(verifyPartial(encryptWith(6n, 999n, pk), partial, pk, vk, ctx)).toBe(false);
  });

  it('rejects a tampered response', () => {
    const partial = partialDecrypt(c, shares[0] as never, pk, vk, ctx);
    const forged = { ...partial, proof: { ...partial.proof, z: partial.proof.z + 1n } };
    expect(verifyPartial(c, forged, pk, vk, ctx)).toBe(false);
  });

  it('rejects a partial attributed to the wrong authority', () => {
    const partial = partialDecrypt(c, shares[0] as never, pk, vk, ctx);
    expect(verifyPartial(c, { ...partial, authority: 2 }, pk, vk, ctx)).toBe(false);
  });
});

describe('combination', () => {
  it('recovers the plaintext from any quorum', () => {
    const c = encryptWith(42n, 777n, pk);
    for (const quorum of [
      [0, 1],
      [0, 2],
      [1, 2],
      [0, 1, 2],
    ]) {
      const parts = quorum.map((i) => partialDecrypt(c, shares[i] as never, pk, vk, ctx));
      expect(combineShares(c, parts, pk, vk, ctx), quorum.join(',')).toBe(42n);
    }
  });

  it('refuses a sub-threshold quorum', () => {
    const c = encryptWith(42n, 777n, pk);
    const parts = [partialDecrypt(c, shares[0] as never, pk, vk, ctx)];
    expect(() => combineShares(c, parts, pk, vk, ctx)).toThrow(InvalidShareError);
  });

  it('refuses a duplicated authority', () => {
    const c = encryptWith(42n, 777n, pk);
    const one = partialDecrypt(c, shares[0] as never, pk, vk, ctx);
    expect(() => combineShares(c, [one, one], pk, vk, ctx)).toThrow(/duplicate/);
  });

  it('refuses an unproven partial, naming the authority', () => {
    // Callers cannot opt out: combining an unproven share is exactly what would
    // let a dishonest authority move the published total.
    const c = encryptWith(42n, 777n, pk);
    const good = partialDecrypt(c, shares[0] as never, pk, vk, ctx);
    const bad = partialDecrypt(c, shares[1] as never, pk, vk, ctx);
    const forged = { ...bad, value: (bad.value * 2n) % pk.nSquared };
    expect(() => combineShares(c, [good, forged], pk, vk, ctx)).toThrow(/authority 2/);
  });
});

describe('threshold elections', () => {
  const voters = makeVoters(3, 'threshold');
  const ring = ringOf(voters);
  const params = makeElectionParams({
    electionId: new Uint8Array(32).fill(3),
    title: 'Threshold election',
    ballotType: 'binary',
    k: 1,
    candidates: ['Yes'],
    publicKey: pk,
    trustModel: 'threshold',
    ring,
    verificationKeys: vk,
  });

  async function threeBallots(): Promise<Board> {
    const board = new Board(params);
    for (const [i, choice] of [1, 1, 0].entries()) {
      board.append(await castBallot(choice, params, signerFor(ring, voters, i), i));
    }
    return board;
  }

  it('tallies through a quorum of authorities', async () => {
    const board = await threeBallots();
    const result = await tally(board, shares, { quorum: [1, 2] });
    expect(result.totals).toEqual([2n]);
    expect(result.partials[0]).toHaveLength(2);
  });

  it('makes the decryption itself verifiable, unlike single-authority mode', async () => {
    const board = await threeBallots();
    const result = await tally(board, shares, { quorum: [1, 2] });
    const audit = auditTally(board, result);

    expect(audit.decryptionVerifiable).toBe(true);
    expect(audit.decryptionVerified).toBe(true);
    expect(audit.ok).toBe(true);
    expect(audit.reason).toBeNull();
  });

  it('catches a fabricated total, which single-authority mode cannot', async () => {
    // This is the concrete payoff of the threshold mode: the partial-decryption
    // proofs pin the total to the ballots, so an announced figure that does not
    // follow from them is detectable from public data alone.
    const board = await threeBallots();
    const result = await tally(board, shares, { quorum: [1, 2] });
    const audit = auditTally(board, { ...result, totals: [99n] });
    expect(audit.ok).toBe(false);
    expect(audit.reason).toMatch(/does not match/);
  });

  it('refuses to tally without a quorum', async () => {
    const board = await threeBallots();
    await expect(tally(board, shares, { quorum: [1] })).rejects.toThrow(ConfigurationError);
  });

  it('binds the proofs to the election context', async () => {
    const board = await threeBallots();
    const result = await tally(board, shares, { quorum: [1, 2] });
    const partial = (result.partials[0] as never[])[0] as never;
    const elsewhere = new Uint8Array(32).fill(1);
    expect(verifyPartial(result.aggregates[0] as bigint, partial, pk, vk, elsewhere)).toBe(false);
    expect(
      verifyPartial(result.aggregates[0] as bigint, partial, pk, vk, electionContext(params)),
    ).toBe(true);
  });
});

/**
 * The protocol layer: parameters, ballots, the board, and the tally.
 */

import { describe, expect, it } from 'vitest';

import { ConfigurationError, ValidationError } from '../../src/errors.js';
import { lsagLink } from '../../src/primitives/lsag.js';
import { decrypt } from '../../src/primitives/paillier.js';
import { castBallot, keyImageKey, verifyBallotSync } from '../../src/protocol/ballot.js';
import { Board } from '../../src/protocol/board.js';
import {
  electionContext,
  makeElectionParams,
  newElectionId,
  withRing,
} from '../../src/protocol/params.js';
import { auditTally, tally, verifyTally } from '../../src/protocol/tally.js';
import { binaryParams, makeVoters, ringOf, signerFor, toyKeys } from '../helpers.js';

const [pk, sk] = toyKeys();
const voters = makeVoters(4);
const ring = ringOf(voters);
const params = binaryParams(pk, ring);

async function boardWith(choices: readonly number[]): Promise<Board> {
  const board = new Board(params);
  for (const [i, choice] of choices.entries()) {
    board.append(await castBallot(choice, params, signerFor(ring, voters, i), i));
  }
  return board;
}

describe('ElectionParams', () => {
  it('derives the ring hash rather than accepting one', () => {
    expect(params.ringHash).toHaveLength(32);
    expect(params.anonymitySetSize).toBe(ring.length);
  });

  it('binds the ring into the context', () => {
    const other = withRing(params, ring.slice(0, 3));
    expect(electionContext(params)).not.toEqual(electionContext(other));
  });

  it('binds the election id into the context', () => {
    const other = makeElectionParams({ ...params, electionId: newElectionId() });
    expect(electionContext(params)).not.toEqual(electionContext(other));
  });

  it('rejects an inconsistent ballot shape', () => {
    expect(() => makeElectionParams({ ...params, k: 3 })).toThrow(ConfigurationError);
    expect(() =>
      makeElectionParams({ ...params, ballotType: 'one-of-k', k: 1, candidates: ['a'] }),
    ).toThrow(ConfigurationError);
  });

  it('rejects a threshold election with no verification keys', () => {
    expect(() => makeElectionParams({ ...params, trustModel: 'threshold' })).toThrow(
      ConfigurationError,
    );
  });

  it('rejects an election id of the wrong size', () => {
    expect(() => makeElectionParams({ ...params, electionId: new Uint8Array(16) })).toThrow(
      ConfigurationError,
    );
  });
});

describe('castBallot', () => {
  it('produces a ballot that verifies', async () => {
    const ballot = await castBallot(1, params, signerFor(ring, voters, 0), 0);
    expect(verifyBallotSync(ballot, params, new Set())).toEqual({ ok: true });
  });

  it('carries no ring (break C3 is unrepresentable)', async () => {
    const ballot = await castBallot(1, params, signerFor(ring, voters, 0), 0);
    expect('ring' in ballot).toBe(false);
    expect('ring' in ballot.signature).toBe(false);
  });

  it('rejects a choice outside {0, 1} for a binary ballot', async () => {
    await expect(castBallot(2, params, signerFor(ring, voters, 0), 0)).rejects.toThrow(
      ValidationError,
    );
  });

  it('rejects a signer index that does not hold the signer key', async () => {
    await expect(castBallot(1, params, signerFor(ring, voters, 0), 1)).rejects.toThrow(
      ValidationError,
    );
  });

  it('works from every ring index, including the last (the C9 regression)', async () => {
    for (let i = 0; i < ring.length; i++) {
      const ballot = await castBallot(1, params, signerFor(ring, voters, i), i);
      expect(verifyBallotSync(ballot, params, new Set()), `index ${i}`).toEqual({ ok: true });
    }
  });

  it('gives the same voter the same key image every time', async () => {
    const key = signerFor(ring, voters, 0);
    const a = await castBallot(1, params, key, 0);
    const b = await castBallot(0, params, key, 0);
    expect(lsagLink(a.signature, b.signature)).toBe(true);
  });

  it('gives different voters different key images', async () => {
    const a = await castBallot(1, params, signerFor(ring, voters, 0), 0);
    const b = await castBallot(1, params, signerFor(ring, voters, 1), 1);
    expect(lsagLink(a.signature, b.signature)).toBe(false);
  });
});

describe('Board', () => {
  it('accepts every valid ballot', async () => {
    const board = await boardWith([1, 0, 1, 1]);
    expect((await board.verifyAll()).every((v) => v.ok)).toBe(true);
  });

  it('resolves a duplicate key image first-wins', async () => {
    const board = await boardWith([1, 0]);
    const key = signerFor(ring, voters, 0);
    board.append(await castBallot(0, params, key, 0));

    const verdicts = await board.verifyAll();
    expect(verdicts[0]).toEqual({ ok: true });
    expect(verdicts[2]).toEqual({ ok: false, reason: 'double-vote' });
    expect(board.accepted()).toHaveLength(2);
  });

  it('does not burn a key image on a rejected ballot', async () => {
    const board = new Board(params);
    const key = signerFor(ring, voters, 0);
    const good = await castBallot(1, params, key, 0);
    // A malformed ballot from the same voter must not block their real one.
    board.append({ ...good, ciphertexts: [0n] });
    board.append(good);

    const verdicts = await board.verifyAll();
    expect(verdicts[0]?.ok).toBe(false);
    expect(verdicts[1]).toEqual({ ok: true });
  });

  it('preserves cast order', async () => {
    const board = await boardWith([1, 0, 1]);
    const images = board.ballots.map(keyImageKey);
    expect(board.accepted().map(keyImageKey)).toEqual(images);
  });
});

describe('tally', () => {
  it('counts only the accepted ballots', async () => {
    const board = await boardWith([1, 0, 1, 1]);
    const result = await tally(board, sk);
    expect(result.totals).toEqual([3n]);
    expect(result.accepted).toBe(4);
    expect(result.rejected).toHaveLength(0);
  });

  it('never opens an individual ballot', async () => {
    const board = await boardWith([1, 0, 1]);
    const result = await tally(board, sk);
    // The aggregate decrypts; the published result exposes nothing per ballot.
    expect(decrypt(result.aggregates[0] as bigint, pk, sk)).toBe(2n);
    expect(result.totals).toEqual([2n]);
  });

  it('handles an empty board', async () => {
    const result = await tally(new Board(params), sk);
    expect(result.totals).toEqual([0n]);
    expect(result.accepted).toBe(0);
  });

  it('excludes a double vote from the total', async () => {
    const board = await boardWith([1, 1]);
    board.append(await castBallot(1, params, signerFor(ring, voters, 0), 0));
    const result = await tally(board, sk);
    expect(result.totals).toEqual([2n]);
    expect(result.rejected).toEqual([{ index: 2, reason: 'double-vote' }]);
  });
});

describe('auditTally', () => {
  it('confirms the ballots and aggregates from public data alone', async () => {
    const board = await boardWith([1, 0, 1]);
    const result = await tally(board, sk);
    const audit = auditTally(board, result);

    expect(audit.ballotsOk).toBe(true);
    expect(audit.aggregatesOk).toBe(true);
    expect(audit.ok).toBe(true);
  });

  it('reports a single-authority decryption as unproved, not verified', async () => {
    // The key holder publishes no proof, so the total is asserted rather than
    // established. Calling that "verified" would be false.
    const board = await boardWith([1, 0, 1]);
    const result = await tally(board, sk);
    const audit = auditTally(board, result);

    expect(audit.decryptionVerifiable).toBe(false);
    expect(audit.decryptionVerified).toBe(false);
    expect(audit.reason).toMatch(/no proof/);
  });

  it('catches altered aggregates', async () => {
    const board = await boardWith([1, 0, 1]);
    const result = await tally(board, sk);
    const audit = auditTally(board, { ...result, aggregates: [result.aggregates[0] as bigint * 1n + 2n] });
    expect(audit.aggregatesOk).toBe(false);
    expect(audit.ok).toBe(false);
  });

  it('catches a mismatched accepted count', async () => {
    const board = await boardWith([1, 0, 1]);
    const result = await tally(board, sk);
    expect(verifyTally(board, { ...result, accepted: 99 })).toBe(false);
  });

  it('catches a result from a different election', async () => {
    const board = await boardWith([1, 0, 1]);
    const result = await tally(board, sk);
    const audit = auditTally(board, { ...result, electionId: newElectionId() });
    expect(audit.reason).toMatch(/different election/);
  });
});

describe('one-of-k elections', () => {
  const kParams = makeElectionParams({
    ...params,
    ballotType: 'one-of-k',
    k: 3,
    candidates: ['Alice', 'Bob', 'Carol'],
  });

  it('tallies one vote per ballot across the columns', async () => {
    const board = new Board(kParams);
    for (const [i, choice] of [0, 2, 0, 1].entries()) {
      board.append(await castBallot(choice, kParams, signerFor(ring, voters, i), i));
    }
    const result = await tally(board, sk);
    expect(result.totals).toEqual([2n, 1n, 1n]);
    expect(result.totals.reduce((a, b) => a + b, 0n)).toBe(BigInt(result.accepted));
  });

  it('rejects a choice outside the candidate range', async () => {
    await expect(castBallot(3, kParams, signerFor(ring, voters, 0), 0)).rejects.toThrow();
  });
});

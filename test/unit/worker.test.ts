/**
 * The worker handle.
 *
 * Node has no `Worker` global, so these exercise the inline path and the shared
 * API surface. Real off-thread behaviour needs a browser and is covered by the
 * browser pass rather than pretended at here.
 */

import { describe, expect, it } from 'vitest';

import { createZKTallyWorker, voterKeyFromSecret } from '../../src/worker/client.js';
import { verifyBallotSync } from '../../src/protocol/ballot.js';
import { Board } from '../../src/protocol/board.js';
import { binaryParams, makeVoters, ringOf, signerFor, toyKeys } from '../helpers.js';

const [pk] = toyKeys();
const voters = makeVoters(3, 'worker');
const ring = ringOf(voters);
const params = binaryParams(pk, ring);

describe('createZKTallyWorker', () => {
  it('reports honestly whether work is actually offloaded', () => {
    const zk = createZKTallyWorker();
    // Under Node there is no Worker global, so the UI-blocking path is in use.
    // Callers need to know that rather than discover it as a frozen page.
    expect(typeof zk.offloaded).toBe('boolean');
    expect(zk.offloaded).toBe(typeof Worker !== 'undefined');
  });

  it('casts a ballot that verifies', async () => {
    const zk = createZKTallyWorker();
    const key = signerFor(ring, voters, 0);
    const ballot = await zk.castBallot({ choice: 1, params, key, ringIndex: 0 });
    expect(verifyBallotSync(ballot, params, new Set())).toEqual({ ok: true });
    await zk.terminate();
  });

  it('reports progress across the ring', async () => {
    const zk = createZKTallyWorker();
    const fractions: number[] = [];
    await zk.castBallot(
      { choice: 1, params, key: signerFor(ring, voters, 0), ringIndex: 0 },
      { onProgress: (f) => fractions.push(f) },
    );
    expect(fractions.length).toBeGreaterThan(0);
    expect(fractions.at(-1)).toBe(1);
    expect(fractions.every((f) => f >= 0 && f <= 1)).toBe(true);
    await zk.terminate();
  });

  it('verifies a board', async () => {
    const zk = createZKTallyWorker();
    const board = new Board(params);
    for (const [i, choice] of [1, 0, 1].entries()) {
      board.append(await zk.castBallot({ choice, params, key: signerFor(ring, voters, i), ringIndex: i }));
    }
    const verdicts = await zk.verifyBoard(board);
    expect(verdicts.every((v) => v.ok)).toBe(true);
    await zk.terminate();
  });

  it('honours an abort signal', async () => {
    const zk = createZKTallyWorker();
    const controller = new AbortController();
    controller.abort();
    await expect(
      zk.castBallot(
        { choice: 1, params, key: signerFor(ring, voters, 0), ringIndex: 0 },
        { signal: controller.signal },
      ),
    ).rejects.toThrow();
    await zk.terminate();
  });
});

describe('voterKeyFromSecret', () => {
  it('rebuilds the public point rather than trusting a transmitted one', () => {
    const original = voters[0]!;
    const rebuilt = voterKeyFromSecret(original.secret);
    expect(rebuilt.public.equals(original.public)).toBe(true);
  });

  it('still refuses to serialize', () => {
    expect(() => JSON.stringify(voterKeyFromSecret(12345n))).toThrow();
  });
});

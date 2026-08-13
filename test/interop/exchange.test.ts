/**
 * Cross-language exchange with the Python package.
 *
 * The conformance corpus proves the two implementations agree on pinned values.
 * This proves the stronger and more useful claim: a board this port *just
 * produced* verifies in Python, and one Python produced verifies here. Nothing
 * is pinned, so it catches divergence in code paths the corpus does not cover.
 *
 * Skipped when the Python package is not importable, so the suite still runs in
 * a checkout of this repo alone.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { castBallot } from '../../src/protocol/ballot.js';
import { Board } from '../../src/protocol/board.js';
import { boardFromJSON, boardToJSON } from '../../src/serialization/jsonCodec.js';
import { binaryParams, makeVoters, ringOf, signerFor, toyKeys } from '../helpers.js';

const here = dirname(fileURLToPath(import.meta.url));
const pythonSrc = join(here, '..', '..', '..', 'zktally', 'src');

function python(script: string, ...args: string[]): string {
  return execFileSync('python3', ['-c', script, ...args], {
    encoding: 'utf8',
    env: { ...process.env, PYTHONPATH: pythonSrc },
  });
}

function pythonAvailable(): boolean {
  try {
    python('import zktally');
    return true;
  } catch {
    return false;
  }
}

const available = pythonAvailable();
const describeInterop = available ? describe : describe.skip;

if (!available) {
  console.warn('interop tests skipped: the Python package is not importable');
}

describeInterop('TypeScript -> Python', () => {
  it('produces a board that Python accepts and tallies identically', async () => {
    const [pk] = toyKeys();
    const voters = makeVoters(4, 'interop');
    const ring = ringOf(voters);
    const params = binaryParams(pk, ring, 'Interop election');

    const board = new Board(params);
    const choices = [1, 0, 1, 1];
    for (const [i, choice] of choices.entries()) {
      board.append(await castBallot(choice, params, signerFor(ring, voters, i), i));
    }

    const dir = mkdtempSync(join(tmpdir(), 'zktally-interop-'));
    const path = join(dir, 'board.json');
    writeFileSync(path, boardToJSON(board, 2));

    const output = python(
      `
import json, sys
from zktally import board_from_json
board = board_from_json(open(sys.argv[1]).read())
verdicts = board.verify_all()
print(json.dumps({
    "accepted": [v.accepted for v in verdicts],
    "reasons": [v.reason for v in verdicts],
    "ringSize": len(board.params.ring),
    "ringHash": board.params.ring_hash.hex(),
}))
`,
      path,
    );

    const report = JSON.parse(output);
    expect(report.accepted, `Python rejected: ${JSON.stringify(report.reasons)}`).toEqual([
      true,
      true,
      true,
      true,
    ]);
    expect(report.ringSize).toBe(ring.length);
    expect(report.ringHash).toBe(
      [...params.ringHash].map((b) => b.toString(16).padStart(2, '0')).join(''),
    );
  });

  it('has its double vote detected by Python', async () => {
    const [pk] = toyKeys();
    const voters = makeVoters(3, 'interop-dup');
    const ring = ringOf(voters);
    const params = binaryParams(pk, ring);

    const board = new Board(params);
    const key = signerFor(ring, voters, 0);
    board.append(await castBallot(1, params, key, 0));
    board.append(await castBallot(0, params, key, 0));

    const dir = mkdtempSync(join(tmpdir(), 'zktally-interop-'));
    const path = join(dir, 'board.json');
    writeFileSync(path, boardToJSON(board, 2));

    const output = python(
      `
import json, sys
from zktally import board_from_json
verdicts = board_from_json(open(sys.argv[1]).read()).verify_all()
print(json.dumps([v.reason for v in verdicts]))
`,
      path,
    );
    expect(JSON.parse(output)).toEqual([null, 'double-vote']);
  });
});

describeInterop('Python -> TypeScript', () => {
  it('accepts a board Python produced', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'zktally-interop-'));
    const path = join(dir, 'board.json');

    python(
      `
import sys
from math import lcm
from zktally import (
    Board, ElectionParams, board_to_json, cast_ballot, canonical_ring, ring_keygen,
)
from zktally.primitives.paillier import PaillierPublicKey

p = 0xE7C4A2F1D3B596874A3F2E1D0C9B8ACF
q = 0xF1D2C3B4A59687789A8B7C6D5E4F303D
n = p * q
pk = PaillierPublicKey(n=n, g=n + 1)

voters = [ring_keygen() for _ in range(4)]
ring = canonical_ring([v.public for v in voters])
params = ElectionParams(
    election_id=bytes(32),
    title="Produced by Python",
    ballot_type="binary",
    k=1,
    candidates=("Yes",),
    public_key=pk,
    trust_model="single-authority",
    ring=ring,
)
board = Board(params=params)
for i, choice in enumerate([1, 1, 0, 1]):
    key = next(v for v in voters if v.public == ring[i])
    board.append(cast_ballot(choice, params, key, i))
open(sys.argv[1], "w").write(board_to_json(board, indent=2))
`,
      path,
    );

    const board = boardFromJSON(readFileSync(path, 'utf8'));
    expect(board.ballots).toHaveLength(4);

    const verdicts = await board.verifyAll();
    expect(
      verdicts.every((v) => v.ok),
      `TypeScript rejected: ${JSON.stringify(verdicts)}`,
    ).toBe(true);
  });

  it('rejects a Python board whose ciphertext was zeroed in transit (C5)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'zktally-interop-'));
    const path = join(dir, 'board.json');

    python(
      `
import sys
from zktally import (
    Board, ElectionParams, board_to_json, cast_ballot, canonical_ring, ring_keygen,
)
from zktally.primitives.paillier import PaillierPublicKey

n = 0xE7C4A2F1D3B596874A3F2E1D0C9B8ACF * 0xF1D2C3B4A59687789A8B7C6D5E4F303D
pk = PaillierPublicKey(n=n, g=n + 1)
voters = [ring_keygen() for _ in range(3)]
ring = canonical_ring([v.public for v in voters])
params = ElectionParams(
    election_id=bytes(32), title="t", ballot_type="binary", k=1,
    candidates=("Yes",), public_key=pk, trust_model="single-authority", ring=ring,
)
board = Board(params=params)
for i in range(3):
    key = next(v for v in voters if v.public == ring[i])
    board.append(cast_ballot(1, params, key, i))
open(sys.argv[1], "w").write(board_to_json(board, indent=2))
`,
      path,
    );

    const doc = JSON.parse(readFileSync(path, 'utf8'));
    // A zero ciphertext would annihilate the homomorphic product.
    doc.ballots[1].ciphertexts[0] = 'A'.repeat(86);
    const board = boardFromJSON(JSON.stringify(doc));

    const verdicts = await board.verifyAll();
    expect(verdicts[1]?.ok).toBe(false);
    expect(board.accepted()).toHaveLength(2);
  });
});

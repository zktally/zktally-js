/**
 * JSON envelopes.
 *
 * The big-integer rule matters more here than in Python: JavaScript's `number`
 * is an IEEE-754 double, so a ciphertext that reached a JSON number would be
 * silently destroyed. These tests are mostly about what the decoder *refuses*.
 */

import { describe, expect, it } from 'vitest';

import { DecodingError, UnsupportedVersionError } from '../../src/errors.js';
import { castBallot } from '../../src/protocol/ballot.js';
import { Board } from '../../src/protocol/board.js';
import { tally } from '../../src/protocol/tally.js';
import {
  boardFromJSON,
  boardToJSON,
  paramsFromDict,
  paramsToDict,
  tallyFromDict,
  tallyToDict,
} from '../../src/serialization/jsonCodec.js';
import { b64uDecode, b64uEncode, bytesToHex } from '../../src/serialization/encoding.js';
import { binaryParams, makeVoters, ringOf, signerFor, toyKeys } from '../helpers.js';

const [pk, sk] = toyKeys();
const voters = makeVoters(3);
const ring = ringOf(voters);
const params = binaryParams(pk, ring);

async function makeBoard(): Promise<Board> {
  const board = new Board(params);
  for (const [i, choice] of [1, 0, 1].entries()) {
    board.append(await castBallot(choice, params, signerFor(ring, voters, i), i));
  }
  return board;
}

const board = await makeBoard();
const encoded = boardToJSON(board, 2);

describe('round trip', () => {
  it('restores the parameters', () => {
    const restored = paramsFromDict(paramsToDict(params));
    expect(bytesToHex(restored.ringHash)).toBe(bytesToHex(params.ringHash));
    expect(restored.publicKey.n).toBe(params.publicKey.n);
    expect(restored.electionId).toEqual(params.electionId);
    expect(restored.ring.map((p) => p.toHex(true))).toEqual(ring.map((p) => p.toHex(true)));
  });

  it('restores the board', () => {
    const restored = boardFromJSON(encoded);
    expect(restored.ballots).toHaveLength(board.ballots.length);
    expect(bytesToHex(restored.params.ringHash)).toBe(bytesToHex(params.ringHash));
  });

  it('keeps every ballot verifying after a round trip', async () => {
    expect((await boardFromJSON(encoded).verifyAll()).every((v) => v.ok)).toBe(true);
  });

  it('preserves board order, which is normative', () => {
    const original = board.ballots.map((b) => b.signature.c0);
    expect(boardFromJSON(encoded).ballots.map((b) => b.signature.c0)).toEqual(original);
  });

  it('restores a tally result', async () => {
    const result = await tally(board, sk);
    const restored = tallyFromDict(tallyToDict(result, params), params);
    expect(restored.totals).toEqual(result.totals);
    expect(restored.aggregates).toEqual(result.aggregates);
    expect(restored.accepted).toBe(result.accepted);
  });
});

describe('wire shape', () => {
  const doc = JSON.parse(encoded);

  it('carries big integers as strings, never JSON numbers', () => {
    expect(typeof doc.ballots[0].ciphertexts[0]).toBe('string');
    expect(typeof doc.params.paillier.n).toBe('string');
    expect(typeof doc.ballots[0].signature.c0).toBe('string');
  });

  it('omits the ring from every ballot', () => {
    expect('ring' in doc.ballots[0]).toBe(false);
    expect('ring' in doc.ballots[0].signature).toBe(false);
  });

  it('uses fixed-width fields', () => {
    const sig = doc.ballots[0].signature;
    expect(b64uDecode(sig.keyImage)).toHaveLength(33);
    expect(b64uDecode(sig.c0)).toHaveLength(32);
    for (const r of sig.responses) expect(b64uDecode(r)).toHaveLength(32);
  });

  it('publishes the derived values', () => {
    expect(doc.params.ring.ringHash).toBeTypeOf('string');
    expect(doc.params.ctx).toBeTypeOf('string');
  });
});

describe('decoder hostility', () => {
  const mutated = (mutate: (doc: any) => void): string => {
    const doc = JSON.parse(encoded);
    mutate(doc);
    return JSON.stringify(doc);
  };

  it('rejects an unknown specVersion', () => {
    expect(() => boardFromJSON(mutated((d) => (d.specVersion = 'zktally/2')))).toThrow(
      UnsupportedVersionError,
    );
  });

  it('recomputes the ring hash rather than trusting it', () => {
    // A supplied ring hash is exactly what an attacker would want to choose.
    expect(() =>
      boardFromJSON(mutated((d) => (d.params.ring.ringHash = b64uEncode(new Uint8Array(32))))),
    ).toThrow(/ringHash/);
  });

  it('recomputes the context rather than trusting it', () => {
    expect(() =>
      boardFromJSON(mutated((d) => (d.params.ctx = b64uEncode(new Uint8Array(32))))),
    ).toThrow(/ctx/);
  });

  it('rejects an altered ring', () => {
    expect(() => boardFromJSON(mutated((d) => d.params.ring.members.pop()))).toThrow(DecodingError);
  });

  it('rejects a numeric ciphertext', () => {
    expect(() => boardFromJSON(mutated((d) => (d.ballots[0].ciphertexts = [12345])))).toThrow(
      /base64url string/,
    );
  });

  it('rejects a short key image', () => {
    expect(() => boardFromJSON(mutated((d) => (d.ballots[0].signature.keyImage = 'AAAA')))).toThrow(
      DecodingError,
    );
  });

  it('rejects an unknown proof type', () => {
    expect(() => boardFromJSON(mutated((d) => (d.ballots[0].proofs[0].type = 'bogus')))).toThrow(
      /unknown proof type/,
    );
  });

  it('rejects a missing field', () => {
    expect(() => boardFromJSON(mutated((d) => delete d.ballots[0].signature))).toThrow(
      /missing required field/,
    );
  });

  it('rejects invalid JSON', () => {
    expect(() => boardFromJSON('{not json')).toThrow(/invalid JSON/);
  });

  it('rejects an off-curve ring member', () => {
    const bogus = b64uEncode(new Uint8Array([0x02, ...new Uint8Array(32)]));
    expect(() => boardFromJSON(mutated((d) => (d.params.ring.members[0] = bogus)))).toThrow(
      DecodingError,
    );
  });
});

describe('key material', () => {
  it('refuses to serialize a private key', () => {
    expect(() => JSON.stringify(sk)).toThrow();
  });

  it('refuses to serialize a voter key', () => {
    expect(() => JSON.stringify(voters[0])).toThrow();
  });

  it('redacts secrets from string conversion', () => {
    expect(String(voters[0])).toContain('<redacted>');
    expect(String(voters[0])).not.toContain(String(voters[0]?.secret));
  });
});

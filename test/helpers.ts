/**
 * Shared test fixtures.
 *
 * The toy primes here are genuinely prime but far below the modulus floor. They
 * exist so the suite runs in seconds; anything asserting key strength uses real
 * parameters and is marked slow.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { sha256 } from '@noble/hashes/sha2.js';

import { G, mul } from '../src/primitives/curve.js';
import { canonicalRing, makeVoterKey, type VoterKey } from '../src/primitives/lsag.js';
import { makePublicKey, type PaillierPrivateKey, type PaillierPublicKey } from '../src/primitives/paillier.js';
import { makeElectionParams, type ElectionParams } from '../src/protocol/params.js';
import { i2osp } from '../src/serialization/encoding.js';
import { invert, lcm } from '../src/math.js';
import type { Point } from '../src/primitives/curve.js';

const here = dirname(fileURLToPath(import.meta.url));

export const VECTORS_DIR = join(here, 'vectors');

export function loadVector(relativePath: string): any {
  return JSON.parse(readFileSync(join(VECTORS_DIR, relativePath), 'utf8'));
}

/** The same toy primes the Python vector generator uses. */
export const TOY_P = 0xe7c4a2f1d3b596874a3f2e1d0c9b8acfn;
export const TOY_Q = 0xf1d2c3b4a59687789a8b7c6d5e4f303dn;

export function toyKeys(): [PaillierPublicKey, PaillierPrivateKey] {
  const n = TOY_P * TOY_Q;
  const lam = lcm(TOY_P - 1n, TOY_Q - 1n);
  const sk = {
    lam,
    mu: invert(lam, n),
    p: TOY_P,
    q: TOY_Q,
    toJSON(): never {
      throw new Error('nope');
    },
  } as PaillierPrivateKey;
  return [makePublicKey(n, n + 1n), sk];
}

/**
 * Deterministic voter keys.
 *
 * Derived from a counter so a test that fails is reproducible, and so ring
 * membership is stable across runs.
 */
export function makeVoters(count: number, label = 'zktally-test'): VoterKey[] {
  const keys: VoterKey[] = [];
  for (let i = 0; i < count; i++) {
    const digest = sha256(new TextEncoder().encode(`${label}:${i}`));
    let secret = 0n;
    for (const b of digest) secret = (secret << 8n) | BigInt(b);
    keys.push(makeVoterKey(secret, mul(G, secret)));
  }
  return keys;
}

export function ringOf(voters: readonly VoterKey[]): Point[] {
  return canonicalRing(voters.map((v) => v.public));
}

/** Find the voter holding the public key at `index` in a canonical ring. */
export function signerFor(ring: readonly Point[], voters: readonly VoterKey[], index: number): VoterKey {
  const member = ring[index] as Point;
  const key = voters.find((v) => v.public.equals(member));
  if (!key) throw new Error(`no voter holds ring index ${index}`);
  return key;
}

export function binaryParams(
  pk: PaillierPublicKey,
  ring: readonly Point[],
  title = 'Adopt the proposal?',
): ElectionParams {
  return makeElectionParams({
    electionId: i2osp(0x2024n, 32),
    title,
    ballotType: 'binary',
    k: 1,
    candidates: ['Yes'],
    publicKey: pk,
    trustModel: 'single-authority',
    ring,
  });
}

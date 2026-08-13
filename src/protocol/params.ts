/**
 * Election parameters and the derived context (spec sections 1.2, 8.1).
 *
 * `ElectionParams` is the public description of an election: the encryption key,
 * the ballot shape, the trust model, and the frozen ring. Everything a verifier
 * needs and nothing secret.
 *
 * `ctx` binds the spec version, the election identity, the key, and the ring
 * into a single 32-byte digest that is mixed into every proof and signature
 * transcript. That binding is what stops a proof or signature from being
 * replayed into another election, under another key, or onto another ballot.
 */

import { sha256 } from '@noble/hashes/sha2.js';

import { DST_BALLOT, SPEC_VERSION } from '../domain.js';
import { ConfigurationError } from '../errors.js';
import type { Point } from '../primitives/curve.js';
import { MAX_RING, canonicalRing, ringHash } from '../primitives/lsag.js';
import type { PaillierPublicKey } from '../primitives/paillier.js';
import type { VerificationKeys } from '../primitives/threshold.js';
import { randomBytes } from '../rng.js';
import { concatBytes, encBytes, encN, encN2 } from '../serialization/encoding.js';

export type BallotType = 'binary' | 'one-of-k';
export type TrustModel = 'threshold' | 'single-authority';

export const ELECTION_ID_BYTES = 32;

/** A fresh 32-byte election identifier. */
export function newElectionId(): Uint8Array {
  return randomBytes(ELECTION_ID_BYTES);
}

export interface ElectionParamsInit {
  readonly electionId: Uint8Array;
  readonly title: string;
  readonly ballotType: BallotType;
  readonly k: number;
  readonly candidates: readonly string[];
  readonly publicKey: PaillierPublicKey;
  readonly trustModel: TrustModel;
  readonly ring: readonly Point[];
  readonly verificationKeys?: VerificationKeys | undefined;
  readonly subringIndex?: number;
  readonly numSubrings?: number;
  readonly specVersion?: string;
}

/**
 * The public parameters of one election.
 *
 * The ring is **frozen** once ballots exist. Changing it changes `ringHash` and
 * therefore `ctx`, which invalidates every proof and signature already cast, so
 * every field is readonly and {@link withRing} returns a new object.
 */
export interface ElectionParams extends Omit<ElectionParamsInit, 'specVersion'> {
  readonly specVersion: string;
  readonly t: number;
  readonly nAuth: number;
  readonly subringIndex: number;
  readonly numSubrings: number;
  /** Derived, never read from the wire. */
  readonly ringHash: Uint8Array;
  /** The set a voter actually hides within -- the sub-ring, when partitioned. */
  readonly anonymitySetSize: number;
}

export function makeElectionParams(init: ElectionParamsInit): ElectionParams {
  const specVersion = init.specVersion ?? SPEC_VERSION;
  if (specVersion !== SPEC_VERSION) {
    throw new ConfigurationError(`unsupported specVersion ${JSON.stringify(specVersion)}`);
  }
  if (init.electionId.length !== ELECTION_ID_BYTES) {
    throw new ConfigurationError(`electionId must be ${ELECTION_ID_BYTES} bytes`);
  }
  if (init.ballotType === 'binary') {
    if (init.k !== 1) throw new ConfigurationError('binary ballots have k == 1');
  } else if (init.ballotType === 'one-of-k') {
    if (init.k < 2) throw new ConfigurationError('one-of-k ballots require k >= 2');
  } else {
    throw new ConfigurationError(`unknown ballotType ${JSON.stringify(init.ballotType)}`);
  }
  if (init.candidates.length !== init.k) {
    throw new ConfigurationError(`expected ${init.k} candidate labels`);
  }
  if (init.ring.length > MAX_RING) {
    throw new ConfigurationError(
      `ring of ${init.ring.length} exceeds MAX_RING=${MAX_RING}; partition into sub-rings`,
    );
  }
  if (init.trustModel === 'threshold' && !init.verificationKeys) {
    throw new ConfigurationError('threshold elections require verification keys');
  }

  return Object.freeze({
    electionId: init.electionId,
    title: init.title,
    ballotType: init.ballotType,
    k: init.k,
    candidates: Object.freeze([...init.candidates]),
    publicKey: init.publicKey,
    trustModel: init.trustModel,
    ring: Object.freeze([...init.ring]),
    verificationKeys: init.verificationKeys,
    specVersion,
    t: init.verificationKeys?.t ?? 1,
    nAuth: init.verificationKeys?.nAuth ?? 1,
    subringIndex: init.subringIndex ?? 0,
    numSubrings: init.numSubrings ?? 1,
    ringHash: ringHash(init.ring),
    anonymitySetSize: init.ring.length,
  });
}

/**
 * Return a copy with the ring replaced, sorted canonically.
 *
 * Used during registration only. Once ballots exist the ring must not change;
 * this returns a new object rather than mutating, so an accidental late call
 * cannot silently invalidate a board.
 */
export function withRing(params: ElectionParams, members: readonly Point[]): ElectionParams {
  return makeElectionParams({ ...params, ring: canonicalRing(members) });
}

/**
 * `ctx` -- the 32-byte digest bound into every transcript.
 *
 * `SHA256(DST_BALLOT || Enc_bytes(specVersion) || electionId || Enc_N(N)
 * || Enc_N2(g) || ringHash)`.
 *
 * Recomputed from the parameters, never read from the wire: a supplied `ctx` is
 * exactly the value an attacker would want to control.
 */
export function electionContext(params: ElectionParams): Uint8Array {
  const ln = params.publicKey.byteLen;
  return sha256(
    concatBytes(
      DST_BALLOT,
      encBytes(new TextEncoder().encode(params.specVersion)),
      params.electionId,
      encN(params.publicKey.n, ln),
      encN2(params.publicKey.g, ln),
      params.ringHash,
    ),
  );
}

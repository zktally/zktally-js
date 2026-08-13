/**
 * Ballot construction and verification (spec section 7).
 *
 * A ballot is `(ciphertexts, proofs, ring signature)`. The signature covers a
 * digest of **all** ciphertexts and **all** proofs, so a proof cannot be swapped
 * out while the signature stays valid -- the research prototype signed only the
 * ciphertext, leaving the proof unbound.
 *
 * Verification order is normative: cheapest and most discriminating checks
 * first, rejecting on the first failure with a reason from a closed set.
 */

import { sha256 } from '@noble/hashes/sha2.js';

import { DST_BALLOT } from '../domain.js';
import { ValidationError } from '../errors.js';
import {
  lsagSign,
  lsagVerify,
  type RingSignature,
  type SignOptions,
  type VoterKey,
} from '../primitives/lsag.js';
import {
  proveBinary,
  proveOneOfK,
  verifyBinary,
  verifyOneOfK,
  type BinaryProof,
  type NthRootProof,
} from '../primitives/nizk.js';
import { encrypt, isValidCiphertext } from '../primitives/paillier.js';
import {
  concatBytes,
  encBytes,
  encChal,
  encN,
  encN2,
  encU32,
} from '../serialization/encoding.js';
import { electionContext, type ElectionParams } from './params.js';

export type RejectReason =
  | 'malformed'
  | 'invalid-ciphertext'
  | 'invalid-proof'
  | 'invalid-signature'
  | 'double-vote'
  | 'wrong-subring';

export type BallotVerdict = { readonly ok: true } | { readonly ok: false; readonly reason: RejectReason };

const ACCEPTED: BallotVerdict = Object.freeze({ ok: true as const });

export type BallotProof = BinaryProof | NthRootProof;

function isBinaryProof(proof: BallotProof): proof is BinaryProof {
  return 'a0' in proof;
}

/**
 * One cast ballot.
 *
 * Carries no ring: that is election data, and taking it from the ballot is
 * break C3.
 */
export interface Ballot {
  readonly ciphertexts: readonly bigint[];
  readonly proofs: readonly BallotProof[];
  readonly signature: RingSignature;
  readonly subringIndex: number;
}

/**
 * Canonical encoding of everything the signature must cover.
 *
 * The leading type byte on each proof keeps the two proof shapes
 * distinguishable within a single stream.
 */
export function encodeBallotBody(
  ciphertexts: readonly bigint[],
  proofs: readonly BallotProof[],
  ln: number,
): Uint8Array {
  const parts: Uint8Array[] = [encU32(ciphertexts.length)];
  for (const c of ciphertexts) parts.push(encN2(c, ln));
  parts.push(encU32(proofs.length));
  for (const proof of proofs) {
    if (isBinaryProof(proof)) {
      parts.push(
        concatBytes(
          new Uint8Array([0x01]),
          encN2(proof.a0, ln),
          encN2(proof.a1, ln),
          encChal(proof.e0),
          encChal(proof.e1),
          encN(proof.z0, ln),
          encN(proof.z1, ln),
        ),
      );
    } else {
      parts.push(
        concatBytes(
          new Uint8Array([0x02]),
          encN2(proof.a, ln),
          encChal(proof.e),
          encN(proof.z, ln),
        ),
      );
    }
  }
  return concatBytes(...parts);
}

/** `SHA256(DST_BALLOT || ctx || Enc_bytes(ballotBody))` -- what gets signed. */
export function ballotMessage(ctx: Uint8Array, body: Uint8Array): Uint8Array {
  return sha256(concatBytes(DST_BALLOT, ctx, encBytes(body)));
}

/**
 * Encrypt a choice, prove it well formed, and sign as a ring member.
 *
 * The Paillier randomness is discarded before returning. It is a receipt:
 * `(choice, r)` recomputes the ciphertext and locates the ballot on the board,
 * which is why ZKTally is not receipt-free. Dropping it here is best-effort and
 * does not change that property, but the library must not be the thing that
 * hands a voter a durable receipt.
 *
 * Async because a large ring makes signing long enough to block a frame.
 */
export async function castBallot(
  choice: number,
  params: ElectionParams,
  key: VoterKey,
  ringIndex: number,
  options: SignOptions = {},
): Promise<Ballot> {
  const ctx = electionContext(params);
  const ln = params.publicKey.byteLen;

  let ciphertexts: readonly bigint[];
  let proofs: readonly BallotProof[];

  if (params.ballotType === 'binary') {
    if (choice !== 0 && choice !== 1) {
      throw new ValidationError(`binary ballot requires choice in {0, 1}, got ${choice}`);
    }
    const [c, r] = encrypt(BigInt(choice), params.publicKey);
    proofs = [proveBinary(c, r, choice, params.publicKey, ctx)];
    ciphertexts = [c];
  } else {
    const bundle = proveOneOfK(choice, params.k, params.publicKey, ctx);
    ciphertexts = bundle.ciphertexts;
    proofs = [...bundle.binaryProofs, bundle.sumProof];
  }

  await Promise.resolve();
  const message = ballotMessage(ctx, encodeBallotBody(ciphertexts, proofs, ln));
  const signature = lsagSign(message, params.ring, ringIndex, key, options);
  return { ciphertexts, proofs, signature, subringIndex: params.subringIndex };
}

/**
 * Verify one ballot against the election parameters.
 *
 * `seen` holds the hex-encoded key images of already-accepted ballots. Never
 * throws.
 */
export async function verifyBallot(
  ballot: Ballot,
  params: ElectionParams,
  seen: ReadonlySet<string>,
  options: SignOptions = {},
): Promise<BallotVerdict> {
  return verifyBallotSync(ballot, params, seen, options);
}

/** Synchronous form of {@link verifyBallot}, for workers and batch loops. */
export function verifyBallotSync(
  ballot: Ballot,
  params: ElectionParams,
  seen: ReadonlySet<string>,
  options: SignOptions = {},
): BallotVerdict {
  const pk = params.publicKey;
  const ln = pk.byteLen;

  if (ballot.subringIndex !== params.subringIndex) {
    return { ok: false, reason: 'wrong-subring' };
  }

  const expectedCiphertexts = params.ballotType === 'binary' ? 1 : params.k;
  const expectedProofs = params.ballotType === 'binary' ? 1 : params.k + 1;
  if (ballot.ciphertexts.length !== expectedCiphertexts) return { ok: false, reason: 'malformed' };
  if (ballot.proofs.length !== expectedProofs) return { ok: false, reason: 'malformed' };

  for (const c of ballot.ciphertexts) {
    if (!isValidCiphertext(c, pk.n)) return { ok: false, reason: 'invalid-ciphertext' };
  }

  const ctx = electionContext(params);
  try {
    if (params.ballotType === 'binary') {
      const proof = ballot.proofs[0] as BallotProof;
      if (!isBinaryProof(proof)) return { ok: false, reason: 'malformed' };
      if (!verifyBinary(ballot.ciphertexts[0] as bigint, proof, pk, ctx)) {
        return { ok: false, reason: 'invalid-proof' };
      }
    } else {
      const binaryProofs = ballot.proofs.slice(0, -1);
      const sumProof = ballot.proofs[ballot.proofs.length - 1] as BallotProof;
      if (!binaryProofs.every(isBinaryProof) || isBinaryProof(sumProof)) {
        return { ok: false, reason: 'malformed' };
      }
      const bundle = { ciphertexts: ballot.ciphertexts, binaryProofs, sumProof };
      if (!verifyOneOfK(bundle, params.k, pk, ctx)) return { ok: false, reason: 'invalid-proof' };
    }

    const message = ballotMessage(ctx, encodeBallotBody(ballot.ciphertexts, ballot.proofs, ln));
    if (!lsagVerify(message, params.ring, ballot.signature, options)) {
      return { ok: false, reason: 'invalid-signature' };
    }
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') throw error;
    // Structurally impossible values reaching an encoder are malformed input,
    // not a crash: verification must be total on adversarial data.
    return { ok: false, reason: 'malformed' };
  }

  if (seen.has(keyImageKey(ballot))) return { ok: false, reason: 'double-vote' };
  return ACCEPTED;
}

/** The seen-set key for a ballot: the hex of its compressed key image. */
export function keyImageKey(ballot: Ballot): string {
  return ballot.signature.keyImage.toHex(true);
}

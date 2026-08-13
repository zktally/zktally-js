/**
 * Non-interactive zero-knowledge proofs (spec sections 3 and 4).
 *
 * A ballot must prove its plaintext is a legal vote without revealing which one.
 * That is a Cramer-Damgard-Schoenmakers OR composition of two instances of the
 * "knowledge of an N-th root" sigma protocol, made non-interactive by
 * Fiat-Shamir.
 *
 * **Both branches are the same relation.** The originating paper renders branch
 * 1 as a discrete-log relation `A1 * (C/g)^e1 = g^z1`, which does not correspond
 * to its own prover; the symmetric form `z^N = A * C^e` is what both ports
 * implement.
 *
 * The Fiat-Shamir transcript binds the election context, so a proof is valid for
 * exactly one ciphertext in one election. The research prototype hashed only
 * `c || A0 || A1`, which made proofs both replayable across elections and
 * transplantable between ballots.
 */

import { sha256 } from '@noble/hashes/sha2.js';

import { CHALLENGE_MODULUS, DST_BIN, DST_NTH } from '../domain.js';
import { InvalidCiphertextError, InvalidPlaintextError, ValidationError } from '../errors.js';
import { gcd, invert, powMod } from '../math.js';
import { randomBelow, randomUnit } from '../rng.js';
import { concatBytes, encBytes, encN2, encU32, os2ip } from '../serialization/encoding.js';
import { encryptWith, isValidCiphertext, type PaillierPublicKey } from './paillier.js';

/** Proof that a ciphertext encrypts 0 or 1, without revealing which. */
export interface BinaryProof {
  readonly a0: bigint;
  readonly a1: bigint;
  readonly e0: bigint;
  readonly e1: bigint;
  readonly z0: bigint;
  readonly z1: bigint;
}

/** Proof of knowledge of an `N`-th root of a given value. */
export interface NthRootProof {
  readonly a: bigint;
  readonly e: bigint;
  readonly z: bigint;
}

/** A 1-of-k ballot: one ciphertext per candidate, plus the proofs. */
export interface OneOfKBallot {
  readonly ciphertexts: readonly bigint[];
  readonly binaryProofs: readonly BinaryProof[];
  readonly sumProof: NthRootProof;
}

/**
 * Per-candidate context, `SHA256(ctx || Enc_u32(i))`.
 *
 * Required: without it, a valid proof for candidate 3 could be lifted onto
 * candidate 1's slot, since the two transcripts would be identical.
 */
export function candidateContext(ctx: Uint8Array, index: number): Uint8Array {
  return sha256(concatBytes(ctx, encU32(index)));
}

/** `(c_0, c_1) = (c, c * g^-1)`. Each is an `N`-th residue iff m is 0 or 1. */
function branchStatements(c: bigint, pk: PaillierPublicKey): [bigint, bigint] {
  return [c, (c * invert(pk.g, pk.nSquared)) % pk.nSquared];
}

/** `SHA256(DST_BIN || ctx || Enc_N2(c) || Enc_N2(A0) || Enc_N2(A1))`. */
export function binaryChallenge(
  ctx: Uint8Array,
  c: bigint,
  a0: bigint,
  a1: bigint,
  ln: number,
): bigint {
  const digest = sha256(concatBytes(DST_BIN, ctx, encN2(c, ln), encN2(a0, ln), encN2(a1, ln)));
  return os2ip(digest) % CHALLENGE_MODULUS;
}

/**
 * Prove that `c` encrypts `v` in `{0, 1}`.
 *
 * Throws on invalid input rather than returning a sentinel. The research
 * prototype wrapped this in a bare catch-all and returned an all-zero object on
 * failure, which is indistinguishable from a real proof and therefore turns a
 * crypto bug into a silently invalid ballot.
 */
export function proveBinary(
  c: bigint,
  r: bigint,
  v: number,
  pk: PaillierPublicKey,
  ctx: Uint8Array,
): BinaryProof {
  if (v !== 0 && v !== 1) throw new InvalidPlaintextError(`vote must be 0 or 1, got ${v}`);
  if (!isValidCiphertext(c, pk.n)) {
    throw new InvalidCiphertextError('ciphertext is not a unit in Z*_(N^2)');
  }
  if (encryptWith(BigInt(v), r, pk) !== c) {
    throw new ValidationError('witness does not open the ciphertext to the claimed vote');
  }

  const { n, nSquared, byteLen: ln } = pk;
  const branches = branchStatements(c, pk);
  const j = 1 - v; // the simulated branch

  // Simulate branch j: choose the challenge and response first, then solve for
  // the commitment. This is why exactly one branch may be faked.
  const eSim = randomBelow(CHALLENGE_MODULUS);
  const zSim = randomUnit(n);
  const aSim =
    (powMod(zSim, n, nSquared) * invert(powMod(branches[j] as bigint, eSim, nSquared), nSquared)) %
    nSquared;

  // Commit honestly on the real branch.
  const s = randomUnit(n);
  const aReal = powMod(s, n, nSquared);

  const [a0, a1] = v === 0 ? [aReal, aSim] : [aSim, aReal];
  const e = binaryChallenge(ctx, c, a0, a1, ln);
  // The challenges must sum to the hash, so the real branch's challenge is
  // forced and cannot also be simulated.
  const eReal = (((e - eSim) % CHALLENGE_MODULUS) + CHALLENGE_MODULUS) % CHALLENGE_MODULUS;
  const zReal = (s * powMod(r, eReal, n)) % n;

  return v === 0
    ? { a0, a1, e0: eReal, e1: eSim, z0: zReal, z1: zSim }
    : { a0, a1, e0: eSim, e1: eReal, z0: zSim, z1: zReal };
}

/** Verify a binary proof. Never throws, including on adversarial input. */
export function verifyBinary(
  c: bigint,
  proof: BinaryProof,
  pk: PaillierPublicKey,
  ctx: Uint8Array,
): boolean {
  const { n, nSquared, byteLen: ln } = pk;
  if (!isValidCiphertext(c, n)) return false;

  const commitments = [proof.a0, proof.a1] as const;
  const challenges = [proof.e0, proof.e1] as const;
  const responses = [proof.z0, proof.z1] as const;

  // Structural validation. The research prototype accepted arbitrary integers in
  // every field, so out-of-range values reached the exponentiation directly.
  for (const a of commitments) {
    if (!(a > 0n && a < nSquared && gcd(a, n) === 1n)) return false;
  }
  for (const e of challenges) {
    if (!(e >= 0n && e < CHALLENGE_MODULUS)) return false;
  }
  for (const z of responses) {
    if (!(z > 0n && z < n && gcd(z, n) === 1n)) return false;
  }

  try {
    const expected = binaryChallenge(ctx, c, proof.a0, proof.a1, ln);
    if ((proof.e0 + proof.e1) % CHALLENGE_MODULUS !== expected) return false;

    const branches = branchStatements(c, pk);
    for (let i = 0; i < 2; i++) {
      const lhs = powMod(responses[i] as bigint, n, nSquared);
      const rhs =
        ((commitments[i] as bigint) * powMod(branches[i] as bigint, challenges[i] as bigint, nSquared)) %
        nSquared;
      if (lhs !== rhs) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** `SHA256(DST_NTH || ctx || Enc_bytes(tag) || Enc_N2(X) || Enc_N2(A))`. */
export function nthRootChallenge(
  ctx: Uint8Array,
  tag: Uint8Array,
  x: bigint,
  a: bigint,
  ln: number,
): bigint {
  const digest = sha256(concatBytes(DST_NTH, ctx, encBytes(tag), encN2(x, ln), encN2(a, ln)));
  return os2ip(digest) % CHALLENGE_MODULUS;
}

/** Prove knowledge of `r` with `x == r^N mod N^2`. */
export function proveNthRoot(
  x: bigint,
  r: bigint,
  pk: PaillierPublicKey,
  ctx: Uint8Array,
  tag: Uint8Array,
): NthRootProof {
  const { n, nSquared, byteLen: ln } = pk;
  if (!isValidCiphertext(x, n)) {
    throw new InvalidCiphertextError('statement is not a unit in Z*_(N^2)');
  }
  if (powMod(r, n, nSquared) !== x) {
    throw new ValidationError('witness is not an N-th root of the statement');
  }
  const s = randomUnit(n);
  const a = powMod(s, n, nSquared);
  const e = nthRootChallenge(ctx, tag, x, a, ln);
  const z = (s * powMod(r, e, n)) % n;
  return { a, e, z };
}

/** Verify an `N`-th root proof. Never throws. */
export function verifyNthRoot(
  x: bigint,
  proof: NthRootProof,
  pk: PaillierPublicKey,
  ctx: Uint8Array,
  tag: Uint8Array,
): boolean {
  const { n, nSquared, byteLen: ln } = pk;
  if (!isValidCiphertext(x, n) || !isValidCiphertext(proof.a, n)) return false;
  if (!(proof.e >= 0n && proof.e < CHALLENGE_MODULUS)) return false;
  if (!(proof.z > 0n && proof.z < n && gcd(proof.z, n) === 1n)) return false;
  try {
    if (proof.e !== nthRootChallenge(ctx, tag, x, proof.a, ln)) return false;
    return powMod(proof.z, n, nSquared) === (proof.a * powMod(x, proof.e, nSquared)) % nSquared;
  } catch {
    return false;
  }
}

/** Tag for the 1-of-k sum proof, keeping it distinct from any other proof. */
export const SUM_TAG = new Uint8Array([0x53, 0x55, 0x4d, 0x31]); // "SUM1"

/**
 * Encrypt a 1-of-k selection and prove it is well formed.
 *
 * Two things must be proved: that every column is binary, and that the columns
 * sum to exactly one. Proving only the first would let a voter submit all ones
 * and cast `k` votes at once.
 */
export function proveOneOfK(
  choice: number,
  k: number,
  pk: PaillierPublicKey,
  ctx: Uint8Array,
): OneOfKBallot {
  if (k < 2) throw new ValidationError(`one-of-k requires k >= 2, got ${k}`);
  if (!(choice >= 0 && choice < k)) {
    throw new InvalidPlaintextError(`choice must be in [0, ${k}), got ${choice}`);
  }

  const { n, nSquared } = pk;
  const ciphertexts: bigint[] = [];
  const binaryProofs: BinaryProof[] = [];
  let rSum = 1n;
  let cSum = 1n;

  for (let i = 0; i < k; i++) {
    const v = i === choice ? 1 : 0;
    const r = randomUnit(n);
    const c = encryptWith(BigInt(v), r, pk);
    ciphertexts.push(c);
    binaryProofs.push(proveBinary(c, r, v, pk, candidateContext(ctx, i)));
    rSum = (rSum * r) % n;
    cSum = (cSum * c) % nSquared;
  }

  // cSum encrypts exactly 1, so dividing out g leaves a pure N-th residue whose
  // root is the product of the per-column randomness.
  const x = (cSum * invert(pk.g, nSquared)) % nSquared;
  return { ciphertexts, binaryProofs, sumProof: proveNthRoot(x, rSum, pk, ctx, SUM_TAG) };
}

/** Verify a 1-of-k ballot. Never throws. */
export function verifyOneOfK(
  ballot: OneOfKBallot,
  k: number,
  pk: PaillierPublicKey,
  ctx: Uint8Array,
): boolean {
  if (k < 2 || ballot.ciphertexts.length !== k || ballot.binaryProofs.length !== k) return false;

  let cSum = 1n;
  for (let i = 0; i < k; i++) {
    const c = ballot.ciphertexts[i] as bigint;
    if (!isValidCiphertext(c, pk.n)) return false;
    if (!verifyBinary(c, ballot.binaryProofs[i] as BinaryProof, pk, candidateContext(ctx, i))) {
      return false;
    }
    cSum = (cSum * c) % pk.nSquared;
  }
  try {
    const x = (cSum * invert(pk.g, pk.nSquared)) % pk.nSquared;
    return verifyNthRoot(x, ballot.sumProof, pk, ctx, SUM_TAG);
  } catch {
    return false;
  }
}

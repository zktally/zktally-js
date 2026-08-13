/**
 * Threshold Paillier, `t`-of-`n` (spec section 5).
 *
 * Follows Damgard-Jurik (PKC 2001). The private key is shared so that no
 * coalition below `t` can decrypt anything, and every partial decryption carries
 * a proof that it was computed with the authority's real share. Rejecting
 * unproven partials is what makes the published tally verifiable: an authority
 * cannot skew the result without detection.
 *
 * @remarks
 * **Trusted dealer.** v1 has one party generate the key and distribute the
 * shares. That party transiently knows `p`, `q`, and `lambda`, so ballot privacy
 * in v1 rests on the dealer destroying them, not on the threshold. Distributed
 * generation of an RSA modulus is a substantial protocol of its own and is
 * deferred.
 *
 * @remarks
 * **Not viable in a browser.** Safe-prime generation at 3072 bits takes minutes
 * to tens of minutes. {@link thresholdKeygen} is provided for Node; a browser
 * application should ship pre-generated election parameters and say so.
 */

import { sha256 } from '@noble/hashes/sha2.js';

import { CHALLENGE_MODULUS, DST_DEC } from '../domain.js';
import { ConfigurationError, InvalidCiphertextError, InvalidShareError } from '../errors.js';
import { bitLength, factorial, gcd, invert, powMod, randomSafePrime } from '../math.js';
import { randomBelow } from '../rng.js';
import { concatBytes, encN2, encU32, os2ip } from '../serialization/encoding.js';
import { isValidCiphertext, makePublicKey, type PaillierPublicKey } from './paillier.js';

/** Threshold mode requires a 3072-bit modulus; the sharing is over `N*m`. */
export const MIN_THRESHOLD_BITS = 3072;

/** Statistical hiding margin for the Chaum-Pedersen blinding factor. */
export const STAT_SECURITY_BITS = 128;

/** One authority's share `(i, f(i))` of the private key. */
export interface KeyShare {
  readonly index: number;
  readonly value: bigint;
  readonly delta: bigint;
  readonly n: bigint;
}

/** Public data letting anyone check a partial decryption. */
export interface VerificationKeys {
  readonly v: bigint;
  readonly keys: readonly bigint[];
  readonly t: number;
  readonly nAuth: number;
  readonly delta: bigint;
}

/** Chaum-Pedersen proof that a partial decryption used the right share. */
export interface DecryptionProof {
  readonly e: bigint;
  readonly z: bigint;
}

/** An authority's contribution toward decrypting one ciphertext. */
export interface PartialDecryption {
  readonly authority: number;
  readonly value: bigint;
  readonly proof: DecryptionProof;
}

export interface ThresholdSetup {
  readonly publicKey: PaillierPublicKey;
  readonly shares: readonly KeyShare[];
  readonly verificationKeys: VerificationKeys;
}

/**
 * Generate a `t`-of-`n` threshold key.
 *
 * Slow: safe primes require both `p'` and `2p'+1` to be prime, so this is a
 * one-time setup cost measured in minutes.
 */
export async function thresholdKeygen(
  bits: number,
  t: number,
  nAuth: number,
): Promise<ThresholdSetup> {
  if (!(t >= 2 && t <= nAuth)) {
    throw new ConfigurationError(`require 2 <= t <= nAuth, got t=${t}, nAuth=${nAuth}`);
  }
  if (bits < MIN_THRESHOLD_BITS) {
    throw new ConfigurationError(
      `threshold mode requires at least ${MIN_THRESHOLD_BITS} bits, got ${bits}`,
    );
  }
  const half = Math.floor((bits + 1) / 2);
  for (;;) {
    const p = randomSafePrime(half);
    await Promise.resolve();
    const q = randomSafePrime(half);
    await Promise.resolve();
    if (p !== q && bitLength(p * q) === bits) return fromSafePrimes(p, q, t, nAuth);
  }
}

/**
 * Build the shared key from given safe primes.
 *
 * Separated from {@link thresholdKeygen} so tests and the vector generator can
 * exercise the construction with small precomputed primes without weakening the
 * public API's parameter floor.
 */
export function fromSafePrimes(
  p: bigint,
  q: bigint,
  t: number,
  nAuth: number,
): ThresholdSetup {
  const n = p * q;
  const m = ((p - 1n) / 2n) * ((q - 1n) / 2n);
  const nSq = n * n;
  if (gcd(n, m) !== 1n) {
    throw new ConfigurationError('gcd(N, m) must be 1; primes are unsuitable');
  }

  // d = 0 (mod m), d = 1 (mod N), by CRT.
  const d = (m * invert(m, n)) % (n * m);

  // Shamir over Z_{N*m}, degree t-1, with f(0) = d.
  const modulus = n * m;
  const coefficients = [d];
  for (let i = 1; i < t; i++) coefficients.push(randomBelow(modulus));

  const f = (x: bigint): bigint => {
    let acc = 0n;
    for (let i = coefficients.length - 1; i >= 0; i--) {
      acc = (acc * x + (coefficients[i] as bigint)) % modulus;
    }
    return acc;
  };

  const delta = factorial(nAuth);
  const shares: KeyShare[] = [];
  for (let i = 1; i <= nAuth; i++) shares.push({ index: i, value: f(BigInt(i)), delta, n });

  // v is a random square, hence a generator of the squares in Z*_{N^2}.
  let base: bigint;
  do {
    base = randomBelow(nSq - 1n) + 1n;
  } while (gcd(base, n) !== 1n);
  const v = (base * base) % nSq;
  const keys = shares.map((s) => powMod(v, delta * s.value, nSq));

  return {
    publicKey: makePublicKey(n, n + 1n),
    shares,
    verificationKeys: { v, keys, t, nAuth, delta },
  };
}

/**
 * Bit length of the blinding factor `a` in a decryption proof.
 *
 * The witness is `Delta * f(i)`, and shares are drawn modulo `N*m` with
 * `m = p'q' < N/4`, so the witness is roughly `2*bitlen(N) + bitlen(Delta)`
 * bits -- **twice** the modulus width, not once.
 *
 * An earlier draft of the specification bounded `a` by `2^(bits + 2*256)`, which
 * is smaller than `e * Delta * f(i)` and therefore does not hide the share at
 * all. The bound below is derived only from public values, so both
 * implementations agree on it and on the resulting encoding width.
 */
export function blindingBits(pk: PaillierPublicKey, vk: VerificationKeys): number {
  return 2 * pk.bits + bitLength(vk.delta) + 256 + STAT_SECURITY_BITS;
}

/** Fixed encoding width for the proof response `z`. */
export function responseByteLen(pk: PaillierPublicKey, vk: VerificationKeys): number {
  return Math.floor((blindingBits(pk, vk) + 2 + 7) / 8);
}

function decryptionChallenge(
  ctx: Uint8Array,
  authority: number,
  c: bigint,
  ci: bigint,
  vki: bigint,
  u1: bigint,
  u2: bigint,
  ln: number,
): bigint {
  const digest = sha256(
    concatBytes(
      DST_DEC,
      ctx,
      encU32(authority),
      encN2(c, ln),
      encN2(ci, ln),
      encN2(vki, ln),
      encN2(u1, ln),
      encN2(u2, ln),
    ),
  );
  return os2ip(digest) % CHALLENGE_MODULUS;
}

/** Compute this authority's partial decryption, with its correctness proof. */
export function partialDecrypt(
  c: bigint,
  share: KeyShare,
  pk: PaillierPublicKey,
  vk: VerificationKeys,
  ctx: Uint8Array,
): PartialDecryption {
  if (!isValidCiphertext(c, pk.n)) {
    throw new InvalidCiphertextError('ciphertext is not a unit in Z*_(N^2)');
  }
  const { nSquared: nSq, byteLen: ln } = pk;
  const exponent = vk.delta * share.value;

  const ci = powMod(c, 2n * exponent, nSq);
  const vki = vk.keys[share.index - 1] as bigint;

  // Chaum-Pedersen: prove the same exponent Delta*f(i) appears in c_i^2 with
  // base c^4, and in vk_i with base v.
  //
  // An earlier draft of the specification named the first base as c^(4*Delta),
  // which cannot satisfy its own verification equation -- that recomputation
  // only closes when Delta == 1. Its stated intent ("the same exponent
  // Delta*f(i) was used in both") is met exactly by c^4, since
  // c_i^2 = c^(4*Delta*f(i)).
  const base1 = powMod(c, 4n, nSq);

  // The blinding factor must exceed e * Delta * f(i) by a statistical security
  // margin, or z = a + e*Delta*f(i) leaks the share.
  const a = randomBelow(1n << BigInt(blindingBits(pk, vk)));
  const u1 = powMod(base1, a, nSq);
  const u2 = powMod(vk.v, a, nSq);

  const e = decryptionChallenge(ctx, share.index, c, ci, vki, u1, u2, ln);
  return { authority: share.index, value: ci, proof: { e, z: a + e * exponent } };
}

/** Verify a partial decryption's correctness proof. Never throws. */
export function verifyPartial(
  c: bigint,
  partial: PartialDecryption,
  pk: PaillierPublicKey,
  vk: VerificationKeys,
  ctx: Uint8Array,
): boolean {
  const { nSquared: nSq, byteLen: ln } = pk;
  if (!isValidCiphertext(c, pk.n)) return false;
  if (!(partial.authority >= 1 && partial.authority <= vk.nAuth)) return false;
  if (!isValidCiphertext(partial.value, pk.n)) return false;
  if (!(partial.proof.e >= 0n && partial.proof.e < CHALLENGE_MODULUS) || partial.proof.z < 0n) {
    return false;
  }

  const vki = vk.keys[partial.authority - 1] as bigint;
  const { e, z } = partial.proof;

  try {
    const base1 = powMod(c, 4n, nSq);
    const u1 =
      (powMod(base1, z, nSq) *
        invert(powMod((partial.value * partial.value) % nSq, e, nSq), nSq)) %
      nSq;
    const u2 = (powMod(vk.v, z, nSq) * invert(powMod(vki, e, nSq), nSq)) % nSq;
    return e === decryptionChallenge(ctx, partial.authority, c, partial.value, vki, u1, u2, ln);
  } catch {
    return false;
  }
}

/**
 * `Delta * prod_{j != i} j / (j - i)` -- an integer by construction.
 *
 * `Delta = nAuth!` is divisible by every product of index differences, so the
 * Lagrange coefficient stays in the integers, where exponent arithmetic must
 * live.
 */
function lagrange(subset: readonly number[], i: number, delta: bigint): bigint {
  let numerator = delta;
  let denominator = 1n;
  for (const j of subset) {
    if (j !== i) {
      numerator *= BigInt(j);
      denominator *= BigInt(j - i);
    }
  }
  if (numerator % denominator !== 0n) {
    throw new InvalidShareError(i, 'Lagrange coefficient is not an integer');
  }
  return numerator / denominator;
}

/**
 * Combine at least `t` verified partial decryptions into the plaintext.
 *
 * Every partial is verified internally and a failure throws
 * {@link InvalidShareError} naming the authority. Callers cannot opt out:
 * combining an unproven share is what would let a dishonest authority move the
 * published total.
 */
export function combineShares(
  c: bigint,
  parts: readonly PartialDecryption[],
  pk: PaillierPublicKey,
  vk: VerificationKeys,
  ctx: Uint8Array,
): bigint {
  if (!isValidCiphertext(c, pk.n)) {
    throw new InvalidCiphertextError('ciphertext is not a unit in Z*_(N^2)');
  }

  const seen = new Map<number, PartialDecryption>();
  for (const part of parts) {
    if (seen.has(part.authority)) throw new InvalidShareError(part.authority, 'duplicate authority');
    if (!verifyPartial(c, part, pk, vk, ctx)) {
      throw new InvalidShareError(part.authority, 'correctness proof failed');
    }
    seen.set(part.authority, part);
  }
  if (seen.size < vk.t) {
    throw new InvalidShareError(0, `need ${vk.t} shares, got ${seen.size}`);
  }

  const { n, nSquared: nSq } = pk;
  const subset = [...seen.keys()].sort((a, b) => a - b);

  let combined = 1n;
  for (const i of subset) {
    const exponent = 2n * lagrange(subset, i, vk.delta);
    const magnitude = exponent < 0n ? -exponent : exponent;
    let term = powMod((seen.get(i) as PartialDecryption).value, magnitude, nSq);
    if (exponent < 0n) term = invert(term, nSq);
    combined = (combined * term) % nSq;
  }

  // combined == c^(4*Delta^2*d) == g^(4*Delta^2*M), so L() then divides out.
  const scale = (4n * vk.delta * vk.delta) % n;
  return (((combined - 1n) / n) * invert(scale, n)) % n;
}

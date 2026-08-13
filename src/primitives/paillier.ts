/**
 * Paillier cryptosystem (spec section 2).
 *
 * Additively homomorphic: `E(m1) * E(m2) = E(m1 + m2)`, which is what lets the
 * tally be computed on ciphertexts so no individual ballot is ever opened.
 *
 * Two preconditions the research prototype omitted are enforced here, and both
 * are load bearing:
 *
 * - `gcd(N, phi(N)) == 1` is required for the encryption map to be bijective and
 *   for `lam^-1 mod N` to exist at all.
 * - `isValidCiphertext` is checked at every entry point that accepts a
 *   ciphertext. Its absence is break **C5**: for `c = 0` both OR-proof branches
 *   collapse to `0 = 0`, a proof with `z0 = z1 = 0` verifies, and the
 *   homomorphic product of the entire election becomes zero. One ballot
 *   destroys the result, undetectably.
 */

import { ConfigurationError, InvalidCiphertextError, InvalidPlaintextError } from '../errors.js';
import { bitLength, gcd, invert, lcm, powMod, randomPrime, randomSafePrime } from '../math.js';
import { randomUnit } from '../rng.js';
import { modulusByteLen } from '../serialization/encoding.js';

/** Floor from the spec. The research prototype used 1024 bits everywhere. */
export const MIN_MODULUS_BITS = 2048;

/** `(N, g)` with the invariant `g == N + 1`. */
export interface PaillierPublicKey {
  readonly n: bigint;
  readonly g: bigint;
  readonly nSquared: bigint;
  readonly byteLen: number;
  readonly bits: number;
}

/**
 * `(lam, mu)` plus the factors.
 *
 * `p` and `q` are retained deliberately: they enable CRT-accelerated decryption
 * and are required to split the key for threshold mode. The research prototype
 * discarded them, which made both impossible.
 */
export interface PaillierPrivateKey {
  readonly lam: bigint;
  readonly mu: bigint;
  readonly p: bigint;
  readonly q: bigint;
  /** Always throws. Private keys must not be persisted by this library. */
  toJSON(): never;
}

export function makePublicKey(n: bigint, g: bigint): PaillierPublicKey {
  if (n <= 0n) throw new ConfigurationError('modulus must be positive');
  if (g !== n + 1n) throw new ConfigurationError(`g must equal n + 1 (got g - n = ${g - n})`);
  return { n, g, nSquared: n * n, byteLen: modulusByteLen(n), bits: bitLength(n) };
}

function makePrivateKey(lam: bigint, mu: bigint, p: bigint, q: bigint): PaillierPrivateKey {
  return {
    lam,
    mu,
    p,
    q,
    toJSON(): never {
      throw new ConfigurationError('a Paillier private key must not be serialized');
    },
    // Redacted: key material must never reach a log or a stack trace.
    toString: () => 'PaillierPrivateKey(<redacted>)',
    [Symbol.for('nodejs.util.inspect.custom')]: () => 'PaillierPrivateKey(<redacted>)',
  } as PaillierPrivateKey;
}

/**
 * `L(x) = (x - 1) / N`, exact division on a non-negative `x`.
 *
 * The research prototype computed this with floor semantics on a possibly
 * negative value, which silently returns `-1` instead of failing.
 */
function lFunction(x: bigint, n: bigint): bigint {
  return (x - 1n) / n;
}

/**
 * Generate a keypair.
 *
 * Async so that a long prime search yields to the event loop instead of
 * freezing the page; the arithmetic itself is synchronous.
 *
 * `safePrimes` is required for threshold mode and is slow -- minutes at 3072
 * bits -- because both `p'` and `2p' + 1` must be prime.
 */
export async function paillierKeygen(
  bits = 3072,
  options: { safePrimes?: boolean } = {},
): Promise<[PaillierPublicKey, PaillierPrivateKey]> {
  if (bits < MIN_MODULUS_BITS) {
    throw new ConfigurationError(`modulus must be at least ${MIN_MODULUS_BITS} bits, got ${bits}`);
  }
  const half = Math.floor((bits + 1) / 2);
  const generate = options.safePrimes ? randomSafePrime : randomPrime;
  // Below this gap p and q are close enough for Fermat factorization.
  const minGap = 1n << BigInt(half - 100);

  for (;;) {
    const p = generate(half);
    await Promise.resolve();
    const q = generate(half);
    await Promise.resolve();

    const gap = p > q ? p - q : q - p;
    if (p === q || gap < minGap) continue;
    const n = p * q;
    if (bitLength(n) !== bits) continue;
    const phi = (p - 1n) * (q - 1n);
    if (gcd(n, phi) !== 1n) continue;

    const lam = lcm(p - 1n, q - 1n);
    return [makePublicKey(n, n + 1n), makePrivateKey(lam, invert(lam, n), p, q)];
  }
}

/**
 * `0 < c < N^2` and `gcd(c, N) == 1`.
 *
 * Every function accepting a ciphertext calls this first. It is the single
 * check that closes the tally-annihilation attack (break C5): requiring `c` to
 * be a unit excludes `0`, `N`, and every other non-unit.
 */
export function isValidCiphertext(c: bigint, n: bigint): boolean {
  return c > 0n && c < n * n && gcd(c, n) === 1n;
}

function requireCiphertext(c: bigint, n: bigint): void {
  if (!isValidCiphertext(c, n)) {
    throw new InvalidCiphertextError(`ciphertext is not a unit in Z*_(N^2) (c mod N = ${c % n})`);
  }
}

/**
 * Encrypt `m`, returning `[c, r]`.
 *
 * @remarks
 * `r` is a **receipt**. Anyone holding `(m, r)` can recompute `c` and locate the
 * ballot on the board, proving how the voter voted. This is structural, not an
 * implementation flaw, and it is why ZKTally is not receipt-free. `castBallot`
 * discards `r` as soon as the proof is built; callers must not persist it.
 */
export function encrypt(m: bigint, pk: PaillierPublicKey): [bigint, bigint] {
  const r = randomUnit(pk.n);
  return [encryptWith(m, r, pk), r];
}

/**
 * Deterministic encryption with caller-supplied randomness.
 *
 * `(1 + m*N)` is used instead of `g^m mod N^2`: for `g = N + 1` the binomial
 * theorem makes it exact, and it avoids a modular exponentiation.
 */
export function encryptWith(m: bigint, r: bigint, pk: PaillierPublicKey): bigint {
  const { n, nSquared } = pk;
  if (!(m >= 0n && m < n)) {
    throw new InvalidPlaintextError(
      `plaintext must be in [0, N), got a ${bitLength(m < 0n ? -m : m)}-bit value`,
    );
  }
  if (!(r >= 1n && r < n) || gcd(r, n) !== 1n) {
    throw new InvalidPlaintextError('randomness must be a unit in [1, N)');
  }
  return ((1n + m * n) * powMod(r, n, nSquared)) % nSquared;
}

/**
 * Recover the plaintext.
 *
 * Uses the Chinese Remainder Theorem over `p^2` and `q^2`: about four times
 * faster than exponentiating modulo `N^2`, and required to be bit-identical to
 * the direct computation.
 */
export function decrypt(c: bigint, pk: PaillierPublicKey, sk: PaillierPrivateKey): bigint {
  requireCiphertext(c, pk.n);
  const pSq = sk.p * sk.p;
  const qSq = sk.q * sk.q;
  const mP = powMod(c % pSq, sk.lam, pSq);
  const mQ = powMod(c % qSq, sk.lam, qSq);
  const u = crt(mP, pSq, mQ, qSq);
  return (lFunction(u, pk.n) * sk.mu) % pk.n;
}

/** Recombine two residues into one modulo `m1 * m2`. */
function crt(a1: bigint, m1: bigint, a2: bigint, m2: bigint): bigint {
  const diff = ((a2 - a1) * invert(m1, m2)) % m2;
  return (a1 + m1 * ((diff + m2) % m2)) % (m1 * m2);
}

/**
 * Homomorphic sum: the product of the ciphertexts modulo `N^2`.
 *
 * `decrypt(aggregate(cs)) == (sum of the plaintexts) mod N`. With a 2048-bit
 * modulus and one-bit votes the sum cannot overflow at any realistic electorate
 * size.
 */
export function aggregate(cs: readonly bigint[], pk: PaillierPublicKey): bigint {
  if (cs.length === 0) throw new InvalidCiphertextError('cannot aggregate an empty list');
  let total = 1n;
  for (const c of cs) {
    requireCiphertext(c, pk.n);
    total = (total * c) % pk.nSquared;
  }
  return total;
}

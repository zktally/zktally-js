/**
 * BigInt modular arithmetic and primality testing.
 *
 * JavaScript has no `pow(base, exp, mod)`, so the square-and-multiply ladder
 * here is the hot path of the entire package -- Paillier operates modulo `N^2`,
 * which is 6144 bits at the recommended parameters.
 *
 * @remarks
 * `BigInt` arithmetic is **not constant-time** and the JIT's behaviour is not
 * predictable. Nothing in this module should be assumed side-channel resistant.
 */

import { randomBits } from './rng.js';

export function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

/** `base ** exp mod m`, right-to-left square and multiply. */
export function powMod(base: bigint, exp: bigint, m: bigint): bigint {
  if (m <= 0n) throw new RangeError('modulus must be positive');
  if (m === 1n) return 0n;
  if (exp < 0n) return powMod(invert(base, m), -exp, m);
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

/** Extended Euclid. Throws when `a` is not invertible modulo `m`. */
export function invert(a: bigint, m: bigint): bigint {
  if (m <= 0n) throw new RangeError('modulus must be positive');
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new RangeError(`${a} is not invertible modulo ${m}`);
  return mod(old_s, m);
}

export function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y) [x, y] = [y, x % y];
  return x;
}

export function lcm(a: bigint, b: bigint): bigint {
  return (a / gcd(a, b)) * b;
}

export function bitLength(n: bigint): number {
  if (n < 0n) throw new RangeError('bitLength of a negative integer');
  return n === 0n ? 0 : n.toString(2).length;
}

/** Integer square root, Newton's method. Used by the Lucas test. */
function isqrt(n: bigint): bigint {
  if (n < 2n) return n;
  let x = 1n << BigInt(Math.ceil(bitLength(n) / 2));
  for (;;) {
    const y = (x + n / x) >> 1n;
    if (y >= x) return x;
    x = y;
  }
}

function isPerfectSquare(n: bigint): boolean {
  const r = isqrt(n);
  return r * r === n;
}

const SMALL_PRIMES: readonly bigint[] = (() => {
  const limit = 1000;
  const sieve = new Uint8Array(limit + 1).fill(1);
  sieve[0] = 0;
  sieve[1] = 0;
  for (let i = 2; i * i <= limit; i++) {
    if (sieve[i]) for (let j = i * i; j <= limit; j += i) sieve[j] = 0;
  }
  const out: bigint[] = [];
  for (let i = 2; i <= limit; i++) if (sieve[i]) out.push(BigInt(i));
  return out;
})();

function millerRabin(n: bigint, base: bigint): boolean {
  let d = n - 1n;
  let s = 0n;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s += 1n;
  }
  let x = powMod(base, d, n);
  if (x === 1n || x === n - 1n) return true;
  for (let i = 1n; i < s; i++) {
    x = (x * x) % n;
    if (x === n - 1n) return true;
  }
  return false;
}

function jacobi(a: bigint, n: bigint): number {
  let x = mod(a, n);
  let y = n;
  let result = 1;
  while (x !== 0n) {
    while ((x & 1n) === 0n) {
      x >>= 1n;
      const r = y % 8n;
      if (r === 3n || r === 5n) result = -result;
    }
    [x, y] = [y, x];
    if (x % 4n === 3n && y % 4n === 3n) result = -result;
    x %= y;
  }
  return y === 1n ? result : 0;
}

/** Strong Lucas probable-prime test with Selfridge's parameter choice. */
function strongLucas(n: bigint): boolean {
  if (isPerfectSquare(n)) return false;

  let d = 5n;
  for (;;) {
    const j = jacobi(d, n);
    if (j === -1) break;
    if (j === 0 && (d < 0n ? -d : d) !== n) return false;
    d = d > 0n ? -(d + 2n) : -(d - 2n);
  }
  const q = (1n - d) / 4n;

  let k = n + 1n;
  let s = 0n;
  while ((k & 1n) === 0n) {
    k >>= 1n;
    s += 1n;
  }

  // Compute U_k, V_k by binary ladder on the Lucas sequences.
  let [u, v, qk] = [1n, 1n, q];
  const bits = k.toString(2).slice(1);
  for (const bit of bits) {
    u = (u * v) % n;
    v = (v * v - 2n * qk) % n;
    qk = (qk * qk) % n;
    if (bit === '1') {
      const u2 = (u + v) % n;
      const v2 = (v + u * d) % n;
      // Halving requires the values to be even before the shift.
      u = mod(u2 & 1n ? u2 + n : u2, 2n * n) / 2n;
      v = mod(v2 & 1n ? v2 + n : v2, 2n * n) / 2n;
      qk = (qk * q) % n;
    }
  }
  if (mod(u, n) === 0n || mod(v, n) === 0n) return true;
  for (let i = 1n; i < s; i++) {
    v = mod(v * v - 2n * qk, n);
    if (v === 0n) return true;
    qk = (qk * qk) % n;
  }
  return false;
}

/**
 * Baillie-PSW primality test: trial division, then a base-2 Miller-Rabin, then
 * a strong Lucas test.
 *
 * No composite is known to pass this combination. The research prototype used a
 * plain Fermat test, which every Carmichael number passes.
 */
export function isProbablePrime(n: bigint): boolean {
  if (n < 2n) return false;
  for (const p of SMALL_PRIMES) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  if (!millerRabin(n, 2n)) return false;
  return strongLucas(n);
}

/** A random prime of exactly `bits` bits, from the platform CSPRNG. */
export function randomPrime(bits: number): bigint {
  for (;;) {
    const candidate = randomBits(bits) | (1n << BigInt(bits - 1)) | 1n;
    if (isProbablePrime(candidate)) return candidate;
  }
}

/** A prime `p = 2p' + 1` with `p'` also prime, needed for threshold mode. */
export function randomSafePrime(bits: number): bigint {
  for (;;) {
    const q = randomBits(bits - 1) | (1n << BigInt(bits - 2)) | 1n;
    if (!isProbablePrime(q)) continue;
    const p = 2n * q + 1n;
    if (bitLength(p) === bits && isProbablePrime(p)) return p;
  }
}

/** `n!` as a bigint. `Delta` in the threshold scheme. */
export function factorial(n: number): bigint {
  let out = 1n;
  for (let i = 2n; i <= BigInt(n); i++) out *= i;
  return out;
}

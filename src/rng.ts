/**
 * The single randomness seam.
 *
 * Every random draw in the package routes through here, for two reasons. The
 * vector generator needs a deterministic source, and having exactly one entry
 * point makes "no weak randomness anywhere" a property that can be checked by
 * reading one file rather than auditing every call site.
 *
 * Break **C4** in the research prototype was `random.randint` -- a Mersenne
 * Twister -- for LSAG nonces. Decoy responses are published in the signature,
 * so roughly 80 signatures recover the generator state and hence the signing
 * key. `Math.random` is the same mistake in this language and MUST NOT appear
 * anywhere in `src/`.
 */

import { gcd } from './math.js';

export interface RandomSource {
  bytes(count: number): Uint8Array;
}

class WebCryptoSource implements RandomSource {
  bytes(count: number): Uint8Array {
    const out = new Uint8Array(count);
    // getRandomValues caps at 65536 bytes per call.
    for (let offset = 0; offset < count; offset += 65536) {
      crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65536, count)));
    }
    return out;
  }
}

const systemSource: RandomSource = new WebCryptoSource();
let current: RandomSource = systemSource;

/**
 * Run `fn` with a caller-supplied random source.
 *
 * Intended for reproducing the conformance corpus and for tests. Restores the
 * platform CSPRNG afterwards even if `fn` throws.
 */
export function withRandomSource<T>(source: RandomSource, fn: () => T): T {
  const previous = current;
  current = source;
  try {
    return fn();
  } finally {
    current = previous;
  }
}

export function randomBytes(count: number): Uint8Array {
  return current.bytes(count);
}

/** Uniform in `[0, bound)` by rejection sampling. */
export function randomBelow(bound: bigint): bigint {
  if (bound <= 0n) throw new RangeError('bound must be positive');
  const bits = bound.toString(2).length;
  const byteLen = Math.ceil(bits / 8);
  const excess = BigInt(byteLen * 8 - bits);
  for (;;) {
    let value = 0n;
    for (const b of randomBytes(byteLen)) value = (value << 8n) | BigInt(b);
    value >>= excess;
    if (value < bound) return value;
  }
}

/** Uniform in `[0, 2**bits)`. */
export function randomBits(bits: number): bigint {
  if (bits <= 0) throw new RangeError('bits must be positive');
  const byteLen = Math.ceil(bits / 8);
  let value = 0n;
  for (const b of randomBytes(byteLen)) value = (value << 8n) | BigInt(b);
  return value >> BigInt(byteLen * 8 - bits);
}

/** Uniform unit in `[1, n)`: a random element of `Z*_n`. */
export function randomUnit(n: bigint): bigint {
  for (;;) {
    const candidate = randomBelow(n);
    if (candidate > 0n && gcd(candidate, n) === 1n) return candidate;
  }
}

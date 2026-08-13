/**
 * Canonical byte encoding.
 *
 * Every encoding here is **injective**: distinct inputs produce distinct byte
 * strings. That property is what makes a concatenated hash transcript
 * unambiguous, and it is exactly what the research prototype lacked -- it used
 * minimal-width big-endian integers with no separators, so `0` encoded to the
 * empty string and adjacent fields could be re-partitioned by an adversary.
 *
 * Widths are fixed for a whole election and derived from the modulus:
 *
 * | Symbol | Definition             | 2048-bit `N` | 3072-bit `N` |
 * | ------ | ---------------------- | ------------ | ------------ |
 * | `LN`   | `ceil(bitlen(N) / 8)`  | 256          | 384          |
 * | `LN2`  | `2 * LN`               | 512          | 768          |
 * | `LQ`   | secp256k1 scalar       | 32           | 32           |
 * | `LP`   | compressed point       | 33           | 33           |
 */

import { DecodingError } from '../errors.js';
import { bitLength } from '../math.js';

/** `LQ` -- secp256k1 scalars, LSAG responses, ring challenges. */
export const SCALAR_BYTES = 32;

/** NIZK challenges. The challenge space is `2**256`. */
export const CHALLENGE_BYTES = 32;

/** `LP` -- compressed SEC1. */
export const POINT_BYTES = 33;

/**
 * Integer-to-octet-string, big-endian, exactly `length` bytes.
 *
 * Throws on a negative value or one too large to fit, rather than truncating or
 * growing the field -- a silently variable width would break injectivity.
 */
export function i2osp(x: bigint, length: number): Uint8Array {
  if (length < 0) throw new RangeError(`length must be non-negative, got ${length}`);
  if (x < 0n) throw new RangeError(`cannot encode negative integer ${x}`);
  if (x >= 1n << BigInt(8 * length)) {
    throw new RangeError(`integer does not fit in ${length} bytes: ${bitLength(x)} bits needed`);
  }
  const out = new Uint8Array(length);
  let v = x;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Octet-string-to-integer, big-endian. Inverse of {@link i2osp}. */
export function os2ip(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  return value;
}

/** `LN` for a Paillier modulus `n`. */
export function modulusByteLen(n: bigint): number {
  if (n <= 0n) throw new RangeError('modulus must be positive');
  return Math.ceil(bitLength(n) / 8);
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** 4 bytes. Lengths, indices, counts. */
export function encU32(x: number): Uint8Array {
  return i2osp(BigInt(x), 4);
}

/** `LN` bytes. Plaintexts, randomness, `z` responses, `N` itself. */
export function encN(x: bigint, ln: number): Uint8Array {
  return i2osp(x, ln);
}

/** `LN2 = 2*LN` bytes. Ciphertexts and commitments `A`. */
export function encN2(x: bigint, ln: number): Uint8Array {
  return i2osp(x, 2 * ln);
}

/** 32 bytes. Curve scalars. */
export function encScalar(x: bigint): Uint8Array {
  return i2osp(x, SCALAR_BYTES);
}

/** 32 bytes. NIZK challenges. */
export function encChal(x: bigint): Uint8Array {
  return i2osp(x, CHALLENGE_BYTES);
}

/**
 * `Enc_u32(len(b)) || b`.
 *
 * The only encoding permitted for variable-length data. The length prefix is
 * what keeps a concatenated transcript unambiguous.
 */
export function encBytes(b: Uint8Array): Uint8Array {
  return concatBytes(encU32(b.length), b);
}

/** UTF-8, NFC-normalized, length-prefixed. */
export function encString(s: string): Uint8Array {
  return encBytes(new TextEncoder().encode(s.normalize('NFC')));
}

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** base64url without padding (RFC 4648 section 5). */
export function b64uEncode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] as number;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += B64_ALPHABET[b0 >> 2];
    out += B64_ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    if (b1 === undefined) break;
    out += B64_ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    if (b2 === undefined) break;
    out += B64_ALPHABET[b2 & 0x3f];
  }
  return out;
}

/**
 * Inverse of {@link b64uEncode}, with an optional exact-length check.
 *
 * JSON envelopes carry big integers as base64url of their *fixed-width* bytes,
 * so the expected length is always known and checking it rejects malformed
 * input before any arithmetic happens.
 */
export function b64uDecode(s: unknown, expectLen?: number): Uint8Array {
  if (typeof s !== 'string') {
    throw new DecodingError(`expected a base64url string, got ${typeof s}`);
  }
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of s) {
    const index = B64_ALPHABET.indexOf(ch);
    if (index < 0) throw new DecodingError(`invalid base64url character ${JSON.stringify(ch)}`);
    buffer = (buffer << 6) | index;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  const raw = Uint8Array.from(out);
  // Reject non-canonical encodings: re-encoding must reproduce the input.
  if (b64uEncode(raw) !== s) throw new DecodingError('non-canonical base64url encoding');
  if (expectLen !== undefined && raw.length !== expectLen) {
    throw new DecodingError(`expected ${expectLen} bytes, decoded ${raw.length}`);
  }
  return raw;
}

/** Decode a fixed-width base64url big integer. */
export function b64uInt(s: unknown, expectLen: number): bigint {
  return os2ip(b64uDecode(s, expectLen));
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new DecodingError('hex string has an odd length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new DecodingError('invalid hex string');
    out[i] = byte;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

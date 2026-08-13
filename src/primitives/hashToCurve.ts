/**
 * RFC 9380 hash-to-curve, suite `secp256k1_XMD:SHA-256_SSWU_RO_`.
 *
 * This module exists to fix break **C1**. The research prototype's "hash to
 * point" was:
 *
 * ```text
 * H_p(P) = SHA256(P) * G
 * ```
 *
 * which makes the scalar `h_P = SHA256(P)` public, and therefore makes the key
 * image
 *
 * ```text
 * I = x * (h_P * G) = h_P * (x * G) = h_P * P
 * ```
 *
 * computable by anyone holding the *public* key. Every published key image
 * identified its voter, so the ring signature provided no anonymity whatsoever.
 *
 * The property LSAG actually needs is that `log_G(H_p(P))` be **unknown**.
 * RFC 9380's Simplified SWU map has no such structure.
 *
 * The implementation is `@noble/curves`, verified against the Python port's
 * independent implementation over randomized inputs under the production DST.
 */

import { secp256k1_hasher } from '@noble/curves/secp256k1.js';

import type { Point } from './curve.js';

/** Hash `msg` to a secp256k1 point with unknown discrete log with respect to `G`. */
export function hashToCurve(msg: Uint8Array, dst: Uint8Array): Point {
  return secp256k1_hasher.hashToCurve(msg, { DST: dst }) as Point;
}

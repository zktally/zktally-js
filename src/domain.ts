/**
 * Domain-separation tags.
 *
 * Every hash in the protocol is prefixed with one of these ASCII tags, written
 * without a length prefix -- they are constants of known length, so they are
 * unambiguous by construction.
 *
 * These bytes are wire-visible and MUST match the Python package exactly; a
 * single differing byte makes every cross-language proof fail to verify.
 */

const ascii = (s: string): Uint8Array => new TextEncoder().encode(s);

export const SPEC_VERSION = 'zktally/1';

export const DST_H2C = ascii('ZKTally-v1-secp256k1_XMD:SHA-256_SSWU_RO_');
export const DST_RING = ascii('ZKTally-v1:RING');
export const DST_LSAG = ascii('ZKTally-v1:LSAG');
export const DST_BIN = ascii('ZKTally-v1:NIZK-BINARY');
export const DST_NTH = ascii('ZKTally-v1:NIZK-NTHROOT');
export const DST_DEC = ascii('ZKTally-v1:DECPROOF');
export const DST_BALLOT = ascii('ZKTally-v1:BALLOT');

/** Challenge space for both NIZK transcripts. LSAG challenges reduce mod `q`. */
export const CHALLENGE_MODULUS = 1n << 256n;

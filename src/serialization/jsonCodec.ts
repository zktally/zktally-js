/**
 * JSON envelopes for storage, transport, and the bulletin board.
 *
 * Every big integer travels as base64url of its **fixed-width** big-endian
 * bytes, never as a JSON number: JavaScript's `number` is an IEEE-754 double and
 * loses precision above 2^53, so a 2048-bit ciphertext round-tripped through one
 * would be silently destroyed. This port is the reason the rule exists, and the
 * one where breaking it would be easiest.
 *
 * Fixed widths also give a cheap structural check -- every ciphertext in a
 * 2048-bit election is exactly 683 base64url characters -- and let a decoder
 * reject malformed input before any arithmetic happens.
 *
 * Decoders **recompute** `ringHash` and `ctx` rather than trusting the values in
 * the document. Both are derived, and both are exactly what an attacker would
 * want to control.
 */

import { SPEC_VERSION } from '../domain.js';
import { DecodingError, UnsupportedVersionError } from '../errors.js';
import { decodePoint, encodePoint, type Point } from '../primitives/curve.js';
import type { RingSignature } from '../primitives/lsag.js';
import type { BinaryProof, NthRootProof } from '../primitives/nizk.js';
import { makePublicKey } from '../primitives/paillier.js';
import { responseByteLen, type PartialDecryption, type VerificationKeys } from '../primitives/threshold.js';
import type { Ballot, BallotProof, RejectReason } from '../protocol/ballot.js';
import { Board } from '../protocol/board.js';
import { electionContext, makeElectionParams, type ElectionParams } from '../protocol/params.js';
import type { Rejection, TallyResult } from '../protocol/tally.js';
import {
  CHALLENGE_BYTES,
  POINT_BYTES,
  SCALAR_BYTES,
  b64uDecode,
  b64uEncode,
  bytesEqual,
  i2osp,
  os2ip,
} from './encoding.js';

type Json = Record<string, unknown>;

function encInt(value: bigint, width: number): string {
  return b64uEncode(i2osp(value, width));
}

function need(obj: unknown, key: string): unknown {
  if (typeof obj !== 'object' || obj === null || !(key in obj)) {
    throw new DecodingError(`missing required field ${JSON.stringify(key)}`);
  }
  return (obj as Json)[key];
}

function needArray(obj: unknown, key: string): unknown[] {
  const value = need(obj, key);
  if (!Array.isArray(value)) throw new DecodingError(`field ${JSON.stringify(key)} must be an array`);
  return value;
}

function decUint(obj: unknown, key: string, width: number): bigint {
  const raw = need(obj, key);
  if (typeof raw !== 'string') {
    throw new DecodingError(`field ${JSON.stringify(key)} must be a base64url string, not a JSON number`);
  }
  return os2ip(b64uDecode(raw, width));
}

function checkVersion(obj: unknown): void {
  const version = need(obj, 'specVersion');
  if (version !== SPEC_VERSION) {
    throw new UnsupportedVersionError(
      `document declares specVersion ${JSON.stringify(version)}; this build implements ${JSON.stringify(SPEC_VERSION)}`,
    );
  }
}

// --- ElectionParams ---------------------------------------------------------

export function paramsToDict(params: ElectionParams): Json {
  const pk = params.publicKey;
  const ln = pk.byteLen;
  const doc: Json = {
    specVersion: params.specVersion,
    electionId: b64uEncode(params.electionId),
    title: params.title,
    ballotType: params.ballotType,
    k: params.k,
    candidates: [...params.candidates],
    paillier: { bits: pk.bits, n: encInt(pk.n, ln), g: encInt(pk.g, 2 * ln) },
    trustModel: params.trustModel,
    ring: {
      ringHash: b64uEncode(params.ringHash),
      size: params.ring.length,
      anonymitySetSize: params.anonymitySetSize,
      subringIndex: params.subringIndex,
      numSubrings: params.numSubrings,
      members: params.ring.map((p) => b64uEncode(encodePoint(p))),
    },
    ctx: b64uEncode(electionContext(params)),
  };
  const vk = params.verificationKeys;
  if (vk) {
    doc['threshold'] = { t: vk.t, nAuth: vk.nAuth, delta: vk.delta.toString() };
    doc['verificationKeys'] = {
      v: encInt(vk.v, 2 * ln),
      vk: vk.keys.map((k) => encInt(k, 2 * ln)),
    };
  }
  return doc;
}

export function paramsFromDict(doc: unknown): ElectionParams {
  checkVersion(doc);
  const paillier = need(doc, 'paillier');
  const n = decUint(paillier, 'n', Math.ceil(Number(need(paillier, 'bits')) / 8));
  const ln = Math.ceil(n.toString(2).length / 8);
  const pk = makePublicKey(n, decUint(paillier, 'g', 2 * ln));

  const ringDoc = need(doc, 'ring');
  const members: Point[] = needArray(ringDoc, 'members').map((m) =>
    decodePoint(b64uDecode(m, POINT_BYTES)),
  );

  let vk: VerificationKeys | undefined;
  const record = doc as Json;
  if ('verificationKeys' in record) {
    const vkDoc = record['verificationKeys'];
    const th = need(doc, 'threshold');
    vk = {
      v: decUint(vkDoc, 'v', 2 * ln),
      keys: needArray(vkDoc, 'vk').map((k) => os2ip(b64uDecode(k, 2 * ln))),
      t: Number(need(th, 't')),
      nAuth: Number(need(th, 'nAuth')),
      delta: BigInt(String(need(th, 'delta'))),
    };
  }

  const params = makeElectionParams({
    electionId: b64uDecode(need(doc, 'electionId'), 32),
    title: String(need(doc, 'title')),
    ballotType: need(doc, 'ballotType') as ElectionParams['ballotType'],
    k: Number(need(doc, 'k')),
    candidates: needArray(doc, 'candidates').map(String),
    publicKey: pk,
    trustModel: need(doc, 'trustModel') as ElectionParams['trustModel'],
    ring: members,
    verificationKeys: vk,
    subringIndex: Number((ringDoc as Json)['subringIndex'] ?? 0),
    numSubrings: Number((ringDoc as Json)['numSubrings'] ?? 1),
  });

  // Derived values are recomputed, never trusted.
  if (!bytesEqual(b64uDecode(need(ringDoc, 'ringHash'), 32), params.ringHash)) {
    throw new DecodingError('ringHash does not match the supplied ring members');
  }
  if ('ctx' in record && !bytesEqual(b64uDecode(record['ctx'], 32), electionContext(params))) {
    throw new DecodingError('ctx does not match the supplied parameters');
  }
  return params;
}

// --- Ballot -----------------------------------------------------------------

function proofToDict(proof: BallotProof, ln: number): Json {
  if ('a0' in proof) {
    const p = proof as BinaryProof;
    return {
      type: 'binary',
      a0: encInt(p.a0, 2 * ln),
      a1: encInt(p.a1, 2 * ln),
      e0: encInt(p.e0, CHALLENGE_BYTES),
      e1: encInt(p.e1, CHALLENGE_BYTES),
      z0: encInt(p.z0, ln),
      z1: encInt(p.z1, ln),
    };
  }
  const p = proof as NthRootProof;
  return {
    type: 'nthroot',
    a: encInt(p.a, 2 * ln),
    e: encInt(p.e, CHALLENGE_BYTES),
    z: encInt(p.z, ln),
  };
}

function proofFromDict(doc: unknown, ln: number): BallotProof {
  const kind = need(doc, 'type');
  if (kind === 'binary') {
    return {
      a0: decUint(doc, 'a0', 2 * ln),
      a1: decUint(doc, 'a1', 2 * ln),
      e0: decUint(doc, 'e0', CHALLENGE_BYTES),
      e1: decUint(doc, 'e1', CHALLENGE_BYTES),
      z0: decUint(doc, 'z0', ln),
      z1: decUint(doc, 'z1', ln),
    };
  }
  if (kind === 'nthroot') {
    return {
      a: decUint(doc, 'a', 2 * ln),
      e: decUint(doc, 'e', CHALLENGE_BYTES),
      z: decUint(doc, 'z', ln),
    };
  }
  throw new DecodingError(`unknown proof type ${JSON.stringify(kind)}`);
}

export function ballotToDict(ballot: Ballot, ln: number): Json {
  const sig = ballot.signature;
  return {
    specVersion: SPEC_VERSION,
    ciphertexts: ballot.ciphertexts.map((c) => encInt(c, 2 * ln)),
    proofs: ballot.proofs.map((p) => proofToDict(p, ln)),
    signature: {
      keyImage: b64uEncode(encodePoint(sig.keyImage)),
      c0: encInt(sig.c0, SCALAR_BYTES),
      responses: sig.responses.map((r) => encInt(r, SCALAR_BYTES)),
    },
    subringIndex: ballot.subringIndex,
  };
}

export function ballotFromDict(doc: unknown, ln: number): Ballot {
  checkVersion(doc);
  const sigDoc = need(doc, 'signature');
  const signature: RingSignature = {
    keyImage: decodePoint(b64uDecode(need(sigDoc, 'keyImage'), POINT_BYTES)),
    c0: decUint(sigDoc, 'c0', SCALAR_BYTES),
    responses: needArray(sigDoc, 'responses').map((r) => os2ip(b64uDecode(r, SCALAR_BYTES))),
  };
  return {
    ciphertexts: needArray(doc, 'ciphertexts').map((c) => os2ip(b64uDecode(c, 2 * ln))),
    proofs: needArray(doc, 'proofs').map((p) => proofFromDict(p, ln)),
    signature,
    subringIndex: Number((doc as Json)['subringIndex'] ?? 0),
  };
}

// --- Board ------------------------------------------------------------------

export function boardToJSON(board: Board, indent?: number): string {
  const ln = board.params.publicKey.byteLen;
  return JSON.stringify(
    {
      specVersion: SPEC_VERSION,
      params: paramsToDict(board.params),
      ballots: board.ballots.map((b) => ballotToDict(b, ln)),
      closedAt: board.closed ? 'closed' : null,
    },
    null,
    indent,
  );
}

/** Parse a board. **Never reorders the ballots**: board order is normative. */
export function boardFromJSON(data: string): Board {
  let doc: unknown;
  try {
    doc = JSON.parse(data);
  } catch (cause) {
    throw new DecodingError(`invalid JSON: ${cause instanceof Error ? cause.message : cause}`);
  }
  checkVersion(doc);
  const params = paramsFromDict(need(doc, 'params'));
  const ln = params.publicKey.byteLen;
  const ballots = needArray(doc, 'ballots').map((b) => ballotFromDict(b, ln));
  return new Board(params, ballots, (doc as Json)['closedAt'] != null);
}

// --- TallyResult ------------------------------------------------------------

export function tallyToDict(result: TallyResult, params: ElectionParams): Json {
  const pk = params.publicKey;
  const ln = pk.byteLen;
  const vk = params.verificationKeys;
  const lz = vk ? responseByteLen(pk, vk) : ln;

  return {
    specVersion: SPEC_VERSION,
    electionId: b64uEncode(result.electionId),
    accepted: result.accepted,
    rejected: result.rejected.map((r) => ({ index: r.index, reason: r.reason })),
    aggregates: result.aggregates.map((c) => encInt(c, 2 * ln)),
    partialDecryptions: result.partials.map((column) =>
      column.map((p) => ({
        authority: p.authority,
        value: encInt(p.value, 2 * ln),
        proof: { e: encInt(p.proof.e, CHALLENGE_BYTES), z: encInt(p.proof.z, lz) },
      })),
    ),
    totals: result.totals.map((t) => Number(t)),
    verified: result.verified,
  };
}

export function tallyFromDict(doc: unknown, params: ElectionParams): TallyResult {
  checkVersion(doc);
  const pk = params.publicKey;
  const ln = pk.byteLen;
  const vk = params.verificationKeys;
  const lz = vk ? responseByteLen(pk, vk) : ln;

  const record = doc as Json;
  const partials: PartialDecryption[][] = ((record['partialDecryptions'] as unknown[]) ?? []).map(
    (column) =>
      (column as unknown[]).map((p) => ({
        authority: Number(need(p, 'authority')),
        value: decUint(p, 'value', 2 * ln),
        proof: {
          e: decUint(need(p, 'proof'), 'e', CHALLENGE_BYTES),
          z: decUint(need(p, 'proof'), 'z', lz),
        },
      })),
  );

  const rejected: Rejection[] = ((record['rejected'] as unknown[]) ?? []).map((r) => ({
    index: Number(need(r, 'index')),
    reason: need(r, 'reason') as RejectReason,
  }));

  return {
    electionId: b64uDecode(need(doc, 'electionId'), 32),
    totals: needArray(doc, 'totals').map((t) => BigInt(String(t))),
    accepted: Number(need(doc, 'accepted')),
    rejected,
    aggregates: needArray(doc, 'aggregates').map((c) => os2ip(b64uDecode(c, 2 * ln))),
    partials,
    verified: Boolean(record['verified'] ?? true),
  };
}

export function pointToJSON(point: Point): string {
  return b64uEncode(encodePoint(point));
}

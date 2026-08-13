/**
 * Tallying (spec section 8.5).
 *
 * Accepted ballots are aggregated per candidate column, and only the aggregate
 * is decrypted -- no individual ballot is ever opened. The result publishes the
 * aggregate ciphertexts, the partial decryptions, and their proofs, so any third
 * party can re-verify the outcome from public data with no secret at all. That
 * is what makes the tally publicly verifiable rather than merely announced.
 */

import { ConfigurationError } from '../errors.js';
import {
  aggregate,
  decrypt,
  type PaillierPrivateKey,
} from '../primitives/paillier.js';
import {
  combineShares,
  partialDecrypt,
  verifyPartial,
  type KeyShare,
  type PartialDecryption,
} from '../primitives/threshold.js';
import type { RejectReason } from './ballot.js';
import type { Board } from './board.js';
import { electionContext } from './params.js';

/**
 * What a third party was able to establish from public data.
 *
 * Deliberately not a single boolean. In single-authority mode the final
 * decryption carries no proof, so it is *unverifiable* rather than wrong, and
 * collapsing that into `true` would report an unchecked total as verified while
 * collapsing it into `false` would suggest the ballots failed. The distinction
 * is the whole point of the threshold mode, so it is surfaced.
 */
export interface TallyAudit {
  readonly ballotsOk: boolean;
  readonly aggregatesOk: boolean;
  readonly decryptionVerified: boolean;
  readonly decryptionVerifiable: boolean;
  readonly reason: string | null;
  /** Everything that *could* be checked was checked and passed. */
  readonly ok: boolean;
}

function audit(
  ballotsOk: boolean,
  aggregatesOk: boolean,
  decryptionVerified: boolean,
  decryptionVerifiable: boolean,
  reason: string | null = null,
): TallyAudit {
  return {
    ballotsOk,
    aggregatesOk,
    decryptionVerified,
    decryptionVerifiable,
    reason,
    ok: ballotsOk && aggregatesOk && (decryptionVerified || !decryptionVerifiable),
  };
}

/** A ballot that did not count, and why. */
export interface Rejection {
  readonly index: number;
  readonly reason: RejectReason;
}

/** The published outcome, including everything needed to re-verify it. */
export interface TallyResult {
  readonly electionId: Uint8Array;
  readonly totals: readonly bigint[];
  readonly accepted: number;
  readonly rejected: readonly Rejection[];
  readonly aggregates: readonly bigint[];
  readonly partials: readonly (readonly PartialDecryption[])[];
  readonly verified: boolean;
}

/**
 * Verify the board, aggregate the accepted ballots, and decrypt the totals.
 *
 * `secret` is either a plain private key (single-authority mode) or the key
 * shares of a quorum of authorities.
 */
export async function tally(
  board: Board,
  secret: PaillierPrivateKey | readonly KeyShare[],
  options: { quorum?: readonly number[] } = {},
): Promise<TallyResult> {
  const params = board.params;
  const pk = params.publicKey;
  const verdicts = await board.verifyAll();

  const accepted = board.ballots.filter((_, i) => verdicts[i]?.ok);
  const rejected: Rejection[] = [];
  verdicts.forEach((verdict, index) => {
    if (!verdict.ok) rejected.push({ index, reason: verdict.reason });
  });

  const columns = params.ballotType === 'binary' ? 1 : params.k;
  if (accepted.length === 0) {
    return {
      electionId: params.electionId,
      totals: Array.from({ length: columns }, () => 0n),
      accepted: 0,
      rejected,
      aggregates: [],
      partials: [],
      verified: true,
    };
  }

  const aggregates = Array.from({ length: columns }, (_, j) =>
    aggregate(
      accepted.map((b) => b.ciphertexts[j] as bigint),
      pk,
    ),
  );

  let totals: bigint[];
  let partials: PartialDecryption[][] = [];

  if (isPrivateKey(secret)) {
    totals = aggregates.map((c) => decrypt(c, pk, secret));
  } else {
    const vk = params.verificationKeys;
    if (!vk) throw new ConfigurationError('threshold tally requires verification keys');
    let shares = [...secret];
    if (options.quorum) {
      const wanted = new Set(options.quorum);
      shares = shares.filter((s) => wanted.has(s.index));
    }
    if (shares.length < vk.t) {
      throw new ConfigurationError(`need ${vk.t} shares to decrypt, got ${shares.length}`);
    }
    const ctx = electionContext(params);
    partials = aggregates.map((c) => shares.map((s) => partialDecrypt(c, s, pk, vk, ctx)));
    totals = aggregates.map((c, j) => combineShares(c, partials[j] as PartialDecryption[], pk, vk, ctx));
  }

  // For 1-of-k, the columns must sum to the number of accepted ballots. This
  // costs nothing and catches an aggregation or decryption error that would
  // otherwise pass silently.
  if (params.ballotType === 'one-of-k') {
    const sum = totals.reduce((a, b) => a + b, 0n);
    if (sum !== BigInt(accepted.length)) {
      throw new ConfigurationError(
        `tally inconsistent: columns sum to ${sum}, ${accepted.length} ballots accepted`,
      );
    }
  }

  return {
    electionId: params.electionId,
    totals,
    accepted: accepted.length,
    rejected,
    aggregates,
    partials,
    verified: true,
  };
}

function isPrivateKey(
  secret: PaillierPrivateKey | readonly KeyShare[],
): secret is PaillierPrivateKey {
  return !Array.isArray(secret);
}

/**
 * Re-verify a published tally from public data alone.
 *
 * Needs no secret material: it re-runs ballot verification, recomputes the
 * aggregates, and checks every partial-decryption proof. This is the executable
 * form of the public-verifiability claim.
 *
 * Returns a breakdown rather than a boolean, because under a single authority
 * the decryption step is genuinely uncheckable and saying so is more useful than
 * either verdict alone.
 */
export function auditTally(board: Board, result: TallyResult): TallyAudit {
  const params = board.params;
  const pk = params.publicKey;
  const threshold = params.trustModel === 'threshold';
  const failure = (reason: string): TallyAudit => audit(false, false, false, threshold, reason);

  if (!bytesMatch(result.electionId, params.electionId)) {
    return failure('result is for a different election');
  }

  const accepted = board.accepted();
  if (accepted.length !== result.accepted) {
    return failure(
      `result claims ${result.accepted} accepted ballots; the board yields ${accepted.length}`,
    );
  }

  const columns = params.ballotType === 'binary' ? 1 : params.k;
  if (accepted.length === 0) {
    const consistent = result.totals.every((total) => total === 0n);
    return audit(
      true,
      consistent,
      consistent,
      threshold,
      consistent ? null : 'empty board with a non-zero total',
    );
  }

  const expected = Array.from({ length: columns }, (_, j) =>
    aggregate(
      accepted.map((b) => b.ciphertexts[j] as bigint),
      pk,
    ),
  );
  if (
    expected.length !== result.aggregates.length ||
    expected.some((c, j) => c !== result.aggregates[j])
  ) {
    return audit(
      true,
      false,
      false,
      threshold,
      'published aggregates do not match the accepted ballots',
    );
  }

  if (!threshold) {
    // A single authority publishes no proof of correct decryption, so the totals
    // are asserted. Reporting them as verified would be false.
    return audit(
      true,
      true,
      false,
      false,
      'single-authority election: the decryption step carries no proof',
    );
  }

  const vk = params.verificationKeys;
  if (!vk || result.partials.length !== columns) {
    return failure('threshold result is missing partial decryptions');
  }

  const ctx = electionContext(params);
  for (let j = 0; j < columns; j++) {
    const c = result.aggregates[j] as bigint;
    const parts = result.partials[j] as readonly PartialDecryption[];
    if (new Set(parts.map((p) => p.authority)).size < vk.t) {
      return failure(`column ${j} has fewer than ${vk.t} distinct authorities`);
    }
    if (parts.some((p) => !verifyPartial(c, p, pk, vk, ctx))) {
      return failure(`column ${j} has a partial decryption whose proof fails`);
    }
    try {
      if (combineShares(c, parts, pk, vk, ctx) !== result.totals[j]) {
        return failure(`column ${j} total does not match its partial decryptions`);
      }
    } catch {
      return failure(`column ${j} partial decryptions could not be combined`);
    }
  }

  return audit(true, true, true, true);
}

/**
 * Whether everything checkable about a published tally checks out.
 *
 * Convenience wrapper over {@link auditTally}. Prefer the audit itself when
 * reporting to a user: under a single authority this returns `true` while the
 * totals themselves remain unproven.
 */
export function verifyTally(board: Board, result: TallyResult): boolean {
  return auditTally(board, result).ok;
}

function bytesMatch(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

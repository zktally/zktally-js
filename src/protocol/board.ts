/**
 * The bulletin board (spec section 8.4).
 *
 * An append-only list of ballots in cast order. Order is **normative**:
 * duplicate key images resolve first-wins, so the earliest valid ballot carrying
 * a given key image counts and every later one is rejected. A last-wins
 * implementation would produce a different tally from the same board, which
 * would make the outcome depend on the verifier rather than on the ballots.
 *
 * The board itself is assumed, not built: authentication and censorship
 * resistance are out of scope, and a malicious board can still drop ballots or
 * show different views to different readers.
 */

import type { SignOptions } from '../primitives/lsag.js';
import { keyImageKey, verifyBallotSync, type Ballot, type BallotVerdict } from './ballot.js';
import type { ElectionParams } from './params.js';

/** An append-only record of cast ballots. */
export class Board {
  readonly params: ElectionParams;
  readonly ballots: Ballot[];
  closed: boolean;

  constructor(params: ElectionParams, ballots: readonly Ballot[] = [], closed = false) {
    this.params = params;
    this.ballots = [...ballots];
    this.closed = closed;
  }

  /** Append a ballot and return its index. Does not verify. */
  append(ballot: Ballot): number {
    if (this.closed) throw new Error('board is closed');
    this.ballots.push(ballot);
    return this.ballots.length - 1;
  }

  get length(): number {
    return this.ballots.length;
  }

  /**
   * Verify every ballot in board order, resolving duplicates first-wins.
   *
   * A key image enters the seen set only when its ballot is *accepted*, so a
   * ballot rejected for a bad proof does not burn the key image and block a
   * later valid ballot from the same voter.
   */
  verifyAllSync(options: SignOptions = {}): BallotVerdict[] {
    const seen = new Set<string>();
    const verdicts: BallotVerdict[] = [];
    for (const ballot of this.ballots) {
      const verdict = verifyBallotSync(ballot, this.params, seen, options);
      if (verdict.ok) seen.add(keyImageKey(ballot));
      verdicts.push(verdict);
    }
    return verdicts;
  }

  /**
   * Async form of {@link verifyAllSync}, yielding to the event loop between
   * ballots so a large board does not freeze the page.
   */
  async verifyAll(options: SignOptions = {}): Promise<BallotVerdict[]> {
    const seen = new Set<string>();
    const verdicts: BallotVerdict[] = [];
    for (const ballot of this.ballots) {
      options.signal?.throwIfAborted();
      const verdict = verifyBallotSync(ballot, this.params, seen);
      if (verdict.ok) seen.add(keyImageKey(ballot));
      verdicts.push(verdict);
      options.onProgress?.(verdicts.length / this.ballots.length);
      await Promise.resolve();
    }
    return verdicts;
  }

  /** The ballots that pass verification, in board order. */
  accepted(): Ballot[] {
    const verdicts = this.verifyAllSync();
    return this.ballots.filter((_, i) => (verdicts[i] as BallotVerdict).ok);
  }
}

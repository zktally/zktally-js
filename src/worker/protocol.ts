/**
 * The message shapes exchanged with the worker.
 *
 * Election parameters, ballots, and boards cross the boundary as their JSON
 * envelopes rather than as live objects. `bigint` and curve points are not
 * structured-cloneable in a form both sides agree on, and reusing the wire codec
 * means the worker boundary is validated by the same decoder that guards the
 * network -- one hostile-input surface instead of two.
 */

export interface CastRequest {
  readonly kind: 'cast';
  readonly id: number;
  readonly choice: number;
  readonly params: unknown;
  /** The voter's secret scalar, decimal-encoded. Never persisted. */
  readonly secret: string;
  readonly ringIndex: number;
}

export interface VerifyBallotRequest {
  readonly kind: 'verifyBallot';
  readonly id: number;
  readonly params: unknown;
  readonly ballot: unknown;
}

export interface VerifyBoardRequest {
  readonly kind: 'verifyBoard';
  readonly id: number;
  readonly board: string;
}

export interface CancelRequest {
  readonly kind: 'cancel';
  readonly id: number;
}

export type WorkerRequest =
  | CastRequest
  | VerifyBallotRequest
  | VerifyBoardRequest
  | CancelRequest;

export interface ProgressMessage {
  readonly kind: 'progress';
  readonly id: number;
  readonly fraction: number;
}

export interface ResultMessage {
  readonly kind: 'result';
  readonly id: number;
  readonly value: unknown;
}

export interface ErrorMessage {
  readonly kind: 'error';
  readonly id: number;
  readonly name: string;
  readonly message: string;
}

export type WorkerResponse = ProgressMessage | ResultMessage | ErrorMessage;

/** Progress callbacks fire at most this often, in milliseconds. */
export const PROGRESS_INTERVAL_MS = 100;

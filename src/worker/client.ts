/**
 * The main-thread handle onto a worker.
 *
 * The API mirrors the direct one, so a caller can swap between them freely. If
 * `Worker` is unavailable -- some embedded webviews -- {@link createZKTallyWorker}
 * falls back to running everything inline and says so, rather than failing at an
 * arbitrary later point.
 */

import { G, mul } from '../primitives/curve.js';
import { makeVoterKey, type VoterKey } from '../primitives/lsag.js';
import { castBallot, verifyBallotSync, type Ballot, type BallotVerdict } from '../protocol/ballot.js';
import { Board } from '../protocol/board.js';
import type { ElectionParams } from '../protocol/params.js';
import {
  ballotFromDict,
  ballotToDict,
  boardToJSON,
  paramsToDict,
} from '../serialization/jsonCodec.js';
import type { WorkerRequest, WorkerResponse } from './protocol.js';

/**
 * A request minus its correlation id, which {@link RemoteWorker.#send} assigns.
 *
 * Distributive: a plain `Omit` over a union collapses to the shared keys, which
 * would silently reject every request-specific field.
 */
type PendingRequest = WorkerRequest extends infer R
  ? R extends { id: number }
    ? Omit<R, 'id'>
    : never
  : never;

export interface OperationOptions {
  readonly onProgress?: (fraction: number) => void;
  readonly signal?: AbortSignal;
}

export interface ZKTallyWorker {
  /** True when the operations actually run off the main thread. */
  readonly offloaded: boolean;
  castBallot(
    request: {
      choice: number;
      params: ElectionParams;
      key: VoterKey;
      ringIndex: number;
    },
    options?: OperationOptions,
  ): Promise<Ballot>;
  verifyBallot(
    ballot: Ballot,
    params: ElectionParams,
    options?: OperationOptions,
  ): Promise<BallotVerdict>;
  verifyBoard(board: Board, options?: OperationOptions): Promise<BallotVerdict[]>;
  terminate(): Promise<void>;
}

class InlineWorker implements ZKTallyWorker {
  readonly offloaded = false;

  async castBallot(
    request: { choice: number; params: ElectionParams; key: VoterKey; ringIndex: number },
    options: OperationOptions = {},
  ): Promise<Ballot> {
    return castBallot(request.choice, request.params, request.key, request.ringIndex, options);
  }

  async verifyBallot(
    ballot: Ballot,
    params: ElectionParams,
    options: OperationOptions = {},
  ): Promise<BallotVerdict> {
    return verifyBallotSync(ballot, params, new Set(), options);
  }

  async verifyBoard(board: Board, options: OperationOptions = {}): Promise<BallotVerdict[]> {
    return board.verifyAll(options);
  }

  async terminate(): Promise<void> {
    // Nothing to tear down.
  }
}

class RemoteWorker implements ZKTallyWorker {
  readonly offloaded = true;
  #worker: Worker;
  #nextId = 1;
  #pending = new Map<
    number,
    { resolve: (value: unknown) => void; reject: (reason: Error) => void; onProgress?: ((f: number) => void) | undefined }
  >();

  constructor(worker: Worker) {
    this.#worker = worker;
    this.#worker.addEventListener('message', (event: MessageEvent<WorkerResponse>) => {
      const message = event.data;
      const entry = this.#pending.get(message.id);
      if (!entry) return;
      if (message.kind === 'progress') {
        entry.onProgress?.(message.fraction);
        return;
      }
      this.#pending.delete(message.id);
      if (message.kind === 'result') entry.resolve(message.value);
      else {
        const error = new Error(message.message);
        error.name = message.name;
        entry.reject(error);
      }
    });
  }

  #send(request: PendingRequest, options: OperationOptions): Promise<unknown> {
    const id = this.#nextId++;
    return new Promise<unknown>((resolve, reject) => {
      this.#pending.set(id, { resolve, reject, onProgress: options.onProgress });
      options.signal?.addEventListener('abort', () => {
        this.#worker.postMessage({ kind: 'cancel', id } satisfies WorkerRequest);
        this.#pending.delete(id);
        reject(new DOMException('operation aborted', 'AbortError'));
      });
      this.#worker.postMessage({ ...request, id } as WorkerRequest);
    });
  }

  async castBallot(
    request: { choice: number; params: ElectionParams; key: VoterKey; ringIndex: number },
    options: OperationOptions = {},
  ): Promise<Ballot> {
    const doc = await this.#send(
      {
        kind: 'cast',
        choice: request.choice,
        params: paramsToDict(request.params),
        secret: request.key.secret.toString(),
        ringIndex: request.ringIndex,
      },
      options,
    );
    return ballotFromDict(doc, request.params.publicKey.byteLen);
  }

  async verifyBallot(
    ballot: Ballot,
    params: ElectionParams,
    options: OperationOptions = {},
  ): Promise<BallotVerdict> {
    return (await this.#send(
      {
        kind: 'verifyBallot',
        params: paramsToDict(params),
        ballot: ballotToDict(ballot, params.publicKey.byteLen),
      },
      options,
    )) as BallotVerdict;
  }

  async verifyBoard(board: Board, options: OperationOptions = {}): Promise<BallotVerdict[]> {
    return (await this.#send(
      { kind: 'verifyBoard', board: boardToJSON(board) },
      options,
    )) as BallotVerdict[];
  }

  async terminate(): Promise<void> {
    this.#worker.terminate();
    for (const entry of this.#pending.values()) {
      entry.reject(new Error('worker terminated'));
    }
    this.#pending.clear();
  }
}

/**
 * Spawn a module worker, or fall back to the inline path when `Worker` is
 * unavailable.
 *
 * The worker is created from a bundled module URL, so it works under a strict
 * CSP with no `eval` and no remote fetch. Check {@link ZKTallyWorker.offloaded}
 * to warn the user that the UI will block.
 */
export function createZKTallyWorker(): ZKTallyWorker {
  if (typeof Worker === 'undefined') return new InlineWorker();
  try {
    // The worker body is its own bundle entry; pointing at this module's own
    // URL would spawn a worker that re-imports the client, not the message loop.
    const worker = new Worker(new URL('./zktally-worker.js', import.meta.url), { type: 'module' });
    return new RemoteWorker(worker);
  } catch {
    return new InlineWorker();
  }
}

/**
 * Derive a usable voter key from a secret scalar.
 *
 * The worker boundary carries the scalar, not the key object, so both sides
 * rebuild the public point rather than trusting a transmitted one.
 */
export function voterKeyFromSecret(secret: bigint): VoterKey {
  return makeVoterKey(secret, mul(G, secret));
}

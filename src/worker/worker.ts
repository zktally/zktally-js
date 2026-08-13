/**
 * The worker-side message loop.
 *
 * A 1000-member ring is ~1000 double-scalar multiplications per sign and per
 * verify -- seconds of work. Doing that on the main thread freezes the page, so
 * the expensive operations run here.
 *
 * Ring iteration is inherently sequential (`c_{i+1}` depends on `L_i`), so this
 * is offload, not parallelism. Verification of *different ballots*, however, is
 * embarrassingly parallel, which is what the pool in `client.ts` exploits.
 */

import { G, mul } from '../primitives/curve.js';
import { makeVoterKey } from '../primitives/lsag.js';
import { castBallot, verifyBallotSync } from '../protocol/ballot.js';
import {
  ballotFromDict,
  ballotToDict,
  boardFromJSON,
  paramsFromDict,
} from '../serialization/jsonCodec.js';
import {
  PROGRESS_INTERVAL_MS,
  type WorkerRequest,
  type WorkerResponse,
} from './protocol.js';

declare const self: {
  postMessage(message: WorkerResponse): void;
  addEventListener(type: 'message', handler: (event: { data: WorkerRequest }) => void): void;
};

const inFlight = new Map<number, AbortController>();

function throttledProgress(id: number): (fraction: number) => void {
  let last = 0;
  return (fraction: number) => {
    const now = Date.now();
    if (fraction < 1 && now - last < PROGRESS_INTERVAL_MS) return;
    last = now;
    self.postMessage({ kind: 'progress', id, fraction });
  };
}

async function handle(request: WorkerRequest): Promise<unknown> {
  switch (request.kind) {
    case 'cast': {
      const params = paramsFromDict(request.params);
      const secret = BigInt(request.secret);
      const key = makeVoterKey(secret, mul(G, secret));
      const controller = new AbortController();
      inFlight.set(request.id, controller);
      try {
        const ballot = await castBallot(request.choice, params, key, request.ringIndex, {
          onProgress: throttledProgress(request.id),
          signal: controller.signal,
        });
        return ballotToDict(ballot, params.publicKey.byteLen);
      } finally {
        inFlight.delete(request.id);
      }
    }
    case 'verifyBallot': {
      const params = paramsFromDict(request.params);
      const ballot = ballotFromDict(request.ballot, params.publicKey.byteLen);
      return verifyBallotSync(ballot, params, new Set(), {
        onProgress: throttledProgress(request.id),
      });
    }
    case 'verifyBoard': {
      const board = boardFromJSON(request.board);
      return board.verifyAllSync({ onProgress: throttledProgress(request.id) });
    }
    case 'cancel': {
      inFlight.get(request.id)?.abort();
      return null;
    }
  }
}

self.addEventListener('message', (event) => {
  const request = event.data;
  void handle(request).then(
    (value) => {
      if (request.kind !== 'cancel') self.postMessage({ kind: 'result', id: request.id, value });
    },
    (error: unknown) => {
      const err = error instanceof Error ? error : new Error(String(error));
      self.postMessage({ kind: 'error', id: request.id, name: err.name, message: err.message });
    },
  );
});

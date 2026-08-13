# zktally

Privacy-preserving, anonymously verifiable e-voting from linkable ring signatures, Paillier
homomorphic encryption, and NIZK vote-correctness proofs — for TypeScript and the browser.

> **ZKTally is unaudited academic software implementing a protocol from a student research
> paper. It has not been reviewed by professional cryptographers and must not be used for any
> binding election.**

This is a **wire-compatible port**, not an independent implementation. A ballot cast in the
browser verifies in the [Python package](https://github.com/ZKTally/ZKTally) and vice versa;
both are validated against the same vector corpus.

Wire format: `zktally/1`.

---

## Install

```bash
npm install zktally
```

Two runtime dependencies, both pinned: `@noble/curves` and `@noble/hashes`. Requires
`BigInt` and `crypto.getRandomValues` — any current browser, Node 20+, Deno, or Bun.

## Use

```ts
import {
  Board, castBallot, canonicalRing, makeElectionParams,
  newElectionId, paillierKeygen, ringKeygen, tally,
} from 'zktally';

const [pk, sk] = await paillierKeygen(2048);

// Voters generate their own keys. Nothing else may generate them.
const voters = Array.from({ length: 5 }, () => ringKeygen());
const ring = canonicalRing(voters.map((v) => v.public));

const params = makeElectionParams({
  electionId: newElectionId(),
  title: 'Adopt the proposal?',
  ballotType: 'binary',
  k: 1,
  candidates: ['Yes'],
  publicKey: pk,
  trustModel: 'single-authority',
  ring,
});

const board = new Board(params);
for (const [i, choice] of [1, 0, 1, 1, 0].entries()) {
  board.append(await castBallot(choice, params, voters[i], ring.indexOf(voters[i].public)));
}

console.log((await tally(board, sk)).totals); // [3n]
```

Multi-candidate elections use `ballotType: 'one-of-k'` with `k >= 2`, which proves each column
binary *and* proves the columns sum to exactly one.

### Off the main thread

A 1000-member ring is roughly 1000 double-scalar multiplications per signature — seconds of
work that would freeze the page.

```ts
import { createZKTallyWorker } from 'zktally/worker';

const zk = createZKTallyWorker();
if (!zk.offloaded) console.warn('Worker unavailable; the UI will block during signing.');

const ballot = await zk.castBallot(
  { choice: 1, params, key, ringIndex },
  { onProgress: (p) => setProgress(p) },
);
await zk.terminate();
```

The API is identical to the direct one, so the two are interchangeable. Ring iteration is
inherently sequential (`c_{i+1}` depends on `L_i`), so this is offload rather than parallelism —
but verification of *different* ballots is embarrassingly parallel.

### Auditing

```ts
import { auditTally } from 'zktally';

const audit = auditTally(board, publishedResult); // no secret material
```

`auditTally` returns a breakdown, not a boolean. Under `trustModel: 'single-authority'` the
final decryption carries no proof, so `decryptionVerifiable` is `false` and the total is
reported as **asserted rather than verified**. Only threshold mode makes the tally itself
checkable.

---

## Security properties

✅ achieved · ⚠️ conditional · ❌ not provided

| Property | | Conditions |
|---|---|---|
| Ballot secrecy | ⚠️ | Against anyone below quorum. Not against `t` colluding authorities, nor a dishonest dealer during v1 setup |
| Voter anonymity | ⚠️ | Anonymity set is the ring, or the sub-ring when partitioned. Defeated by traffic analysis |
| Double-vote prevention | ✅ | Key image bound into every challenge; first-wins resolution |
| Ballot-stuffing resistance | ✅ | Ring fixed by the election parameters, never read from a ballot |
| Vote well-formedness | ✅ | Binary / 1-of-k NIZK plus mandatory ciphertext-domain validation |
| Public verifiability of ballots | ✅ | Anyone re-verifies every proof and signature from public data |
| Public verifiability of the tally | ✅ | Threshold mode only; partial decryptions carry correctness proofs |
| Non-malleability | ✅ | Election context bound into every transcript; proofs bound into the signed message |
| Eligibility | ⚠️ | Cryptographically enforced *given* an honest registrar |
| **Receipt-freeness** | ❌ | The voter holds the encryption randomness, which reconstructs their ciphertext. Structural, not a bug |
| **Coercion resistance** | ❌ | Not implemented |
| Everlasting privacy | ❌ | Ciphertexts are public forever; a future break reveals every vote |
| Side-channel resistance | ❌ | `BigInt` is not constant-time and JIT behaviour is unpredictable |
| Post-quantum security | ❌ | Paillier and secp256k1 both fall to Shor |

**Key material.** `VoterKey` and `PaillierPrivateKey` throw from `toJSON` and redact themselves
from string conversion; the library never persists either. Zeroization is **not** available —
JavaScript cannot reliably erase a `bigint`, since values are immutable and the GC may copy
them. That is a documented limitation, not something this package works around.

**Randomness** comes exclusively from `crypto.getRandomValues`. `Math.random` appears nowhere in
`src/`.

**Threshold keygen is not viable in a browser** — safe-prime generation at 3072 bits takes
minutes to tens of minutes. `thresholdKeygen` is for Node; a browser application should ship
pre-generated election parameters and say so.

## Development

```bash
npm install
npm run sync:vectors   # mirror the corpus from the Python package
npm test
npm run build          # bundles, declarations, and the bundle-size gate
```

Test suites: `unit/`, `property/` (fast-check), `conformance/` (the shared corpus — the primary
correctness gate), `tamper/` (one test per known break), and `interop/`, which shells out to the
Python package so a board produced here is verified there and back again. Interop skips
automatically when Python is not importable.

The corpus in `test/vectors/` is generated by the Python package and mirrored here.
`npm run sync:vectors` verifies every file against the manifest checksums and refuses to write
on a mismatch — vectors have exactly one source, and hand-editing this copy would let the two
ports drift while both suites stayed green.

## License

MIT. See [LICENSE](LICENSE).

/**
 * ZKTally -- privacy-preserving, anonymously verifiable e-voting.
 *
 * A wire-compatible port of the Python reference implementation. A ballot cast
 * here verifies there, and vice versa; both are validated against the same
 * vector corpus.
 *
 * **ZKTally is unaudited academic software implementing a protocol from a
 * student research paper. It has not been reviewed by professional
 * cryptographers and must not be used for any binding election.**
 */

export const SPEC_VERSION = 'zktally/1';

export {
  ConfigurationError,
  DecodingError,
  InvalidCiphertextError,
  InvalidPlaintextError,
  InvalidPointError,
  InvalidRingError,
  InvalidShareError,
  UnsupportedVersionError,
  ValidationError,
  ZKTallyError,
} from './errors.js';

export {
  CHALLENGE_MODULUS,
  DST_BALLOT,
  DST_BIN,
  DST_DEC,
  DST_H2C,
  DST_LSAG,
  DST_NTH,
  DST_RING,
} from './domain.js';

export { withRandomSource, type RandomSource } from './rng.js';

export {
  CURVE_ORDER,
  FIELD_PRIME,
  G,
  IDENTITY,
  decodePoint,
  encodePoint,
  isInPrimeOrderSubgroup,
  isOnCurve,
  randomScalar,
  type Point,
} from './primitives/curve.js';

export { hashToCurve } from './primitives/hashToCurve.js';

export {
  MIN_MODULUS_BITS,
  aggregate,
  decrypt,
  encrypt,
  encryptWith,
  isValidCiphertext,
  makePublicKey,
  paillierKeygen,
  type PaillierPrivateKey,
  type PaillierPublicKey,
} from './primitives/paillier.js';

export {
  SUM_TAG,
  binaryChallenge,
  candidateContext,
  nthRootChallenge,
  proveBinary,
  proveNthRoot,
  proveOneOfK,
  verifyBinary,
  verifyNthRoot,
  verifyOneOfK,
  type BinaryProof,
  type NthRootProof,
  type OneOfKBallot,
} from './primitives/nizk.js';

export {
  MAX_RING,
  canonicalRing,
  computeKeyImage,
  hashToPoint,
  lsagLink,
  lsagSign,
  lsagVerify,
  makeVoterKey,
  ringHash,
  ringKeygen,
  subringIndex,
  type RingSignature,
  type SignOptions,
  type VoterKey,
} from './primitives/lsag.js';

export {
  MIN_THRESHOLD_BITS,
  STAT_SECURITY_BITS,
  blindingBits,
  combineShares,
  fromSafePrimes,
  partialDecrypt,
  responseByteLen,
  thresholdKeygen,
  verifyPartial,
  type DecryptionProof,
  type KeyShare,
  type PartialDecryption,
  type ThresholdSetup,
  type VerificationKeys,
} from './primitives/threshold.js';

export {
  ELECTION_ID_BYTES,
  electionContext,
  makeElectionParams,
  newElectionId,
  withRing,
  type BallotType,
  type ElectionParams,
  type ElectionParamsInit,
  type TrustModel,
} from './protocol/params.js';

export {
  ballotMessage,
  castBallot,
  encodeBallotBody,
  keyImageKey,
  verifyBallot,
  verifyBallotSync,
  type Ballot,
  type BallotProof,
  type BallotVerdict,
  type RejectReason,
} from './protocol/ballot.js';

export { Board } from './protocol/board.js';

export {
  auditTally,
  tally,
  verifyTally,
  type Rejection,
  type TallyAudit,
  type TallyResult,
} from './protocol/tally.js';

export {
  CHALLENGE_BYTES,
  POINT_BYTES,
  SCALAR_BYTES,
  b64uDecode,
  b64uEncode,
  b64uInt,
  bytesToHex,
  encBytes,
  encChal,
  encN,
  encN2,
  encScalar,
  encString,
  encU32,
  hexToBytes,
  i2osp,
  modulusByteLen,
  os2ip,
} from './serialization/encoding.js';

export {
  ballotFromDict,
  ballotToDict,
  boardFromJSON,
  boardToJSON,
  paramsFromDict,
  paramsToDict,
  pointToJSON,
  tallyFromDict,
  tallyToDict,
} from './serialization/jsonCodec.js';

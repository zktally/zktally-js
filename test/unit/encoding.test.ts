/**
 * Encoding widths and the base64url codec.
 *
 * A decoder is an attack surface: everything it accepts, someone can send.
 * These tests are mostly about what it *refuses*.
 */

import { describe, expect, it } from 'vitest';

import { DecodingError } from '../../src/errors.js';
import {
  b64uDecode,
  b64uEncode,
  bytesToHex,
  encBytes,
  encString,
  encU32,
  hexToBytes,
  i2osp,
  modulusByteLen,
  os2ip,
} from '../../src/serialization/encoding.js';

describe('i2osp', () => {
  it('is fixed width and big-endian', () => {
    expect(bytesToHex(i2osp(1n, 4))).toBe('00000001');
    expect(bytesToHex(i2osp(0n, 3))).toBe('000000');
    expect(bytesToHex(i2osp(255n, 1))).toBe('ff');
  });

  it('round-trips through os2ip', () => {
    for (const value of [0n, 1n, 255n, 65535n, 1n << 200n]) {
      expect(os2ip(i2osp(value, 32))).toBe(value);
    }
  });

  it('refuses to truncate rather than silently narrowing a field', () => {
    // A variable width would break the injectivity the whole transcript rests on.
    expect(() => i2osp(256n, 1)).toThrow(RangeError);
    expect(() => i2osp(-1n, 4)).toThrow(RangeError);
  });
});

describe('length prefixing', () => {
  it('makes concatenation unambiguous', () => {
    // Without the prefix, "ab"+"c" and "a"+"bc" would produce identical bytes.
    const a = bytesToHex(encBytes(new Uint8Array([1, 2])));
    const b = bytesToHex(encBytes(new Uint8Array([1])));
    expect(a).toBe('0000000201' + '02');
    expect(b).toBe('0000000101');
    expect(a).not.toBe(b);
  });

  it('normalizes strings to NFC before encoding', () => {
    // U+00E9 vs U+0065 U+0301 -- the same character, two encodings.
    expect(bytesToHex(encString('é'))).toBe(bytesToHex(encString('é')));
  });
});

describe('base64url', () => {
  it('round-trips arbitrary byte strings without padding', () => {
    for (let length = 0; length < 40; length++) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37) % 256);
      const encoded = b64uEncode(bytes);
      expect(encoded).not.toContain('=');
      expect(b64uDecode(encoded)).toEqual(bytes);
    }
  });

  it('uses the URL-safe alphabet', () => {
    const encoded = b64uEncode(new Uint8Array([0xfb, 0xff]));
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
  });

  it('rejects a non-canonical encoding', () => {
    // Trailing bits that the encoder would never emit.
    expect(() => b64uDecode('AB')).toThrow(DecodingError);
  });

  it('rejects a wrong length when one is expected', () => {
    expect(() => b64uDecode(b64uEncode(new Uint8Array(4)), 33)).toThrow(DecodingError);
  });

  it('rejects a JSON number where a string is required', () => {
    expect(() => b64uDecode(12345 as unknown as string)).toThrow(DecodingError);
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => b64uDecode('AAA*')).toThrow(DecodingError);
  });
});

describe('hex', () => {
  it('round-trips', () => {
    const bytes = new Uint8Array([0, 1, 15, 16, 255]);
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
  });

  it('rejects an odd-length string', () => {
    expect(() => hexToBytes('abc')).toThrow(DecodingError);
  });
});

describe('modulusByteLen', () => {
  it('sizes the field from the modulus', () => {
    expect(modulusByteLen((1n << 2048n) - 1n)).toBe(256);
    expect(modulusByteLen((1n << 3072n) - 1n)).toBe(384);
  });

  it('rejects a non-positive modulus', () => {
    expect(() => modulusByteLen(0n)).toThrow(RangeError);
  });
});

describe('encU32', () => {
  it('is always four bytes', () => {
    expect(encU32(0)).toHaveLength(4);
    expect(encU32(0xffffffff)).toHaveLength(4);
  });
});

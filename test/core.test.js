import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseSctpChunks,
  parseChunkHeader,
  SCTP_CHUNK_HEADER_SIZE,
} from '../src/core.js';

/**
 * Build a chunk as it would appear on the wire: 4-byte header followed by the
 * value, then zero to three padding bytes so the total is a multiple of 4.
 */
function buildChunk(type, flags, value) {
  const valueBytes = value ?? new Uint8Array(0);
  const totalLength = 4 + valueBytes.length;
  const paddedLength = (totalLength + 3) & ~3;
  const chunk = new Uint8Array(paddedLength);
  chunk[0] = type & 0xff;
  chunk[1] = flags & 0xff;
  chunk[2] = (totalLength >> 8) & 0xff;
  chunk[3] = totalLength & 0xff;
  chunk.set(valueBytes, 4);
  return chunk;
}

/** Concatenate byte arrays into one contiguous buffer. */
function concat(arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

test('parseSctpChunks returns empty array for empty input', () => {
  assert.deepEqual(parseSctpChunks(new Uint8Array(0)), []);
});

test('parseSctpChunks parses a single DATA chunk with value', () => {
  const value = new Uint8Array([0x10, 0x20, 0x30, 0x40]);
  const buf = buildChunk(0x00, 0x03, value);
  const chunks = parseSctpChunks(buf);
  assert.equal(chunks.length, 1);
  assert.equal(chunks[0].type, 0x00);
  assert.equal(chunks[0].flags, 0x03);
  assert.equal(chunks[0].length, 8);
  assert.deepEqual(Array.from(chunks[0].value), [0x10, 0x20, 0x30, 0x40]);
  assert.equal(chunks[0].endOffset, 8);
});

test('parseSctpChunks parses a chunk whose value length is not a multiple of 4', () => {
  // 7-byte total (4 header + 3 value) → padded to 8.
  const value = new Uint8Array([0xaa, 0xbb, 0xcc]);
  const buf = buildChunk(0x01, 0x00, value);
  const chunks = parseSctpChunks(buf);
  assert.equal(chunks.length, 1);
  assert.equal(chunks[0].length, 7);
  assert.deepEqual(Array.from(chunks[0].value), [0xaa, 0xbb, 0xcc]);
  assert.equal(chunks[0].endOffset, 8);
});

test('parseSctpChunks parses multiple concatenated chunks', () => {
  const c1 = buildChunk(0x00, 0x01, new Uint8Array([0x01, 0x02, 0x03, 0x04]));
  const c2 = buildChunk(0x01, 0x02, new Uint8Array([0x05]));
  const c3 = buildChunk(0x0e, 0x00, new Uint8Array(0));
  const buf = concat([c1, c2, c3]);
  const chunks = parseSctpChunks(buf);
  assert.equal(chunks.length, 3);
  assert.equal(chunks[0].type, 0x00);
  assert.equal(chunks[1].type, 0x01);
  assert.equal(chunks[2].type, 0x0e);
  assert.deepEqual(Array.from(chunks[2].value), []);
});

test('parseSctpChunks handles an INIT chunk with a large value', () => {
  const value = new Uint8Array(20);
  for (let i = 0; i < value.length; i++) value[i] = i & 0xff;
  const buf = buildChunk(0x01, 0x00, value);
  const chunks = parseSctpChunks(buf);
  assert.equal(chunks.length, 1);
  assert.equal(chunks[0].type, 0x01);
  assert.equal(chunks[0].length, 24);
  assert.deepEqual(Array.from(chunks[0].value), Array.from(value));
});

test('parseSctpChunks ignores 1–3 trailing bytes that cannot form a header', () => {
  const c1 = buildChunk(0x00, 0x00, new Uint8Array([0xff]));
  const trailing = new Uint8Array([0x01, 0x02]);
  const buf = concat([c1, trailing]);
  const chunks = parseSctpChunks(buf);
  assert.equal(chunks.length, 1);
  assert.equal(chunks[0].type, 0x00);
});

test('parseSctpChunks throws when chunk length is less than header size', () => {
  const buf = new Uint8Array([0x00, 0x00, 0x00, 0x03]); // length 3 < 4
  assert.throws(() => parseSctpChunks(buf), RangeError);
});

test('parseSctpChunks throws when declared value extends beyond buffer', () => {
  // length 16 but only 4 bytes of buffer total
  const buf = new Uint8Array([0x00, 0x00, 0x00, 0x10]);
  assert.throws(() => parseSctpChunks(buf), RangeError);
});

test('parseSctpChunks accepts an ArrayBuffer directly', () => {
  const value = new Uint8Array([0xde, 0xad]);
  const chunk = buildChunk(0x06, 0x00, value);
  const ab = chunk.buffer.slice(chunk.byteOffset, chunk.byteOffset + chunk.byteLength);
  const chunks = parseSctpChunks(ab);
  assert.equal(chunks.length, 1);
  assert.equal(chunks[0].type, 0x06);
  assert.deepEqual(Array.from(chunks[0].value), [0xde, 0xad]);
});

test('parseChunkHeader returns null for a truncated header', () => {
  const buf = new Uint8Array([0x00, 0x01, 0x02]); // 3 bytes, need 4
  const result = parseChunkHeader(buf, 0);
  assert.equal(result, null);
});

test('parseChunkHeader respects a non-zero offset', () => {
  const value = new Uint8Array([0x42]);
  const chunk = buildChunk(0x02, 0x00, value);
  // Skip 2 garbage bytes before the chunk.
  const buf = concat([new Uint8Array([0xff, 0xff]), chunk]);
  const result = parseChunkHeader(buf, 2);
  assert.notEqual(result, null);
  assert.equal(result.type, 0x02);
  assert.deepEqual(Array.from(result.value), [0x42]);
});

test('parseChunkHeader value is a view, not a copy', () => {
  const value = new Uint8Array([0x77]);
  const buf = buildChunk(0x03, 0x00, value);
  const result = parseChunkHeader(buf, 0);
  assert.equal(result.value.buffer, buf.buffer);
  assert.equal(result.value.byteOffset, 4);
  assert.equal(result.value.byteLength, 1);
});

test('SCTP_CHUNK_HEADER_SIZE is 4', () => {
  assert.equal(SCTP_CHUNK_HEADER_SIZE, 4);
});

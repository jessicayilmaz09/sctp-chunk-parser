/**
 * SCTP Chunk Parser — decodes SCTP packet chunk headers into type, flags,
 * length, and value slices for WebRTC data channel inspection.
 */

/**
 * Fixed size of the per-chunk header preceding each chunk value: 4 bytes
 * (1 byte type, 1 byte flags, 2 bytes length in network byte order).
 */
export const SCTP_CHUNK_HEADER_SIZE = 4;

/**
 * @typedef {Object} SctpChunk
 * @property {number} type   - unsigned 8-bit chunk type (0–255).
 * @property {number} flags   - unsigned 8-bit flags field (0–255).
 * @property {number} length  - declared total chunk length in bytes (header + value).
 * @property {Uint8Array} value - view of the chunk's value bytes (length - 4, padded away).
 * @property {number} endOffset - byte offset in the original buffer where this chunk ends (padded).
 */

/**
 * Read an unsigned 16-bit big-endian integer from a DataView at the given offset.
 * Using DataView avoids relying on a Node-specific Buffer and keeps the library
 * portable to browsers and workers without a polyfill.
 */
function readUint16Be(view, offset) {
  return view.getUint16(offset, false);
}

/**
 * Parse a single SCTP chunk header starting at `offset` within `buffer`.
 *
 * Why this exists separately from {@link parseSctpChunks}: callers that only
 * need the first chunk (e.g. a quick INIT probe) can skip the iteration logic
 * and its associated allocation of an output array.
 *
 * @param {Uint8Array|ArrayBuffer} buffer - the SCTP packet (or chunk region).
 * @param {number} [offset=0] - byte offset at which the chunk begins.
 * @returns {SctpChunk|null} parsed chunk, or null if fewer than 4 bytes remain
 *   (truncated header — the buffer ends mid-header before a full header can be read).
 * @throws {RangeError} if `length` declares fewer bytes than the header itself
 *   (the packet is malformed: length must be >= 4 per RFC 4975 §3).
 */
export function parseChunkHeader(buffer, offset = 0) {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
  const view =
    bytes.buffer instanceof ArrayBuffer &&
    Object.prototype.toString.call(bytes) === '[object Uint8Array]' &&
    bytes.byteOffset === 0 &&
    bytes.byteLength === bytes.buffer.byteLength
      ? new DataView(bytes.buffer)
      : new DataView(
          bytes.buffer,
          bytes.byteOffset ?? 0,
          bytes.byteLength ?? bytes.length,
        );

  const absoluteOffset = (bytes.byteOffset ?? 0) + offset;
  const remaining = view.byteLength - absoluteOffset;

  if (remaining < SCTP_CHUNK_HEADER_SIZE) {
    return null;
  }

  const type = view.getUint8(absoluteOffset);
  const flags = view.getUint8(absoluteOffset + 1);
  const length = readUint16Be(view, absoluteOffset + 2);

  // RFC 4975 §3: "Length: 16 bits (unsigned integer). This field represents the
  // length of the chunk in bytes, including the Chunk Type, Chunk Flags, and
  // Chunk Value. ... If the chunk does not have a value, the Length is set to 4."
  if (length < SCTP_CHUNK_HEADER_SIZE) {
    throw new RangeError(
      `SCTP chunk at offset ${offset} declares length ${length} < ${SCTP_CHUNK_HEADER_SIZE} (header size)`,
    );
  }

  const valueLength = length - SCTP_CHUNK_HEADER_SIZE;
  if (valueLength > 0 && offset + SCTP_CHUNK_HEADER_SIZE + valueLength > (view.byteLength - (bytes.byteOffset ?? 0))) {
    // The chunk claims more value bytes than the buffer actually contains.
    // Rather than silently truncating, surface this as a RangeError — a
    // truncated value is usually a sign of a bad capture, not something
    // a downstream parser can safely interpret.
    throw new RangeError(
      `SCTP chunk at offset ${offset} declares value length ${valueLength}, but only ${
        view.byteLength - (bytes.byteOffset ?? 0) - offset - SCTP_CHUNK_HEADER_SIZE
      } bytes remain`,
    );
  }

  // Build a subarray view covering exactly the declared value bytes. The
  // padding (0–3 bytes to reach the next 4-byte boundary) is *excluded*
  // from `value` so callers don't have to strip it themselves; `endOffset`
  // points past the padding so {@link parseSctpChunks} knows where to resume.
  const valueStart = (bytes.byteOffset ?? 0) + offset + SCTP_CHUNK_HEADER_SIZE;
  const value =
    valueLength > 0
      ? new Uint8Array(bytes.buffer, valueStart, valueLength)
      : new Uint8Array(0);

  const paddedLength = (length + 3) & ~3;
  const endOffset = offset + paddedLength;

  return { type, flags, length, value, endOffset };
}

/**
 * Parse all chunks in an SCTP packet body into an array of chunk descriptors.
 *
 * Why not return an iterator: the typical caller (a WebRTC diagnostic tool)
 * wants the full list so it can filter by chunk type in a single pass and
 * hand the results to a UI. An iterator would force materialisation anyway.
 *
 * @param {Uint8Array|ArrayBuffer} buffer - the SCTP packet body (the bytes
 *   after the 12-byte common header).
 * @returns {SctpChunk[]} all chunks in order; empty array if `buffer` is empty.
 * @throws {RangeError} if any chunk header is malformed (length < 4, or value
 *   extends beyond the buffer).
 */
export function parseSctpChunks(buffer) {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
  const total = bytes.byteLength ?? bytes.length;
  const out = [];
  let offset = 0;

  while (offset < total) {
    const chunk = parseChunkHeader(bytes, offset);
    if (chunk === null) {
      // Fewer than 4 bytes remain and no header can be read. RFC 4975 does
      // not define what a receiver should do with a trailing 1–3 byte
      // fragment; we treat it as end-of-stream rather than error so that
      // slightly-truncated captures still decode the chunks that are present.
      break;
    }
    out.push(chunk);
    offset = chunk.endOffset;
  }

  return out;
}

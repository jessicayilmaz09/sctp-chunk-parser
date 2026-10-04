# SCTP Chunk Parser

Decodes SCTP packet chunk headers into `type`, `flags`, `length`, and `value` slices for WebRTC data channel inspection.

## Usage

```js
import { parseSctpChunks } from 'sctp-chunk-parser';

const chunks = parseSctpChunks(new Uint8Array(0));
for (const c of chunks) {
  console.log(c.type, c.flags, c.length, c.value);
}
```

A single chunk can be parsed in isolation:

```js
import { parseChunkHeader } from 'sctp-chunk-parser';

const chunk = parseChunkHeader(new Uint8Array([0x00, 0x00, 0x00, 0x04]), 0);
// chunk === { type, flags, length, value, endOffset } or null
```

## Exports

- `parseSctpChunks(buffer)` → array of `{ type, flags, length, value, endOffset }`
- `parseChunkHeader(buffer, offset?)` → a single chunk object, or `null` if fewer than 4 bytes remain (truncated header)
- `SCTP_CHUNK_HEADER_SIZE` → `4`

`buffer` is a `Uint8Array` or `ArrayBuffer`. `value` is a `Uint8Array` view into the original buffer (no copy); padding bytes defined by RFC 4975 are excluded from `value` but accounted for in `endOffset`.

## Why

WebRTC data channel diagnostics need to peek inside SCTP packets to identify chunk types (DATA, INIT, SACK, etc.) without pulling in a full SCTP stack. This library does exactly that one job: walk the chunk list, split each into header + value, and hand back views. It deliberately does not interpret the contents of any chunk value — that belongs to a higher layer.

## Edge cases

- A chunk whose declared `length` is less than 4 (the header size) throws `RangeError`; this is a malformed packet per RFC 4975 §3.
- A chunk whose declared value extends past the end of the buffer throws `RangeError` rather than silently truncating.
- 1–3 trailing bytes that cannot form a full header are treated as end-of-stream: `parseSctpChunks` returns the chunks it found and stops. The RFC does not define a receiver behaviour for a truncated tail, so we pick the lenient option.
- `value` is a view, not a copy. Mutating it mutates the source buffer.

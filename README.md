# socks5-address-field

Serializes and parses the SOCKS5 `DST.ADDR` address field, the variable-length
value defined in RFC 1928 §5.

```js
import {
  parseAddressField,
  serializeAddressField,
  AddressType,
} from 'socks5-address-field';

// Decode ATYP + address octets from an offset within a packet buffer.
const wire = serializeAddressField(AddressType.IPv4, '8.8.8.1');
const { type, value, end } = parseAddressField(wire);
// type === 1, value === '8.8.8.1', end === 5

// Encode a textual address back to the on-wire bytes, ATYP included.
const domainWire = serializeAddressField(AddressType.Domain, 'localhost');
```

`parseAddressField(buf, start)` returns `{ type, value, end }`. `value` is a
string: dotted-decimal for IPv4, the raw hostname for `Domain`, eight
lowercase hex groups joined by `:` for IPv6. `end` is the buffer offset just
past the last consumed byte, so the caller can continue parsing the port or
any trailing field without recounting.

`serializeAddressField(type, value)` returns a `Uint8Array` containing the
ATYP byte followed by the address octets in network byte order.

## Why this exists

A full SOCKS5 implementation owns command codes, reply codes, authentication
negotiation, and port encoding. Those concerns interact in ways that make a
library either too rigid or too permissive. This module owns exactly one
piece — the `DST.ADDR` field — so the surrounding framing code can stay
simple and correct. The trade-off is that you write the two-byte port
yourself; that is a `Buffer.writeUInt16BE` one-liner and belongs in your
framing layer, not here.

## The awkward edge

IPv6 normalization is intentionally not done. The parser emits eight
lowercase groups with no `::` compression, and the serializer requires the
caller to supply exactly eight groups. If you feed it `fe80::1` it will throw.
Normalize upstream with `node:net` or your OS resolver before calling
`serializeAddressField` if you need canonical compression.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.


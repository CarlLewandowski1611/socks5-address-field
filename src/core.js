/**
 * Core serialization/parsing of the variable-length SOCKS5 address field.
 *
 * RFC 1928 §5 encodes the destination address in DST.ADDR with a leading
 * type byte (ATYP) drawn from a small fixed set:
 *
 *   0x01  IPv4   — 4 octets, network byte order
 *   0x03  domain — 1 length byte then that many ASCII octets
 *   0x04  IPv6   — 16 octets, network byte order
 *
 * The remaining socket-level fields (port, command, reply code) live
 * elsewhere in the packet and are deliberately not handled here; this
 * module owns only DST.ADDR so it can be composed into a full request or
 * reply without dragging in framing concerns.
 */

/** Enumerated address type bytes from RFC 1928 §5. */
export const AddressType = Object.freeze({
  IPv4: 0x01,
  Domain: 0x03,
  IPv6: 0x04,
});

/**
 * Parse a single DST.ADDR field.
 *
 * @param {Uint8Array} buf   Buffer holding ATYP plus the address octets.
 * @param {number}     start Offset of the ATYP byte within `buf`.
 * @returns {{ type: number, value: string, end: number }}
 *   `value` is a textual form: dotted-decimal for IPv4, the raw hostname
 *   for domains, canonical colon form for IPv6. `end` is the offset just
 *   past the last consumed byte, so callers can continue parsing (port, etc.)
 *   from `buf` without re-counting.
 * @throws {Error} If `buf` is too short, the ATYP is unknown, or the domain
 *   length byte is inconsistent with the remaining buffer.
 */
export function parseAddressField(buf, start = 0) {
  if (!(buf instanceof Uint8Array)) {
    throw new TypeError('buf must be a Uint8Array');
  }
  if (!Number.isInteger(start) || start < 0 || start >= buf.length) {
    throw new RangeError('start is out of bounds');
  }

  const atyp = buf[start];

  if (atyp === AddressType.IPv4) {
    const end = start + 1 + 4;
    if (end > buf.length) throw new RangeError('truncated IPv4 address');
    const a = buf[start + 1];
    const b = buf[start + 2];
    const c = buf[start + 3];
    const d = buf[start + 4];
    return { type: atyp, value: `${a}.${b}.${c}.${d}`, end };
  }

  if (atyp === AddressType.Domain) {
    if (start + 1 >= buf.length) {
      throw new RangeError('domain length byte is missing');
    }
    const len = buf[start + 1];
    const end = start + 2 + len;
    if (end > buf.length) throw new RangeError('domain name is truncated');
    const bytes = buf.subarray(start + 2, end);
    // Hostnames are a length-prefixed UTF-8-ish string in practice; latin1
    // mirrors the bytes byte-for-byte and keeps the round-trip lossless,
    // which utf-8 decoding would not for malformed inputs.
    const value = Buffer.from(bytes).toString('latin1');
    return { type: atyp, value, end };
  }

  if (atyp === AddressType.IPv6) {
    const end = start + 1 + 16;
    if (end > buf.length) throw new RangeError('truncated IPv6 address');
    const segments = [];
    for (let i = 0; i < 16; i += 2) {
      // High byte first matches the big-endian convention used by the IPv4
      // branch and by RFC 1928 itself.
      segments.push((buf[start + 1 + i] << 8) | buf[start + 2 + i]);
    }
    return { type: atyp, value: segments.map((s) => s.toString(16)).join(':'), end };
  }

  throw new Error(`unknown ATYP: 0x${atyp.toString(16).padStart(2, '0')}`);
}

/**
 * Serialize a textual address back into the DST.ADDR wire form, including
 * the leading ATYP byte.
 *
 * The caller decides the type by passing the matching `AddressType` value;
 * `value` is then encoded in the obvious way for that type. For Domain,
 * `value` is treated as an ASCII hostname — non-ASCII code points above
 * 0xff are rejected so the length byte stays a valid octet count.
 *
 * @param {number} type  One of `AddressType.IPv4`, `.Domain`, `.IPv6`.
 * @param {string} value Textual address.
 * @returns {Uint8Array} Wire bytes: ATYP followed by the address octets.
 * @throws {Error} On type mismatch, bad IPv4/IPv6 syntax, or a domain whose
 *   encoding exceeds 255 octets.
 */
export function serializeAddressField(type, value) {
  if (type === AddressType.IPv4) {
    return serializeIPv4(value);
  }
  if (type === AddressType.Domain) {
    return serializeDomain(value);
  }
  if (type === AddressType.IPv6) {
    return serializeIPv6(value);
  }
  throw new Error(`unknown address type: ${type}`);
}

function serializeIPv4(value) {
  if (typeof value !== 'string') throw new TypeError('value must be a string');
  const parts = value.split('.');
  if (parts.length !== 4) throw new Error(`invalid IPv4 address: ${value}`);
  const octets = new Uint8Array(5);
  octets[0] = AddressType.IPv4;
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) {
      throw new Error(`invalid IPv4 octet: ${parts[i]}`);
    }
    octets[1 + i] = n;
  }
  return octets;
}

function serializeDomain(value) {
  if (typeof value !== 'string') throw new TypeError('value must be a string');
  // latin1 round-trips byte-for-byte with the UTF-16 string the caller gives
  // us; this preserves whatever bytes they intended while letting us reject
  // code points that cannot fit in a single octet.
  const bytes = Buffer.from(value, 'latin1');
  if (bytes.length > 255) {
    throw new Error(`domain name too long: ${bytes.length} octets (max 255)`);
  }
  const out = new Uint8Array(2 + bytes.length);
  out[0] = AddressType.Domain;
  out[1] = bytes.length;
  out.set(bytes, 2);
  return out;
}

function serializeIPv6(value) {
  if (typeof value !== 'string') throw new TypeError('value must be a string');
  const parts = value.split(':');
  if (parts.length !== 8) {
    throw new Error(`invalid IPv6 address: ${value}`);
  }
  const out = new Uint8Array(17);
  out[0] = AddressType.IPv6;
  for (let i = 0; i < 8; i++) {
    const seg = parts[i];
    if (!/^[0-9a-fA-F]{1,4}$/.test(seg)) {
      throw new Error(`invalid IPv6 segment: ${seg}`);
    }
    const num = parseInt(seg, 16);
    out[1 + i * 2] = (num >> 8) & 0xff;
    out[2 + i * 2] = num & 0xff;
  }
  return out;
}

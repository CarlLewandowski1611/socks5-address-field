import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseAddressField, serializeAddressField, AddressType } from '../src/index.js';

function hex(s) {
  return Uint8Array.from(Buffer.from(s.replace(/\s+/g, ''), 'hex'));
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// --- parseAddressField: happy paths ---

test('parse IPv4 reads 4 octets after ATYP', () => {
  const buf = hex('01 08 08 08 01');
  const r = parseAddressField(buf);
  assert.equal(r.type, AddressType.IPv4);
  assert.equal(r.value, '8.8.8.1');
  assert.equal(r.end, 5);
});

test('parse IPv4 respects start offset and reports end past the field', () => {
  const buf = hex('ff 01 7f 00 00 01 aa');
  const r = parseAddressField(buf, 1);
  assert.equal(r.value, '127.0.0.1');
  assert.equal(r.end, 6);
});

test('parse Domain reads length-prefixed hostname', () => {
  const buf = hex('03 09 6c 6f 63 61 6c 68 6f 73 74');
  const r = parseAddressField(buf);
  assert.equal(r.type, AddressType.Domain);
  assert.equal(r.value, 'localhost');
  assert.equal(r.end, 11);
});

test('parse Domain with zero-length name is allowed', () => {
  const buf = hex('03 00');
  const r = parseAddressField(buf);
  assert.equal(r.value, '');
  assert.equal(r.end, 2);
});

test('parse IPv6 emits eight lowercase hex groups', () => {
  // fe80::1 in full form: fe80 0000 0000 0000 0000 0000 0000 0001
  const buf = hex('04 fe 80 00 00 00 00 00 00 00 00 00 00 00 00 00 01');
  const r = parseAddressField(buf);
  assert.equal(r.type, AddressType.IPv6);
  assert.equal(r.value, 'fe80:0:0:0:0:0:0:1');
  assert.equal(r.end, 17);
});

// --- parseAddressField: edge cases and errors ---

test('parse rejects unknown ATYP', () => {
  assert.throws(() => parseAddressField(hex('02')), /unknown ATYP/);
});

test('parse rejects non-Uint8Array input', () => {
  assert.throws(() => parseAddressField([0x01, 8, 8, 8, 8]), /Uint8Array/);
});

test('parse rejects out-of-range start', () => {
  assert.throws(() => parseAddressField(hex('01'), 1), /out of bounds/);
});

test('parse rejects truncated IPv4', () => {
  assert.throws(() => parseAddressField(hex('01 7f 00 00')), /truncated IPv4/);
});

test('parse rejects truncated IPv6', () => {
  assert.throws(() => parseAddressField(hex('04 00 00')), /truncated IPv6/);
});

test('parse rejects domain missing its length byte', () => {
  assert.throws(() => parseAddressField(hex('03')), /domain length byte/);
});

test('parse rejects domain whose length exceeds remaining bytes', () => {
  // ATYP=03 LEN=05 but only 3 name bytes follow
  assert.throws(() => parseAddressField(hex('03 05 61 62 63')), /truncated/);
});

// --- serializeAddressField: happy paths ---

test('serialize IPv4 produces ATYP + 4 octets', () => {
  const out = serializeAddressField(AddressType.IPv4, '192.0.2.1');
  assert.ok(bytesEqual(out, hex('01 c0 00 02 01')));
});

test('serialize Domain prefixes ATYP + 1 length byte', () => {
  const out = serializeAddressField(AddressType.Domain, 'localhost');
  assert.ok(bytesEqual(out, hex('03 09 6c 6f 63 61 6c 68 6f 73 74')));
});

test('serialize IPv6 writes 16 octets big-endian', () => {
  const out = serializeAddressField(AddressType.IPv6, 'fe80:0:0:0:0:0:0:1');
  assert.ok(bytesEqual(out, hex('04 fe 80 00 00 00 00 00 00 00 00 00 00 00 00 00 01')));
});

// --- serializeAddressField: edge cases and errors ---

test('serialize rejects IPv4 with a non-octet value', () => {
  assert.throws(() => serializeAddressField(AddressType.IPv4, '1.2.3.256'), /invalid IPv4 octet/);
});

test('serialize rejects IPv4 with too few octets', () => {
  assert.throws(() => serializeAddressField(AddressType.IPv4, '1.2.3'), /invalid IPv4/);
});

test('serialize rejects a domain longer than 255 octets', () => {
  const long = 'a'.repeat(256);
  assert.throws(() => serializeAddressField(AddressType.Domain, long), /too long/);
});

test('serialize rejects unknown address type', () => {
  assert.throws(() => serializeAddressField(0x99, 'x'), /unknown address type/);
});

test('serialize rejects IPv6 with too few segments', () => {
  assert.throws(() => serializeAddressField(AddressType.IPv6, 'fe80::1'), /invalid IPv6/);
});

// --- round-trip behavior actually implemented ---

test('round-trip IPv4', () => {
  const wire = serializeAddressField(AddressType.IPv4, '198.51.100.42');
  const parsed = parseAddressField(wire);
  assert.equal(parsed.value, '198.51.100.42');
});

test('round-trip Domain', () => {
  const wire = serializeAddressField(AddressType.Domain, 'localhost');
  const parsed = parseAddressField(wire);
  assert.equal(parsed.value, 'localhost');
});

test('round-trip IPv6 (caller-supplied full form)', () => {
  const wire = serializeAddressField(AddressType.IPv6, '2001:db8:0:0:0:0:0:1');
  const parsed = parseAddressField(wire);
  assert.equal(parsed.value, '2001:db8:0:0:0:0:0:1');
});

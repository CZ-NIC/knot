/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdbool.h>

#include "libknot/dnssec/shared/bignum.h"
#include "libknot/dnssec/binary.h"
#include "libknot/dnssec/error.h"
#include "libknot/dnssec/sign/der.h"
#include "libknot/dnssec/shared/binary_wire.h"

/*
 * In fact, this is a very tiny subset of ASN.1 encoding format implementation,
 * which is necessary for the purpose of DNSSEC.
 *
 * References: RFC 3279 (X.509 PKI), X.690, RFC 6605 (ECDSA), RFC8080 (EDDSA)
 *
 * Dss-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
 */

#define ASN1_TYPE_SEQUENCE 0x30
#define ASN1_TYPE_INTEGER  0x02

#define ASN1_MAX_SIZE 127

/*!
 * Check if the next object has a given type.
 */
static bool asn1_expect_type(wire_ctx_t *wire, uint8_t type)
{
	assert(wire);
	return (wire_ctx_available(wire) >= 1 && wire_ctx_read_u8(wire) == type);
}

/*!
 * Decode the size of the object (only short format is supported).
 */
static int asn1_decode_size(wire_ctx_t *wire, size_t *size)
{
	assert(wire);
	assert(size);

	if (wire_ctx_available(wire) < 1) {
		return DNSSEC_MALFORMED_DATA;
	}

	uint8_t byte = wire_ctx_read_u8(wire);
	if (byte & 0x80) {
		// long form, we do not need it for DNSSEC
		return KNOT_ENOTSUP;
	}

	*size = byte;

	return KNOT_EOK;
}

/*!
 * Decode an unsigned integer object.
 */
static int asn1_decode_integer(wire_ctx_t *wire, dnssec_binary_t *_value)
{
	assert(wire);
	assert(_value);

	if (!asn1_expect_type(wire, ASN1_TYPE_INTEGER)) {
		return DNSSEC_MALFORMED_DATA;
	}

	size_t size;
	int result = asn1_decode_size(wire, &size);
	if (result != KNOT_EOK) {
		return result;
	}

	if (size == 0 || size > wire_ctx_available(wire)) {
		return DNSSEC_MALFORMED_DATA;
	}

	dnssec_binary_t value = { .data = wire->position, .size = size };
	wire->position += size;

	// skip leading zeroes (unless equal to zero)
	while (value.size > 1 && value.data[0] == 0) {
		value.data += 1;
		value.size -= 1;
	}

	*_value = value;

	return KNOT_EOK;
}

/*!
 * Encode object header (type and length).
 */
static void asn1_write_header(wire_ctx_t *wire, uint8_t type, size_t length)
{
	assert(wire);
	assert(length < ASN1_MAX_SIZE);

	wire_ctx_write_u8(wire, type);
	wire_ctx_write_u8(wire, length);
}

/*!
 * Encode unsigned integer object.
 */
static void asn1_write_integer(wire_ctx_t *wire, size_t integer_size,
			       const dnssec_binary_t *integer)
{
	assert(wire);
	assert(integer);
	assert(integer->data);

	asn1_write_header(wire, ASN1_TYPE_INTEGER, integer_size);
	bignum_write(wire, integer_size, integer);
}

/*!
 * Decode signature parameters from X.509 ECDSA signature.
 */
int dss_sig_value_decode(const dnssec_binary_t *der,
			 dnssec_binary_t *r, dnssec_binary_t *s)
{
	if (!der || !der->data || !r || !s) {
		return KNOT_EINVAL;
	}

	wire_ctx_t wire = binary_init(der);

	size_t size;
	int result;

	// decode the sequence

	if (!asn1_expect_type(&wire, ASN1_TYPE_SEQUENCE)) {
		return DNSSEC_MALFORMED_DATA;
	}

	result = asn1_decode_size(&wire, &size);
	if (result != KNOT_EOK) {
		return result;
	}

	if (size != wire_ctx_available(&wire)) {
		return DNSSEC_MALFORMED_DATA;
	}

	// decode the 'r' and 's' values

	dnssec_binary_t der_r;
	result = asn1_decode_integer(&wire, &der_r);
	if (result != KNOT_EOK) {
		return result;
	}

	dnssec_binary_t der_s;
	result = asn1_decode_integer(&wire, &der_s);
	if (result != KNOT_EOK) {
		return result;
	}

	if (wire_ctx_available(&wire) != 0) {
		return DNSSEC_MALFORMED_DATA;
	}

	*r = der_r;
	*s = der_s;

	return KNOT_EOK;
}

/*!
 * Encode signature parameters from X.509 ECDSA signature.
 */
int dss_sig_value_encode(const dnssec_binary_t *r, const dnssec_binary_t *s,
			 dnssec_binary_t *der)
{
	if (!r || !r->data || !s || !s->data || !der) {
		return KNOT_EINVAL;
	}

	size_t r_size = bignum_size_s(r);
	size_t s_size = bignum_size_s(s);

	// check supported inputs range

	if (r_size > ASN1_MAX_SIZE || s_size > ASN1_MAX_SIZE) {
		return KNOT_ENOTSUP;
	}

	size_t seq_size = 2 + r_size + 2 + s_size;
	if (seq_size > ASN1_MAX_SIZE) {
		return KNOT_ENOTSUP;
	}

	// encode result

	size_t total_size = 2 + seq_size;

	dnssec_binary_t _der = { 0 };
	if (dnssec_binary_alloc(&_der, total_size)) {
		return KNOT_ENOMEM;
	}

	wire_ctx_t wire = binary_init(&_der);
	asn1_write_header(&wire, ASN1_TYPE_SEQUENCE, seq_size);
	asn1_write_integer(&wire, r_size, r);
	asn1_write_integer(&wire, s_size, s);
	assert(wire_ctx_available(&wire) == 0);

	*der = _der;

	return KNOT_EOK;
}

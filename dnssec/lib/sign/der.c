/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdbool.h>

#include "binary.h"
#include "error.h"
#include "sign/der.h"
#include "wire.h"

/*
 * In fact, this is a very tiny subset of ASN.1 encoding format implementation,
 * which is necessary for the purpose of DNSSEC.
 *
 * References: RFC 3279 (X.509 PKI), X.690, RFC 2536 (DSA), RFC 6605 (ECDSA)
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
	return (wire_available(wire) >= 1 && wire_read_u8(wire) == type);
}

/*!
 * Decode the size of the object (only short format is supported).
 */
static int asn1_decode_size(wire_ctx_t *wire, size_t *size)
{
	assert(wire);
	assert(size);

	if (wire_available(wire) < 1) {
		return DNSSEC_MALFORMED_DATA;
	}

	uint8_t byte = wire_read_u8(wire);
	if (byte & 0x80) {
		// long form, we do not need it for DNSSEC
		return DNSSEC_NOT_IMPLEMENTED_ERROR;
	}

	*size = byte;

	return DNSSEC_EOK;
}

/*!
 * Decode an integer object and retrieves a pointer to it.
 */
static int asn1_decode_integer(wire_ctx_t *wire, dnssec_binary_t *value)
{
	assert(wire);
	assert(value);

	if (!asn1_expect_type(wire, ASN1_TYPE_INTEGER)) {
		return DNSSEC_MALFORMED_DATA;
	}

	size_t size;
	int result = asn1_decode_size(wire, &size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	if (size > wire_available(wire)) {
		return DNSSEC_MALFORMED_DATA;
	}

	value->size = size;
	value->data = wire->position;
	wire->position += size;

	return DNSSEC_EOK;
}

/*!
 * Encode object header (type and length).
 */
static void asn1_write_header(wire_ctx_t *wire, uint8_t type, size_t length)
{
	assert(wire);
	assert(length < ASN1_MAX_SIZE);

	wire_write_u8(wire, type);
	wire_write_u8(wire, length);
}

/*!
 * Encode integer object.
 */
static void asn1_write_integer(wire_ctx_t *wire, const dnssec_binary_t *integer)
{
	assert(wire);
	assert(integer);
	assert(integer->data);

	asn1_write_header(wire, ASN1_TYPE_INTEGER, integer->size);
	wire_write_binary(wire, integer);
}

/*!
 * Decode signature parameters from X.509 (EC)DSA signature.
 */
int dss_sig_value_decode(const dnssec_binary_t *der,
			 dnssec_binary_t *r, dnssec_binary_t *s)
{
	if (!der || !der->data || !r || !s) {
		return DNSSEC_EINVAL;
	}

	wire_ctx_t wire = wire_init_binary(der);

	size_t size;
	int result;

	// decode the sequence

	if (!asn1_expect_type(&wire, ASN1_TYPE_SEQUENCE)) {
		return DNSSEC_MALFORMED_DATA;
	}

	result = asn1_decode_size(&wire, &size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	if (size != wire_available(&wire)) {
		return DNSSEC_MALFORMED_DATA;
	}

	// decode the 'r' and 's' values

	dnssec_binary_t der_r;
	result = asn1_decode_integer(&wire, &der_r);
	if (result != DNSSEC_EOK) {
		return result;
	}

	dnssec_binary_t der_s;
	result = asn1_decode_integer(&wire, &der_s);
	if (result != DNSSEC_EOK) {
		return result;
	}

	if (wire_available(&wire) != 0) {
		return DNSSEC_MALFORMED_DATA;
	}

	*r = der_r;
	*s = der_s;

	return DNSSEC_EOK;
}

/*!
 * Encode signature parameters from X.509 (EC)DSA signature.
 */
int dss_sig_value_encode(const dnssec_binary_t *r, const dnssec_binary_t *s,
			 dnssec_binary_t *der)
{
	if (!r || !r->data || !s || !s->data || !der) {
		return DNSSEC_EINVAL;
	}

	// check supported inputs range

	if (r->size > ASN1_MAX_SIZE || s->size > ASN1_MAX_SIZE) {
		return DNSSEC_NOT_IMPLEMENTED_ERROR;
	}

	size_t seq_size = 2 + r->size + 2 + s->size;
	if (seq_size > ASN1_MAX_SIZE) {
		return DNSSEC_NOT_IMPLEMENTED_ERROR;
	}

	// encode result

	size_t total_size = 2 + seq_size;
	uint8_t *encoded = malloc(total_size);
	if (!encoded) {
		return DNSSEC_ENOMEM;
	}

	wire_ctx_t wire = wire_init(encoded, total_size);

	asn1_write_header(&wire, ASN1_TYPE_SEQUENCE, seq_size);
	asn1_write_integer(&wire, r);
	asn1_write_integer(&wire, s);
	assert(wire_available(&wire) == 0);

	der->size = total_size;
	der->data = encoded;

	return DNSSEC_EOK;
}

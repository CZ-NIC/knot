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

#include <assert.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "key/algorithm.h"
#include "key/dnskey.h"
#include "shared.h"
#include "wire.h"

/**
 * Trim leading zeroes from binary data.
 *
 * GnuTLS uses Nettle, Nettle uses GMP, and some GMP conversions operations
 * return numbers prefixed with a zero byte. The byte is useless and can
 * create incompatibility with other DNSSEC software.
 */
static void trim_leading_zeros(gnutls_datum_t *data)
{
	assert(data);

	dnssec_binary_t tmp = datum_to_binary(data);
	dnssec_binary_ltrim(&tmp);
	*data = binary_to_datum(&tmp);
}

/* -- DNSSEC to crypto ------------------------------------------------------*/

/*!
 * Convert RSA public key to DNSSEC format.
 */
static int rsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	_cleanup_datum_ gnutls_datum_t modulus = { 0 };
	_cleanup_datum_ gnutls_datum_t pub_exponent = { 0 };

	int result = gnutls_pubkey_get_pk_rsa_raw(key, &modulus, &pub_exponent);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	trim_leading_zeros(&modulus);
	trim_leading_zeros(&pub_exponent);

	assert(pub_exponent.size <= UINT8_MAX);

	size_t size = 1 + pub_exponent.size + modulus.size;
	uint8_t *data = malloc(size);
	if (!data) {
		return DNSSEC_ENOMEM;
	}

	wire_ctx_t wire = wire_init(data, size);
	wire_write_u8(&wire, pub_exponent.size);
	wire_write_datum(&wire, &pub_exponent);
	wire_write_datum(&wire, &modulus);
	assert(wire_tell(&wire) == size);

	rdata->size = size;
	rdata->data = data;

	return DNSSEC_EOK;
}

/*!
 * Convert DSA public key to DNSSEC format.
 */
static int dsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	_cleanup_datum_ gnutls_datum_t p = { 0 };
	_cleanup_datum_ gnutls_datum_t q = { 0 };
	_cleanup_datum_ gnutls_datum_t g = { 0 };
	_cleanup_datum_ gnutls_datum_t y = { 0 };

	int result = gnutls_pubkey_get_pk_dsa_raw(key, &p, &q, &g, &y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	trim_leading_zeros(&p);
	trim_leading_zeros(&q);
	trim_leading_zeros(&g);
	trim_leading_zeros(&y);

	if (q.size != 20) {
		// only certain key size range can be exported in DNSKEY
		return DNSSEC_INVALID_KEY_SIZE;
	}

	assert(p.size == g.size && g.size == y.size);
	assert(p.size >= 64 && (p.size - 64) % 8 == 0);

	uint8_t t = (p.size - 64) / 8;

	size_t size = 1 + q.size + (3 * p.size);
	uint8_t *data = malloc(size);
	if (!data) {
		return DNSSEC_ENOMEM;
	}

	wire_ctx_t ctx = wire_init(data, size);
	wire_write_u8(&ctx, t);
	wire_write_datum(&ctx, &q);
	wire_write_datum(&ctx, &p);
	wire_write_datum(&ctx, &g);
	wire_write_datum(&ctx, &y);
	assert(wire_tell(&ctx) == size);

	rdata->size = size;
	rdata->data = data;

	return DNSSEC_EOK;
}

/*!
 * Convert ECDSA public key to DNSSEC format.
 */
static int ecdsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	_cleanup_datum_ gnutls_datum_t point_x = { 0 };
	_cleanup_datum_ gnutls_datum_t point_y = { 0 };
	gnutls_ecc_curve_t curve = { 0 };

	int result = gnutls_pubkey_get_pk_ecc_raw(key, &curve, &point_x, &point_y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	trim_leading_zeros(&point_x);
	trim_leading_zeros(&point_y);

	assert(point_x.size == point_y.size);

	size_t size = point_x.size + point_y.size;
	uint8_t *data = malloc(size);
	if (!data) {
		return DNSSEC_ENOMEM;
	}

	wire_ctx_t wire = wire_init(data, size);
	wire_write_datum(&wire, &point_x);
	wire_write_datum(&wire, &point_y);
	assert(wire_tell(&wire) == size);

	rdata->size = size;
	rdata->data = data;

	return DNSSEC_EOK;
}

/* -- crypto to DNSSEC ------------------------------------------------------*/

/*!
 * Convert RSA key in DNSSEC format to crypto key.
 */
static int rsa_rdata_to_pubkey(const dnssec_binary_t *rdata, gnutls_pubkey_t key)
{
	assert(rdata);
	assert(key);

	if (rdata->size == 0) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	wire_ctx_t ctx = wire_init_binary(rdata);

	// parse exponent

	_cleanup_datum_ gnutls_datum_t pub_exponent = { 0 };
	pub_exponent.size = wire_read_u8(&ctx);
	if (pub_exponent.size == 0 || wire_available(&ctx) < pub_exponent.size) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}
	pub_exponent.data = gnutls_malloc(pub_exponent.size);
	if (!pub_exponent.data) {
		return DNSSEC_ENOMEM;
	}
	wire_read_datum(&ctx, &pub_exponent);

	// parse modulus

	_cleanup_datum_ gnutls_datum_t modulus = { 0 };
	modulus.size = wire_available(&ctx);
	if (modulus.size == 0) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}
	modulus.data = gnutls_malloc(modulus.size);
	if (!modulus.data) {
		return DNSSEC_ENOMEM;
	}
	wire_read_datum(&ctx, &modulus);

	assert(wire_tell(&ctx) == rdata->size);

	int result = gnutls_pubkey_import_rsa_raw(key, &modulus, &pub_exponent);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	return DNSSEC_EOK;
}

/*!
 * Check if the size of DSA public key in DNSSEC format is correct.
 */
static bool valid_dsa_rdata_size(size_t size)
{
	// minimal key size
	if (size < 1 + 20 + 3 * 64) {
		return false;
	}

	// p, g, and y size equals
	size_t pgy_size = size - 20 - 1;
	if (pgy_size % 3 != 0) {
		return false;
	}

	// p size constraints
	size_t p_size = pgy_size / 3;
	if (p_size % 8 != 0) {
		return false;
	}

	return true;
}

/*!
 * Compute the DSA t value from RDATA public key size.
 */
static uint8_t expected_t_size(size_t size)
{
	size_t p_size = (size - 1 - 20) / 3;
	return (p_size - 64) / 8;
}

/*!
 * Convert DSA key in DNSSEC format to crypto key.
 */
static int dsa_rdata_to_pubkey(const dnssec_binary_t *rdata, gnutls_pubkey_t key)
{
	assert(rdata);
	assert(key);

	if (!valid_dsa_rdata_size(rdata->size)) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	wire_ctx_t ctx =wire_init_binary(rdata);

	// read t

	uint8_t t = wire_read_u8(&ctx);
	if (t != expected_t_size(rdata->size)) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	// parse q

	_cleanup_datum_ gnutls_datum_t q = { 0 };
	q.size = 20;
	q.data = gnutls_malloc(q.size);
	if (!q.data) {
		return DNSSEC_ENOMEM;
	}
	wire_read_datum(&ctx, &q);

	// parse p, g, and y

	_cleanup_datum_ gnutls_datum_t p = { 0 };
	_cleanup_datum_ gnutls_datum_t g = { 0 };
	_cleanup_datum_ gnutls_datum_t y = { 0 };
	p.size = g.size = y.size = wire_available(&ctx) / 3;
	p.data = gnutls_malloc(p.size);
	g.data = gnutls_malloc(g.size);
	y.data = gnutls_malloc(y.size);
	if (!p.data || !g.data || !y.data) {
		return DNSSEC_ENOMEM;
	}
	wire_read_datum(&ctx, &p);
	wire_read_datum(&ctx, &g);
	wire_read_datum(&ctx, &y);

	assert(wire_tell(&ctx) == rdata->size);

	int result = gnutls_pubkey_import_dsa_raw(key, &p, &q, &g, &y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	return DNSSEC_EOK;
}

/**
 * Choose proper ECDSA curve based on RDATA public key size.
 */
static gnutls_ecc_curve_t choose_ecdsa_curve(size_t rdata_size)
{
	switch (rdata_size) {
	case 64: return GNUTLS_ECC_CURVE_SECP256R1;
	case 96: return GNUTLS_ECC_CURVE_SECP384R1;
	default: return GNUTLS_ECC_CURVE_INVALID;
	}
}

/*!
 * Convert ECDSA key in DNSSEC format to crypto key.
 */
static int ecdsa_rdata_to_pubkey(const dnssec_binary_t *rdata, gnutls_pubkey_t key)
{
	assert(rdata);
	assert(key);

	gnutls_ecc_curve_t curve = choose_ecdsa_curve(rdata->size);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	wire_ctx_t ctx = wire_init_binary(rdata);

	// parse points

	_cleanup_datum_ gnutls_datum_t point_x = { 0 };
	_cleanup_datum_ gnutls_datum_t point_y = { 0 };
	point_x.size = point_y.size = rdata->size / 2;
	point_x.data = gnutls_malloc(point_x.size);
	point_y.data = gnutls_malloc(point_y.size);
	if (!point_x.data || !point_y.data) {
		return DNSSEC_ENOMEM;
	}
	wire_read_datum(&ctx, &point_x);
	wire_read_datum(&ctx, &point_y);

	assert(wire_tell(&ctx) == rdata->size);

	int result = gnutls_pubkey_import_ecc_raw(key, curve, &point_x, &point_y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	return DNSSEC_EOK;
}

/* -- internal API --------------------------------------------------------- */

/*!
 * Encode public key to the format used in DNSKEY RDATA.
 */
int convert_pubkey_to_dnskey(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	int algorithm = gnutls_pubkey_get_pk_algorithm(key, NULL);
	if (algorithm < 0) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	switch ((gnutls_pk_algorithm_t)algorithm) {
	case GNUTLS_PK_RSA: return rsa_pubkey_to_rdata(key, rdata);
	case GNUTLS_PK_DSA: return dsa_pubkey_to_rdata(key, rdata);
	case GNUTLS_PK_EC:  return ecdsa_pubkey_to_rdata(key, rdata);
	default:
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}
}

/*!
 * Create public key from the format encoded in DNSKEY RDATA.
 */
int convert_dnskey_to_pubkey(uint8_t algorithm, const dnssec_binary_t *rdata,
			     gnutls_pubkey_t key)
{
	assert(rdata);
	assert(key);

	gnutls_pk_algorithm_t gnutls_alg = algorithm_to_gnutls(algorithm);

	switch(gnutls_alg) {
	case GNUTLS_PK_RSA: return rsa_rdata_to_pubkey(rdata, key);
	case GNUTLS_PK_DSA: return dsa_rdata_to_pubkey(rdata, key);
	case GNUTLS_PK_EC:  return ecdsa_rdata_to_pubkey(rdata, key);
	default:
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}
}

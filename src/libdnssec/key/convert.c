/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libdnssec/shared/bignum.h"
#include "libdnssec/binary.h"
#include "libdnssec/error.h"
#include "libdnssec/key.h"
#include "libdnssec/key/algorithm.h"
#include "libdnssec/key/dnskey.h"
#include "libdnssec/shared/shared.h"
#include "libdnssec/shared/binary_wire.h"

/* -- wrappers for GnuTLS types -------------------------------------------- */

static size_t bignum_size_u_datum(const gnutls_datum_t *_bignum)
{
	const dnssec_binary_t bignum = binary_from_datum(_bignum);
	return bignum_size_u(&bignum);
}

static void wire_write_bignum_datum(wire_ctx_t *ctx, size_t width,
				    const gnutls_datum_t *_bignum)
{
	const dnssec_binary_t bignum = binary_from_datum(_bignum);
	bignum_write(ctx, width, &bignum);
}

static gnutls_datum_t wire_take_datum(wire_ctx_t *ctx, size_t count)
{
	gnutls_datum_t result = { .data = ctx->position, .size = count };
	ctx->position += count;

	return result;
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
	_cleanup_datum_ gnutls_datum_t exponent = { 0 };

	int result = gnutls_pubkey_get_pk_rsa_raw(key, &modulus, &exponent);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	size_t exponent_size = bignum_size_u_datum(&exponent);
	if (exponent_size > UINT8_MAX) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	size_t modulus_size = bignum_size_u_datum(&modulus);

	result = dnssec_binary_alloc(rdata, 1 + exponent_size + modulus_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t wire = binary_init(rdata);
	wire_ctx_write_u8(&wire, exponent_size);
	wire_write_bignum_datum(&wire, exponent_size, &exponent);
	wire_write_bignum_datum(&wire, modulus_size, &modulus);
	assert(wire_ctx_offset(&wire) == rdata->size);

	return DNSSEC_EOK;
}

/*!
 * Get point size for an ECDSA curve.
 */
static size_t ecdsa_curve_point_size(gnutls_ecc_curve_t curve)
{
	switch (curve) {
	case GNUTLS_ECC_CURVE_SECP256R1: return 32;
	case GNUTLS_ECC_CURVE_SECP384R1: return 48;
	default: return 0;
	}
}

#if defined(HAVE_ED25519) || defined(HAVE_ED448)
static size_t eddsa_curve_point_size(gnutls_ecc_curve_t curve)
{
	switch (curve) {
#ifdef HAVE_ED25519
	case GNUTLS_ECC_CURVE_ED25519: return 32;
#endif
#ifdef HAVE_ED448
	case GNUTLS_ECC_CURVE_ED448: return 57;
#endif
	default: return 0;
	}
}
#endif

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

	size_t point_size = ecdsa_curve_point_size(curve);
	if (point_size == 0) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	result = dnssec_binary_alloc(rdata, 2 * point_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t wire = binary_init(rdata);
	wire_write_bignum_datum(&wire, point_size, &point_x);
	wire_write_bignum_datum(&wire, point_size, &point_y);
	assert(wire_ctx_offset(&wire) == rdata->size);

	return DNSSEC_EOK;
}

/*!
 * Convert EDDSA public key to DNSSEC format.
 */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
static int eddsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	_cleanup_datum_ gnutls_datum_t point_x = { 0 };
	gnutls_ecc_curve_t curve = { 0 };

	int result = gnutls_pubkey_get_pk_ecc_raw(key, &curve, &point_x, NULL);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	size_t point_size = eddsa_curve_point_size(curve);
	if (point_size == 0) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	result = dnssec_binary_alloc(rdata, point_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t wire = binary_init(rdata);
	wire_write_bignum_datum(&wire, point_size, &point_x);
	assert(wire_ctx_offset(&wire) == rdata->size);

	return DNSSEC_EOK;
}
#endif

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

	wire_ctx_t ctx = binary_init(rdata);

	// parse public exponent

	uint8_t exponent_size = wire_ctx_read_u8(&ctx);
	if (exponent_size == 0 || wire_ctx_available(&ctx) < exponent_size) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	gnutls_datum_t exponent = wire_take_datum(&ctx, exponent_size);

	// parse modulus

	size_t modulus_size = wire_ctx_available(&ctx);
	if (modulus_size == 0) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	gnutls_datum_t modulus = wire_take_datum(&ctx, modulus_size);

	assert(wire_ctx_offset(&ctx) == rdata->size);

	int result = gnutls_pubkey_import_rsa_raw(key, &modulus, &exponent);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	return DNSSEC_EOK;
}

/**
 * Get ECDSA curve based on DNSKEY RDATA size.
 */
static gnutls_ecc_curve_t ecdsa_curve_from_rdata_size(size_t rdata_size)
{
	switch (rdata_size) {
	case 64: return GNUTLS_ECC_CURVE_SECP256R1;
	case 96: return GNUTLS_ECC_CURVE_SECP384R1;
	default: return GNUTLS_ECC_CURVE_INVALID;
	}
}

/**
 * Get EDDSA curve based on DNSKEY RDATA size.
 */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
static gnutls_ecc_curve_t eddsa_curve_from_rdata_size(size_t rdata_size)
{
	switch (rdata_size) {
#ifdef HAVE_ED25519
	case 32: return GNUTLS_ECC_CURVE_ED25519;
#endif
#ifdef HAVE_ED448
	case 57: return GNUTLS_ECC_CURVE_ED448;
#endif
	default: return GNUTLS_ECC_CURVE_INVALID;
	}
}
#endif

/*!
 * Convert ECDSA key in DNSSEC format to crypto key.
 */
static int ecdsa_rdata_to_pubkey(const dnssec_binary_t *rdata, gnutls_pubkey_t key)
{
	assert(rdata);
	assert(key);

	gnutls_ecc_curve_t curve = ecdsa_curve_from_rdata_size(rdata->size);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	// parse points

	wire_ctx_t ctx = binary_init(rdata);

	size_t point_size = wire_ctx_available(&ctx) / 2;
	gnutls_datum_t point_x = wire_take_datum(&ctx, point_size);
	gnutls_datum_t point_y = wire_take_datum(&ctx, point_size);
	assert(wire_ctx_offset(&ctx) == rdata->size);

	int result = gnutls_pubkey_import_ecc_raw(key, curve, &point_x, &point_y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	return DNSSEC_EOK;
}

/*!
 * Convert EDDSA key in DNSSEC format to crypto key.
 */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
static int eddsa_rdata_to_pubkey(const dnssec_binary_t *rdata, gnutls_pubkey_t key)
{
	assert(rdata);
	assert(key);

	gnutls_ecc_curve_t curve = eddsa_curve_from_rdata_size(rdata->size);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	wire_ctx_t ctx = binary_init(rdata);

	size_t point_size = wire_ctx_available(&ctx);
	gnutls_datum_t point_x = wire_take_datum(&ctx, point_size);
	assert(wire_ctx_offset(&ctx) == rdata->size);

	int result = gnutls_pubkey_import_ecc_raw(key, curve, &point_x, NULL);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	return DNSSEC_EOK;
}
#endif

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
	case GNUTLS_PK_EC:  return ecdsa_pubkey_to_rdata(key, rdata);
#ifdef HAVE_ED25519
	case GNUTLS_PK_EDDSA_ED25519: return eddsa_pubkey_to_rdata(key, rdata);
#endif
#ifdef HAVE_ED448
	case GNUTLS_PK_EDDSA_ED448: return eddsa_pubkey_to_rdata(key, rdata);
#endif
	default: return DNSSEC_INVALID_KEY_ALGORITHM;
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
	case GNUTLS_PK_EC:  return ecdsa_rdata_to_pubkey(rdata, key);
#ifdef HAVE_ED25519
	case GNUTLS_PK_EDDSA_ED25519: return eddsa_rdata_to_pubkey(rdata, key);
#endif
#ifdef HAVE_ED448
	case GNUTLS_PK_EDDSA_ED448: return eddsa_rdata_to_pubkey(rdata, key);
#endif
	default: return DNSSEC_INVALID_KEY_ALGORITHM;
	}
}

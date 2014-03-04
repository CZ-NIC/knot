#include <assert.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <stdint.h>
#include <string.h>

#include "binary.h"
#include "error.h"
#include "keys/pubkey.h"
#include "shared.h"
#include "wire.h"

// INTERNAL API (crypto dependent)

// auto cleanup functions

static void free_datum(gnutls_datum_t *ptr)
{
	gnutls_free(ptr->data);
}

#define _cleanup_datum_ _cleanup_(free_datum)

// internal

/*!
 * Trim leading zero from binary data.
 *
 * From some reason, numbers exported by GnuTLS are prefixed with a zero.
 */
static void trim_leading_zero(gnutls_datum_t *data)
{
	assert(data);

	if (data->data[0] == '\0') {
		memmove(data->data, data->data + 1, data->size - 1);
		data->size -= 1;

		assert(data->data[0] != '\0');
	}
}

static void wire_write_datum(wire_ctx_t *ctx, gnutls_datum_t *data)
{
	assert(data);
	wire_write(ctx, data->data, data->size);
}

// API

int rsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	_cleanup_datum_ gnutls_datum_t modulus = { 0 };
	_cleanup_datum_ gnutls_datum_t pub_exponent = { 0 };

	int result = gnutls_pubkey_get_pk_rsa_raw(key, &modulus, &pub_exponent);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_PUBKEY_EXPORT_ERROR;
	}

	trim_leading_zero(&modulus);
	trim_leading_zero(&pub_exponent);

	// TODO: larger keys are defined, but not used in real life
	assert(pub_exponent.size < UINT8_MAX);

	size_t size = 1 + pub_exponent.size + modulus.size;
	uint8_t *data = malloc(size);
	if (!data) {
		return DNSSEC_ENOMEM;
	}

	wire_ctx_t wire = { 0 };
	wire_init(&wire, data, size);

	wire_write_u8(&wire, pub_exponent.size);
	wire_write_datum(&wire, &pub_exponent);
	wire_write_datum(&wire, &modulus);
	assert(wire_tell(&wire) == size);

	rdata->size = size;
	rdata->data = data;

	return DNSSEC_EOK;
}

int dsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	// TODO: sensible names?
	_cleanup_datum_ gnutls_datum_t p = { 0 };
	_cleanup_datum_ gnutls_datum_t q = { 0 };
	_cleanup_datum_ gnutls_datum_t g = { 0 };
	_cleanup_datum_ gnutls_datum_t y = { 0 };

	int result = gnutls_pubkey_get_pk_dsa_raw(key, &p, &q, &g, &y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_PUBKEY_EXPORT_ERROR;
	}

	trim_leading_zero(&p);
	trim_leading_zero(&q);
	trim_leading_zero(&g);
	trim_leading_zero(&y);

	if (q.size != 20) {
		// only certain key size range can be exported in DNSKEY
		return DNSSEC_INVALID_KEY_SIZE;
	}

	assert(p.size == g.size && g.size == y.size);
	assert(p.size >= 64 && (p.size - 64) % 8 == 0); // TODO: >= ? > 64

	uint8_t t = (p.size - 64) / 8;

	size_t size = 1 + q.size + (3 * p.size);
	uint8_t *data = malloc(size);
	if (!data) {
		return DNSSEC_ENOMEM;
	}

	wire_ctx_t ctx;
	wire_init(&ctx, data, size);

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

int ecdsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	_cleanup_datum_ gnutls_datum_t point_x = { 0 };
	_cleanup_datum_ gnutls_datum_t point_y = { 0 };
	gnutls_ecc_curve_t curve = { 0 };

	int result = gnutls_pubkey_get_pk_ecc_raw(key, &curve, &point_x, &point_y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_PUBKEY_EXPORT_ERROR;
	}

	trim_leading_zero(&point_x);
	trim_leading_zero(&point_y);

	assert(point_x.size == point_y.size);

	size_t size = point_x.size + point_y.size;
	uint8_t *data = malloc(size);
	if (!data) {
		return DNSSEC_ENOMEM;
	}

	wire_ctx_t wire = { 0 };
	wire_init(&wire, data, size);
	wire_write_datum(&wire, &point_x);
	wire_write_datum(&wire, &point_y);
	assert(wire_tell(&wire) == size);

	rdata->size = size;
	rdata->data = data;

	return DNSSEC_EOK;
}

int rsa_rdata_to_pubkey(dnssec_binary_t *rdata, gnutls_pubkey_t key)
{
	return DNSSEC_ENOTSUP;
}

int dsa_rdata_to_pubkey(dnssec_binary_t *rdata, gnutls_pubkey_t key)
{
	return DNSSEC_ENOTSUP;
}

int ecdsa_rdata_to_pubkey(dnssec_binary_t *rdata, gnutls_pubkey_t key)
{
	return DNSSEC_ENOTSUP;
}

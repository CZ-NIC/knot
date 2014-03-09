#include <assert.h>
#include <gnutls/abstract.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "binary.h"
#include "error.h"
#include "hex.h"
#include "key.h"
#include "keys/pubkey.h"
#include "keytag.h"
#include "wire.h"

char *dnssec_key_id_to_string(const dnssec_key_id_t id)
{
	const dnssec_binary_t binary = {
		.data = (uint8_t *)id,
		.size = DNSSEC_KEY_ID_SIZE
	};

	return hex_to_string(&binary);
}

static bool key_is_valid(const dnssec_key_t *key)
{
	/*
	 * 2 bytes: flags
	 * 1 byte:  protocol
	 * 1 byte:  algorithm
	 * rest:    public key
	 */

	return key && key->rdata.size > 4;
}

static void update_keytag(dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return;
	}

	key->keytag = keytag(&key->rdata);
}

static void update_key_id(dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return;
	}

	assert(key->public_key);

	dnssec_key_id_t new_id;
	size_t id_size = DNSSEC_KEY_ID_SIZE;

	int r = gnutls_pubkey_get_key_id(key->public_key, 0, new_id, &id_size);
	if (r != GNUTLS_E_SUCCESS) {
		return;
	}

	assert(id_size == DNSSEC_KEY_ID_SIZE);

	memcpy(key->id, new_id, id_size);
}

int dnssec_key_new(dnssec_key_t **key_ptr)
{
	if (!key_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_key_t *key = malloc(sizeof(*key));
	if (!key) {
		return DNSSEC_ENOMEM;
	}

	clear_struct(key);
	*key_ptr = key;

	return DNSSEC_EOK;
}

void dnssec_key_clear(dnssec_key_t *key)
{
	if (!key) {
		return;
	}

	dnssec_binary_free(&key->rdata);
	gnutls_privkey_deinit(key->private_key);
	gnutls_pubkey_deinit(key->public_key);

	clear_struct(key);
}

void dnssec_key_free(dnssec_key_t **key_ptr)
{
	if (!key_ptr || !*key_ptr) {
		return;
	}

	dnssec_key_clear(*key_ptr);

	free(*key_ptr);
	*key_ptr = NULL;
}

uint16_t dnssec_key_get_flags(const dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return 0;
	}

	wire_ctx_t ctx;
	wire_init_binary(&ctx, &key->rdata);

	return wire_read_u16(&ctx);
}

uint8_t dnssec_key_get_protocol(const dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return 0;
	}

	wire_ctx_t ctx;
	wire_init_binary(&ctx, &key->rdata);
	wire_seek(&ctx, 2);

	return wire_read_u8(&ctx);
}

uint8_t dnssec_key_get_algorithm(const dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return 0;
	}

	wire_ctx_t ctx;
	wire_init_binary(&ctx, &key->rdata);
	wire_seek(&ctx, 3);

	return wire_read_u8(&ctx);
}

uint16_t dnssec_key_get_keytag(const dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return 0;
	}

	return key->keytag;
}

int dnssec_key_get_pubkey(const dnssec_key_t *key, dnssec_binary_t *pubkey)
{
	if (!key || !pubkey) {
		return DNSSEC_EINVAL;
	}

	wire_ctx_t ctx;
	wire_init_binary(&ctx, &key->rdata);
	wire_seek(&ctx, 4);

	pubkey->size = wire_available(&ctx);
	pubkey->data = ctx.position;

	return DNSSEC_EOK;
}

int dnssec_key_get_id(const dnssec_key_t *key, dnssec_key_id_t id)
{
	if (!key || !id) {
		return DNSSEC_EINVAL;
	}

	memcpy(id, key->id, DNSSEC_KEY_ID_SIZE);

	return DNSSEC_EOK;
}

int dnssec_key_from_params(dnssec_key_t *key, uint16_t flags, uint8_t protocol,
			   uint8_t algorithm, const dnssec_binary_t *public_key)
{
	if (!key || !public_key) {
		return DNSSEC_EINVAL;
	}

	size_t rdata_size = 4 + public_key->size;
	uint8_t *rdata = malloc(rdata_size);
	if (!rdata) {
		return DNSSEC_ENOMEM;
	}

	key->rdata.data = rdata;
	key->rdata.size = rdata_size;

	wire_ctx_t wc;
	wire_init(&wc, key->rdata.data, key->rdata.size);

	wire_write_u16(&wc, flags);
	wire_write_u8(&wc, protocol);
	wire_write_u8(&wc, algorithm);
	wire_write_binary(&wc, public_key);

	assert(wire_tell(&wc) == key->rdata.size);

	int result = gnutls_pubkey_init(&key->public_key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	result = rdata_to_pubkey(algorithm, public_key, key->public_key);
	if (result != DNSSEC_EOK) {
		return result;
	}

	update_keytag(key);
	update_key_id(key);

	return DNSSEC_EOK;
}

int dnssec_key_from_dnskey(dnssec_key_t *key, const dnssec_binary_t *rdata)
{
	if (!key || !rdata) {
		return DNSSEC_EINVAL;
	}

	int result = dnssec_binary_dup(rdata, &key->rdata);
	if (result != DNSSEC_EOK) {
		return result;
	}

	uint8_t algorithm = dnssec_key_get_algorithm(key);
	dnssec_binary_t pubkey = { 0 };
	result = dnssec_key_get_pubkey(key, &pubkey);
	if (result != DNSSEC_EOK) {
		return result;
	}

	result = gnutls_pubkey_init(&key->public_key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	result = rdata_to_pubkey(algorithm, &pubkey, key->public_key);
	if (result != DNSSEC_EOK) {
		return result;
	}

	update_keytag(key);
	update_key_id(key);

	return DNSSEC_EOK;
}

// TODO: move to crypto abstraction?
static void binary_to_datum(const dnssec_binary_t *binary, gnutls_datum_t *datum)
{
	assert(binary);
	assert(datum);

	datum->data = binary->data;
	datum->size = binary->size;
}

static void free_x509_privkey(gnutls_x509_privkey_t *ptr)
{
	if (*ptr) {
		gnutls_x509_privkey_deinit(*ptr);
	}
}

#define _cleanup_x509_privkey_ _cleanup_(free_x509_privkey)

int privkey_from_pkcs8(const dnssec_binary_t *pkcs8, gnutls_privkey_t *key)
{
	assert(pkcs8);
	assert(key);

	gnutls_datum_t data;
	binary_to_datum(pkcs8, &data);

	int result;

	_cleanup_x509_privkey_ gnutls_x509_privkey_t key_x509 = NULL;
	result = gnutls_x509_privkey_init(&key_x509);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	result = gnutls_x509_privkey_import_pkcs8(key_x509, &data,
						  GNUTLS_X509_FMT_PEM, NULL, 0);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_PKCS8_IMPORT_ERROR;
	}

	gnutls_privkey_t key_abs = NULL;
	result = gnutls_privkey_init(&key_abs);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	result = gnutls_privkey_import_x509(key_abs, key_x509, 0);
	if (result != GNUTLS_E_SUCCESS) {
		gnutls_privkey_deinit(key_abs);
		return DNSSEC_ENOMEM;
	}

	*key = key_abs;

	return DNSSEC_EOK;
}

int dnssec_key_from_pkcs8(dnssec_key_t *key, const dnssec_binary_t *pkcs8_data)
{
	if (!key || !pkcs8_data) {
		return DNSSEC_EINVAL;
	}

	gnutls_privkey_t private_key = NULL;
	int result = privkey_from_pkcs8(pkcs8_data, &private_key);
	if (result != DNSSEC_EOK) {
		return result;
	}

	gnutls_pubkey_t public_key = NULL;
	result = gnutls_pubkey_init(&public_key);
	if (result != DNSSEC_EOK) {
		gnutls_privkey_deinit(private_key);
		return result;
	}

	key->private_key = private_key;
	key->public_key = public_key;

	return DNSSEC_EOK;
}

int dnssec_key_get_dnskey(const dnssec_key_t *key, dnssec_binary_t *rdata)
{
	if (!key_is_valid(key)) {
		return DNSSEC_EINVAL;
	}

	dnssec_binary_t copy = { 0 };
	int result = dnssec_binary_dup(&key->rdata, &copy);
	if (result != DNSSEC_EOK) {
		return result;
	}

	*rdata = copy;
	return DNSSEC_EOK;
}

int dnssec_key_get_ds(const dnssec_key_t *key, dnssec_key_digest_t digest,
		      dnssec_binary_t *rdata)
{
	return DNSSEC_ERROR;
}

#include <assert.h>
#include <gnutls/abstract.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "key/internal.h"
#include "key/keytag.h"
#include "key/pubkey.h"
#include "wire.h"

/*!
 * DNSKEY RDATA fields offsets.
 *
 * \see RFC 4034 (section 2.1)
 */
enum dnskey_rdata_offsets {
	DNSKEY_RDATA_OFFSET_FLAGS = 0,
	DNSKEY_RDATA_OFFSET_PROTOCOL = 2,
	DNSKEY_RDATA_OFFSET_ALGORITHM = 3,
	DNSKEY_RDATA_OFFSET_PUBKEY = 4,
};

/*!
 * Minimal size of DNSKEY RDATA.
 */
#define DNSKEY_RDATA_MIN_SIZE DNSKEY_RDATA_OFFSET_PUBKEY

/*!
 * RDATA template for newly allocated keys.
 */
static const dnssec_binary_t DNSKEY_RDATA_TEMPLATE = {
	.size = 4,
	.data = (uint8_t []) { 0x01, 0x00, 0x03, 0x00 }
};

/* -- key allocation ------------------------------------------------------- */

int dnssec_key_new(dnssec_key_t **key_ptr)
{
	if (!key_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_key_t *key = calloc(1, sizeof(*key));
	if (!key) {
		return DNSSEC_ENOMEM;
	}

	int r = dnssec_binary_dup(&DNSKEY_RDATA_TEMPLATE, &key->rdata);
	if (r != DNSSEC_EOK) {
		free(key);
		return DNSSEC_ENOMEM;
	}

	*key_ptr = key;

	return DNSSEC_EOK;
}

/*!
 * Clear public and private keys used by crypto backend.
 */
static void free_crypto_keys(dnssec_key_t *key)
{
	assert(key);

	gnutls_privkey_deinit(key->private_key);
	key->private_key = NULL;

	gnutls_pubkey_deinit(key->public_key);
	key->public_key = NULL;
}

void dnssec_key_clear(dnssec_key_t *key)
{
	if (!key) {
		return;
	}

	// reuse RDATA
	dnssec_binary_t rdata = key->rdata;

	// clear the structure
	free_crypto_keys(key);
	clear_struct(key);

	// restore template RDATA (downsize, no need to realloc)
	assert(rdata.size >= DNSKEY_RDATA_MIN_SIZE);
	rdata.size = DNSKEY_RDATA_MIN_SIZE;
	memcpy(rdata.data, DNSKEY_RDATA_TEMPLATE.data, rdata.size);

	key->rdata = rdata;
}

void dnssec_key_free(dnssec_key_t *key)
{
	if (!key) {
		return;
	}

	free_crypto_keys(key);
	dnssec_binary_free(&key->rdata);

	free(key);
}

/* -- key identifiers ------------------------------------------------------ */

/*!
 * Update key tag, should be called when anything in RDATA changes.
 */
static void update_keytag(dnssec_key_t *key)
{
	assert(key);
	keytag(&key->rdata, &key->keytag);
}

/*!
 * Update key ID (X.509 CKA_ID), should be called when public key changes.
 */
static void update_key_id(dnssec_key_t *key)
{
	assert(key);
	assert(key->public_key);

	dnssec_key_id_t new_id = { 0 };
	size_t id_size = DNSSEC_KEY_ID_SIZE;
	gnutls_pubkey_get_key_id(key->public_key, 0, new_id, &id_size);
	assert(id_size == DNSSEC_KEY_ID_SIZE);

	dnssec_key_id_copy(new_id, key->id);
}

int dnssec_key_get_keytag(const dnssec_key_t *key, uint16_t *keytag)
{
	if (!key || !keytag) {
		return DNSSEC_EINVAL;
	}

	*keytag = key->keytag;

	return DNSSEC_EOK;
}

int dnssec_key_get_id(const dnssec_key_t *key, dnssec_key_id_t id)
{
	if (!key || !id) {
		return DNSSEC_EINVAL;
	}

	dnssec_key_id_copy(key->id, id);

	return DNSSEC_EOK;
}

/* -- freely modifiable attributes ----------------------------------------- */

#define rdata_read(rdata, offset, size, var) \
{\
	wire_ctx_t wire = wire_init_binary(rdata); \
	wire_seek(&wire, DNSKEY_RDATA_OFFSET_##offset); \
	*var = wire_read_u##size(&wire); \
}

#define rdata_write(rdata, offset, size, var) \
{\
	wire_ctx_t wire = wire_init_binary(rdata); \
	wire_seek(&wire, DNSKEY_RDATA_OFFSET_##offset); \
	wire_write_u##size(&wire, var); \
}

int dnssec_key_get_flags(const dnssec_key_t *key, uint16_t *flags)
{
	if (!key || !flags) {
		return DNSSEC_EINVAL;
	}

	rdata_read(&key->rdata, FLAGS, 16, flags);

	return DNSSEC_EOK;
}

int dnssec_key_set_flags(dnssec_key_t *key, uint16_t flags)
{
	if (!key) {
		return DNSSEC_EINVAL;
	}

	rdata_write(&key->rdata, FLAGS, 16, flags);
	update_keytag(key);

	return DNSSEC_EOK;
}

int dnssec_key_get_protocol(const dnssec_key_t *key, uint8_t *protocol)
{
	if (!key || !protocol) {
		return DNSSEC_EINVAL;
	}

	rdata_read(&key->rdata, PROTOCOL, 8, protocol);

	return DNSSEC_EOK;
}

int dnssec_key_set_protocol(dnssec_key_t *key, uint8_t protocol)
{
	if (!key) {
		return DNSSEC_EINVAL;
	}

	rdata_write(&key->rdata, PROTOCOL, 8, protocol);
	update_keytag(key);

	return DNSSEC_EOK;
}

/* -- restriced attributes ------------------------------------------------- */

/*!
 * Check if current public key algorithm matches with the new algorithm.
 */
static bool can_change_algorithm(dnssec_key_t *key, uint8_t algorithm)
{
	assert(key);

	if (!key->public_key) {
		return true;
	}

	gnutls_pk_algorithm_t new = dnskey_algorithm_to_gnutls(algorithm);
	if (new == GNUTLS_PK_UNKNOWN) {
		return false;
	}

	int current = gnutls_pubkey_get_pk_algorithm(key->public_key, NULL);
	assert(current >= 0);

	return current == new;
}

/*!
 * Create a public key.
 */
static int create_public_key(dnssec_key_t *key)
{
	assert(key);
	assert(!key->public_key);

	gnutls_pubkey_t new_key = NULL;
	int result = gnutls_pubkey_init(&new_key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	uint8_t algorithm = 0;
	dnssec_key_get_algorithm(key, &algorithm);

	dnssec_binary_t rdata_pubkey = { 0 };
	dnssec_key_get_pubkey(key, &rdata_pubkey);

	result = rdata_to_pubkey(algorithm, &rdata_pubkey, new_key);
	if (result != DNSSEC_EOK) {
		gnutls_pubkey_deinit(new_key);
		return result;
	}

	key->public_key = new_key;

	return DNSSEC_EOK;
}

int dnssec_key_get_algorithm(const dnssec_key_t *key, uint8_t *algorithm)
{
	if (!key || !algorithm) {
		return DNSSEC_EINVAL;
	}

	rdata_read(&key->rdata, ALGORITHM, 8, algorithm);

	return DNSSEC_EOK;
}

int dnssec_key_set_algorithm(dnssec_key_t *key, uint8_t algorithm)
{
	if (!key) {
		return DNSSEC_EINVAL;
	}

	if (!can_change_algorithm(key, algorithm)) {
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	rdata_write(&key->rdata, ALGORITHM, 8, algorithm);
	update_keytag(key);

	return DNSSEC_EOK;
}

int dnssec_key_get_pubkey(const dnssec_key_t *key, dnssec_binary_t *pubkey)
{
	if (!key || !pubkey) {
		return DNSSEC_EINVAL;
	}

	wire_ctx_t ctx;
	wire_init_binary(&ctx, &key->rdata);
	wire_seek(&ctx, DNSKEY_RDATA_OFFSET_PUBKEY);

	pubkey->size = wire_available(&ctx);
	pubkey->data = ctx.position;

	return DNSSEC_EOK;
}

int dnssec_key_set_pubkey(dnssec_key_t *key, const dnssec_binary_t *data)
{
	if (!key || !data || !data->data) {
		return DNSSEC_EINVAL;
	}

	if (key->public_key) {
		return DNSSEC_KEY_ALREADY_PRESENT;
	}

	size_t rdata_size = DNSKEY_RDATA_OFFSET_PUBKEY + data->size;
	int result = dnssec_binary_resize(&key->rdata, rdata_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t wire;
	wire_init_binary(&wire, &key->rdata);
	wire_seek(&wire, DNSKEY_RDATA_OFFSET_PUBKEY);
	wire_write_binary(&wire, data);
	assert(wire_tell(&wire) == rdata_size);

	update_keytag(key);

	result = create_public_key(key);
	if (result != DNSSEC_EOK) {
		return result;
	}

	update_key_id(key);

	return DNSSEC_EOK;
}

int dnssec_key_get_rdata(const dnssec_key_t *key, dnssec_binary_t *rdata)
{
	if (!key || !rdata) {
		return DNSSEC_EINVAL;
	}

	*rdata = key->rdata;

	return DNSSEC_EOK;
}

int dnssec_key_set_rdata(dnssec_key_t *key, const dnssec_binary_t *rdata)
{
	if (!key || !rdata || !rdata->data) {
		return DNSSEC_EINVAL;
	}

	if (rdata->size < DNSKEY_RDATA_MIN_SIZE) {
		return DNSSEC_MALFORMED_DATA;
	}

	if (key->public_key) {
		return DNSSEC_KEY_ALREADY_PRESENT;
	}

	int result = dnssec_binary_resize(&key->rdata, rdata->size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	memcpy(key->rdata.data, rdata->data, rdata->size);

	update_keytag(key);

	result = create_public_key(key);
	if (result != DNSSEC_EOK) {
		key->rdata.size = DNSKEY_RDATA_MIN_SIZE;
		return result;
	}

	update_key_id(key);

	return DNSSEC_EOK;
}

/* -- private key import --------------------------------------------------- */

static int privkey_from_pem(const dnssec_binary_t *pem, gnutls_privkey_t *key,
			    dnssec_key_id_t key_id)
{
	assert(pem);
	assert(key);

	gnutls_datum_t data;
	binary_to_datum(pem, &data);

	gnutls_x509_privkey_t key_x509 = NULL;
	int result = gnutls_x509_privkey_init(&key_x509);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	result = gnutls_x509_privkey_import_pkcs8(key_x509, &data,
						  GNUTLS_X509_FMT_PEM, NULL, 0);
	if (result != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(key_x509);
		return DNSSEC_PKCS8_IMPORT_ERROR;
	}

	gnutls_privkey_t key_abs = NULL;
	result = gnutls_privkey_init(&key_abs);
	if (result != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(key_x509);
		return DNSSEC_ENOMEM;
	}

	result = gnutls_privkey_import_x509(key_abs, key_x509,
					    GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
	if (result != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(key_x509);
		gnutls_privkey_deinit(key_abs);
		return DNSSEC_ENOMEM;
	}

	dnssec_key_id_t id = { 0 };
	size_t id_size = DNSSEC_KEY_ID_SIZE;
	gnutls_x509_privkey_get_key_id(key_x509, 0, id, &id_size);
	assert(id_size == DNSSEC_KEY_ID_SIZE);

	*key = key_abs;
	dnssec_key_id_copy(id, key_id);

	return DNSSEC_EOK;
}

static int pubkey_from_privkey(gnutls_privkey_t privkey, gnutls_pubkey_t *pubkey)
{
	assert(privkey);
	assert(pubkey);

	gnutls_pubkey_t new_key = NULL;
	int result = gnutls_pubkey_init(&new_key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	result = gnutls_pubkey_import_privkey(new_key, privkey, 0, 0);
	if (result != GNUTLS_E_SUCCESS) {
		gnutls_pubkey_deinit(new_key);
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	*pubkey = new_key;

	return DNSSEC_EOK;
}

int dnssec_key_load_pkcs8(dnssec_key_t *key, const dnssec_binary_t *pem)
{
	if (!key || !pem) {
		return DNSSEC_EINVAL;
	}

	gnutls_privkey_t private_key = NULL;
	dnssec_key_id_t new_key_id = { 0 };
	int result = privkey_from_pem(pem, &private_key, new_key_id);
	if (result != DNSSEC_EOK) {
		return result;
	}

	if (key->public_key && dnssec_key_id_cmp(key->id, new_key_id) != 0) {
		gnutls_privkey_deinit(private_key);
		return DNSSEC_INVALID_KEY_ID;
	}

	if (key->public_key) {
		key->private_key = private_key;
		return DNSSEC_EOK;
	}

	gnutls_pubkey_t public_key = NULL;
	result = pubkey_from_privkey(private_key, &public_key);
	if (result != DNSSEC_EOK) {
		gnutls_privkey_deinit(private_key);
		return result;
	}

	dnssec_key_id_copy(new_key_id, key->id);
	key->public_key = public_key;
	key->private_key = private_key;

	return DNSSEC_EOK;
}

/* -- key presence checking ------------------------------------------------ */

bool dnssec_key_can_sign(const dnssec_key_t *key)
{
	return key && key->private_key;
}

bool dnssec_key_can_verify(const dnssec_key_t *key)
{
	return key && key->public_key;
}

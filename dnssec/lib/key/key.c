#include <assert.h>
#include <gnutls/abstract.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "keystore.h"
#include "key/algorithm.h"
#include "key/convert.h"
#include "key/dnskey.h"
#include "key/internal.h"
#include "key/keyid.h"
#include "key/keytag.h"
#include "keystore/pem.h"
#include "shared.h"
#include "wire.h"

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

_public_
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
static void free_keys(dnssec_key_t *key)
{
	assert(key);

	gnutls_privkey_deinit(key->private_key);
	key->private_key = NULL;

	gnutls_pubkey_deinit(key->public_key);
	key->public_key = NULL;
}

_public_
void dnssec_key_clear(dnssec_key_t *key)
{
	if (!key) {
		return;
	}

	// reuse RDATA
	dnssec_binary_t rdata = key->rdata;

	// clear the structure
	free_keys(key);
	clear_struct(key);

	// restore template RDATA (downsize, no need to realloc)
	assert(rdata.size >= DNSKEY_RDATA_MIN_SIZE);
	rdata.size = DNSKEY_RDATA_MIN_SIZE;
	memmove(rdata.data, DNSKEY_RDATA_TEMPLATE.data, rdata.size);

	key->rdata = rdata;
}

_public_
void dnssec_key_free(dnssec_key_t *key)
{
	if (!key) {
		return;
	}

	free_keys(key);
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

	gnutls_pubkey_to_key_id(key->public_key, key->id);
}

_public_
int dnssec_key_get_keytag(const dnssec_key_t *key, uint16_t *keytag)
{
	if (!key || !keytag) {
		return DNSSEC_EINVAL;
	}

	*keytag = key->keytag;

	return DNSSEC_EOK;
}

_public_
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

_public_
int dnssec_key_get_flags(const dnssec_key_t *key, uint16_t *flags)
{
	if (!key || !flags) {
		return DNSSEC_EINVAL;
	}

	rdata_read(&key->rdata, FLAGS, 16, flags);

	return DNSSEC_EOK;
}

_public_
int dnssec_key_set_flags(dnssec_key_t *key, uint16_t flags)
{
	if (!key) {
		return DNSSEC_EINVAL;
	}

	rdata_write(&key->rdata, FLAGS, 16, flags);
	update_keytag(key);

	return DNSSEC_EOK;
}

_public_
int dnssec_key_get_protocol(const dnssec_key_t *key, uint8_t *protocol)
{
	if (!key || !protocol) {
		return DNSSEC_EINVAL;
	}

	rdata_read(&key->rdata, PROTOCOL, 8, protocol);

	return DNSSEC_EOK;
}

_public_
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

	gnutls_pk_algorithm_t new = algorithm_to_gnutls(algorithm);
	if (new == GNUTLS_PK_UNKNOWN) {
		return false;
	}

	int current = gnutls_pubkey_get_pk_algorithm(key->public_key, NULL);
	assert(current >= 0);

	return current == new;
}

_public_
int dnssec_key_get_algorithm(const dnssec_key_t *key, uint8_t *algorithm)
{
	if (!key || !algorithm) {
		return DNSSEC_EINVAL;
	}

	rdata_read(&key->rdata, ALGORITHM, 8, algorithm);

	return DNSSEC_EOK;
}

_public_
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

_public_
int dnssec_key_get_pubkey(const dnssec_key_t *key, dnssec_binary_t *pubkey)
{
	if (!key || !pubkey) {
		return DNSSEC_EINVAL;
	}

	dnssec_binary_t rdata_pubkey = { 0 };

	wire_ctx_t wire = wire_init_binary(&key->rdata);
	wire_seek(&wire, DNSKEY_RDATA_OFFSET_PUBKEY);
	wire_available_binary(&wire, &rdata_pubkey);

	return dnssec_binary_dup(&rdata_pubkey, pubkey);
}

_public_
int dnssec_key_set_pubkey(dnssec_key_t *key, const dnssec_binary_t *pubkey)
{
	if (!key || !pubkey || !pubkey->data) {
		return DNSSEC_EINVAL;
	}

	if (key->public_key) {
		return DNSSEC_KEY_ALREADY_PRESENT;
	}

	dnssec_binary_t new_rdata = key->rdata;
	int result = dnskey_rdata_set_pubkey(&new_rdata, pubkey);
	if (result != DNSSEC_EOK) {
		return result;
	}

	gnutls_pubkey_t new_pubkey = NULL;
	result = dnskey_rdata_to_crypto_key(&new_rdata, &new_pubkey);
	if (result != DNSSEC_EOK) {
		return result;
	}

	// commit result

	key->rdata = new_rdata;
	key->public_key = new_pubkey;

	update_key_id(key);
	update_keytag(key);

	return DNSSEC_EOK;
}

_public_
int dnssec_key_get_rdata(const dnssec_key_t *key, dnssec_binary_t *rdata)
{
	if (!key || !rdata) {
		return DNSSEC_EINVAL;
	}

	return dnssec_binary_dup(&key->rdata, rdata);
}

_public_
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

	dnssec_binary_t new_rdata = key->rdata;
	int result = dnssec_binary_resize(&new_rdata, rdata->size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	gnutls_pubkey_t new_pubkey = NULL;
	result = dnskey_rdata_to_crypto_key(rdata, &new_pubkey);
	if (result != DNSSEC_EOK) {
		return result;
	}

	memmove(new_rdata.data, rdata->data, rdata->size);

	// commit result

	key->rdata = new_rdata;
	key->public_key = new_pubkey;

	update_key_id(key);
	update_keytag(key);

	return DNSSEC_EOK;
}

/* -- key presence checking ------------------------------------------------ */

_public_
bool dnssec_key_can_sign(const dnssec_key_t *key)
{
	return key && key->private_key;
}

_public_
bool dnssec_key_can_verify(const dnssec_key_t *key)
{
	return key && key->public_key;
}

/* -- internal API --------------------------------------------------------- */

void key_update_identifiers(dnssec_key_t *key)
{
	assert(key);

	update_keytag(key);
	update_key_id(key);
}

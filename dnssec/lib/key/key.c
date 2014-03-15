#include <assert.h>
#include <gnutls/abstract.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "binary.h"
#include "error.h"
#include "hex.h"
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
	.data = (uint8_t []) { 0x00, 0x00, 0x03, 0x00 }
};

/* -- key allocation ------------------------------------------------------- */

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

	int r = dnssec_binary_dup(&DNSKEY_RDATA_TEMPLATE, &key->rdata);
	if (r != DNSSEC_EOK) {
		free(key);
		return DNSSEC_ENOMEM;
	}

	*key_ptr = key;

	return DNSSEC_EOK;
}

void dnssec_key_clear(dnssec_key_t *key)
{
	if (!key) {
		return;
	}

	// reuse RDATA
	dnssec_binary_t rdata = key->rdata;

	// clear the structure
	gnutls_privkey_deinit(key->private_key);
	gnutls_pubkey_deinit(key->public_key);
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

	gnutls_privkey_deinit(key->private_key);
	gnutls_pubkey_deinit(key->public_key);
	dnssec_binary_free(&key->rdata);

	free(key);
}

/* -- key identifiers ------------------------------------------------------ */

static void update_identifiers(dnssec_key_t *key)
{
	assert(key);
	assert(key->public_key);

	// DNSSEC keytag

	keytag(&key->rdata, &key->keytag);

	// X.509 CKA_ID

	dnssec_key_id_t new_id;
	size_t id_size = DNSSEC_KEY_ID_SIZE;
	int r = gnutls_pubkey_get_key_id(key->public_key, 0, new_id, &id_size);
	if (r != GNUTLS_E_SUCCESS) {
		return;
	}

	assert(id_size == DNSSEC_KEY_ID_SIZE);
	memcpy(key->id, new_id, id_size);
}

char *dnssec_key_id_to_string(const dnssec_key_id_t id)
{
	const dnssec_binary_t binary = {
		.data = (uint8_t *)id,
		.size = DNSSEC_KEY_ID_SIZE
	};

	return hex_to_string(&binary);
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

	memcpy(id, key->id, DNSSEC_KEY_ID_SIZE);

	return DNSSEC_EOK;
}

/* -- key attributes ------------------------------------------------------- */

int dnssec_key_get_flags(const dnssec_key_t *key, uint16_t *flags)
{
	if (!key || !flags) {
		return DNSSEC_EINVAL;
	}

	wire_ctx_t ctx;
	wire_init_binary(&ctx, &key->rdata);
	wire_seek(&ctx, DNSKEY_RDATA_OFFSET_FLAGS);
	*flags = wire_read_u16(&ctx);

	return DNSSEC_EOK;
}

int dnssec_key_get_protocol(const dnssec_key_t *key, uint8_t *protocol)
{
	if (!key || !protocol) {
		return DNSSEC_EINVAL;
	}

	wire_ctx_t ctx;
	wire_init_binary(&ctx, &key->rdata);
	wire_seek(&ctx, DNSKEY_RDATA_OFFSET_PROTOCOL);
	*protocol = wire_read_u8(&ctx);

	return DNSSEC_EOK;
}

int dnssec_key_get_algorithm(const dnssec_key_t *key, uint8_t *algorithm)
{
	if (!key || !algorithm) {
		return DNSSEC_EINVAL;
	}

	wire_ctx_t ctx;
	wire_init_binary(&ctx, &key->rdata);
	wire_seek(&ctx, DNSKEY_RDATA_OFFSET_ALGORITHM);
	*algorithm = wire_read_u8(&ctx);

	return DNSSEC_EOK;
}

// TODO: ref or alloc?
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

// TODO: ref or alloc?
int dnssec_key_get_rdata(const dnssec_key_t *key, dnssec_binary_t *rdata)
{
	if (!key || !rdata) {
		return DNSSEC_EINVAL;
	}

	*rdata = key->rdata;

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

/* -- public key construction ---------------------------------------------- */

int dnssec_key_from_params(dnssec_key_t *key, uint16_t flags, uint8_t protocol,
			   uint8_t algorithm, const dnssec_binary_t *public_key)
{
	if (!key || !public_key || !public_key->data) {
		return DNSSEC_EINVAL;
	}

	size_t rdata_size = DNSKEY_RDATA_OFFSET_PUBKEY + public_key->size;
	int result = dnssec_binary_resize(&key->rdata, rdata_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t rdata;
	wire_init_binary(&rdata, &key->rdata);

	wire_write_u16(&rdata, flags);
	wire_write_u8(&rdata, protocol);
	wire_write_u8(&rdata, algorithm);
	wire_write_binary(&rdata, public_key);

	assert(wire_tell(&rdata) == rdata_size);

	result = gnutls_pubkey_init(&key->public_key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	result = rdata_to_pubkey(algorithm, public_key, key->public_key);
	if (result != DNSSEC_EOK) {
		return result;
	}

	update_identifiers(key);

	return DNSSEC_EOK;
}

int dnssec_key_from_dnskey(dnssec_key_t *key, const dnssec_binary_t *rdata)
{
	if (!key || !rdata || !rdata->data) {
		return DNSSEC_EINVAL;
	}

	int result = dnssec_binary_resize(&key->rdata, rdata->size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	memcpy(key->rdata.data, rdata->data, rdata->size);

	uint8_t algorithm = 0;
	dnssec_key_get_algorithm(key, &algorithm);
	dnssec_binary_t pubkey = { 0 };
	dnssec_key_get_pubkey(key, &pubkey);

	result = gnutls_pubkey_init(&key->public_key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	result = rdata_to_pubkey(algorithm, &pubkey, key->public_key);
	if (result != DNSSEC_EOK) {
		return result;
	}

	update_identifiers(key);

	return DNSSEC_EOK;
}

//int privkey_from_pkcs8(const dnssec_binary_t *pkcs8, gnutls_privkey_t *key)
//{
//	assert(pkcs8);
//	assert(key);
//
//	gnutls_datum_t data;
//	binary_to_datum(pkcs8, &data);
//
//	int result;
//
//	_cleanup_x509_privkey_ gnutls_x509_privkey_t key_x509 = NULL;
//	result = gnutls_x509_privkey_init(&key_x509);
//	if (result != GNUTLS_E_SUCCESS) {
//		return DNSSEC_ENOMEM;
//	}
//
//	result = gnutls_x509_privkey_import_pkcs8(key_x509, &data,
//						  GNUTLS_X509_FMT_PEM, NULL, 0);
//	if (result != GNUTLS_E_SUCCESS) {
//		return DNSSEC_PKCS8_IMPORT_ERROR;
//	}
//
//	gnutls_privkey_t key_abs = NULL;
//	result = gnutls_privkey_init(&key_abs);
//	if (result != GNUTLS_E_SUCCESS) {
//		return DNSSEC_ENOMEM;
//	}
//
//	result = gnutls_privkey_import_x509(key_abs, key_x509, 0);
//	if (result != GNUTLS_E_SUCCESS) {
//		gnutls_privkey_deinit(key_abs);
//		return DNSSEC_ENOMEM;
//	}
//
//	*key = key_abs;
//
//	return DNSSEC_EOK;
//}
//
//int dnssec_key_from_pkcs8(dnssec_key_t *key, const dnssec_binary_t *pkcs8_data)
//{
//	if (!key || !pkcs8_data) {
//		return DNSSEC_EINVAL;
//	}
//
//	gnutls_privkey_t private_key = NULL;
//	int result = privkey_from_pkcs8(pkcs8_data, &private_key);
//	if (result != DNSSEC_EOK) {
//		return result;
//	}
//
//	gnutls_pubkey_t public_key = NULL;
//	result = gnutls_pubkey_init(&public_key);
//	if (result != DNSSEC_EOK) {
//		gnutls_privkey_deinit(private_key);
//		return result;
//	}
//
//	key->private_key = private_key;
//	key->public_key = public_key;
//
//	return DNSSEC_EOK;
//}

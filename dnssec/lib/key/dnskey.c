#include "binary.h"
#include "error.h"
#include "key/dnskey.h"
#include "key/convert.h"
#include "wire.h"

/* -- internal API --------------------------------------------------------- */

/*!
 * Update 'Public key' field of DNSKEY RDATA.
 */
int dnskey_rdata_set_pubkey(dnssec_binary_t *rdata, const dnssec_binary_t *pubkey)
{
	assert(rdata);
	assert(pubkey);

	size_t new_size = DNSKEY_RDATA_OFFSET_PUBKEY + pubkey->size;
	int result = dnssec_binary_resize(rdata, new_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t wire = wire_init_binary(rdata);
	wire_seek(&wire, DNSKEY_RDATA_OFFSET_PUBKEY);
	wire_write_binary(&wire, pubkey);
	assert(wire_tell(&wire) == rdata->size);

	return DNSSEC_EOK;
}

/*!
 * Create a GnuTLS public key from DNSKEY RDATA.
 *
 * \param rdata    DNSKEY RDATA.
 * \param key_ptr  Resulting public key.
 */
int dnskey_rdata_to_crypto_key(const dnssec_binary_t *rdata, gnutls_pubkey_t *key_ptr)
{
	assert(rdata);
	assert(key_ptr);

	uint8_t algorithm = 0;
	dnssec_binary_t rdata_pubkey = { 0 };

	wire_ctx_t wire = wire_init_binary(rdata);
	wire_seek(&wire, DNSKEY_RDATA_OFFSET_ALGORITHM);
	algorithm = wire_read_u8(&wire);
	wire_seek(&wire, DNSKEY_RDATA_OFFSET_PUBKEY);
	wire_available_binary(&wire, &rdata_pubkey);

	gnutls_pubkey_t key = NULL;
	int result = gnutls_pubkey_init(&key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	result = convert_dnskey_to_pubkey(algorithm, &rdata_pubkey, key);
	if (result != DNSSEC_EOK) {
		gnutls_pubkey_deinit(key);
		return result;
	}

	*key_ptr = key;

	return DNSSEC_EOK;
}

/* -- move to some other place API ----------------------------------------- */
#warning "Move this to some proper place..."

#include "key/internal.h"
#include "key/algorithm.h"
#include "keystore/public.h"

static int create_public_key(gnutls_privkey_t privkey,
			     gnutls_pubkey_t *pubkey_ptr,
			     dnssec_binary_t *rdata)
{
	assert(privkey);
	assert(pubkey_ptr);
	assert(rdata);

	// crypto public key

	gnutls_pubkey_t pubkey = NULL;
	int result = public_from_private(privkey, &pubkey);
	if (result != DNSSEC_EOK) {
		return result;
	}

	// dnssec public key

	_cleanup_binary_ dnssec_binary_t rdata_pubkey = { 0 };
	result = convert_pubkey_to_dnskey(pubkey, &rdata_pubkey);
	if (result != DNSSEC_EOK) {
		gnutls_pubkey_deinit(pubkey);
		return result;
	}

	size_t rdata_size = DNSKEY_RDATA_OFFSET_PUBKEY + rdata_pubkey.size;
	result = dnssec_binary_resize(rdata, rdata_size);
	if (result != DNSSEC_EOK) {
		gnutls_pubkey_deinit(pubkey);
		return result;
	}

	// updated RDATA

	wire_ctx_t wire = wire_init_binary(rdata);
	wire_seek(&wire, DNSKEY_RDATA_OFFSET_PUBKEY);
	wire_write_binary(&wire, &rdata_pubkey);
	assert(wire_tell(&wire) == rdata->size);

	*pubkey_ptr = pubkey;

	return DNSSEC_EOK;
}

static bool valid_algorithm(dnssec_key_t *key, gnutls_privkey_t privkey)
{
	uint8_t current_algorithm = 0;
	dnssec_key_get_algorithm(key, &current_algorithm);
	int gnu_algorithm = gnutls_privkey_get_pk_algorithm(privkey, NULL);

	return (gnu_algorithm == algorithm_to_gnutls(current_algorithm));
}

int key_set_private_key(dnssec_key_t *key, gnutls_privkey_t privkey)
{
	assert(key);
	assert(privkey);
	assert(key->private_key == NULL);

	if (!valid_algorithm(key, privkey)) {
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	if (!key->public_key) {
		int r = create_public_key(privkey, &key->public_key, &key->rdata);
		if (r != DNSSEC_EOK) {
			return r;
		}

		key_update_identifiers(key);
	}

	key->private_key = privkey;

	return DNSSEC_EOK;
}

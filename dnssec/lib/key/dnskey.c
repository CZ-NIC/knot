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

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "key/dnskey.h"
#include "key/internal.h"
#include "key/privkey.h"
#include "keystore/pem.h"
#include "shared.h"

/* -- internal functions --------------------------------------------------- */

/*!
 * Check if DNSKEY has and algorithm set.
 */
static bool has_algorithm(dnssec_key_t *key)
{
	assert(key);

	uint8_t algorithm = dnssec_key_get_algorithm(key);
	return algorithm != 0;
}

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_key_load_pkcs8(dnssec_key_t *key, const dnssec_binary_t *pem)
{
	if (!key || !pem || !pem->data) {
		return DNSSEC_EINVAL;
	}

	if (!key->public_key && !has_algorithm(key)) {
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	gnutls_privkey_t privkey = NULL;
	_cleanup_free_ char *id = NULL;
	int r = pem_to_privkey(pem, &privkey, &id);
	if (r != DNSSEC_EOK) {
		return r;
	}

	if (key->public_key && !dnssec_keyid_equal(key->id, id)) {
		gnutls_privkey_deinit(privkey);
		return DNSSEC_INVALID_KEY_ID;
	}

	r = key_set_private_key(key, privkey);
	if (r != DNSSEC_EOK) {
		gnutls_privkey_deinit(privkey);
		return r;
	}

	return DNSSEC_EOK;
}

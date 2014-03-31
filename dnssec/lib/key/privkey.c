#include <assert.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "key/privkey.h"
#include "shared.h"

int pubkey_from_privkey(gnutls_privkey_t privkey, gnutls_pubkey_t *pubkey)
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

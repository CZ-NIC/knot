#include <assert.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "key/privkey.h"
#include "shared.h"

int privkey_from_pem(const dnssec_binary_t *data, gnutls_privkey_t *key,
		     dnssec_key_id_t key_id)
{
	assert(data);
	assert(key);

	gnutls_datum_t pem;
	binary_to_datum(data, &pem);

	// create X.509 private key

	gnutls_x509_privkey_t key_x509 = NULL;
	int result = gnutls_x509_privkey_init(&key_x509);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	int format = GNUTLS_X509_FMT_PEM;
	result = gnutls_x509_privkey_import_pkcs8(key_x509, &pem, format, NULL, 0);
	if (result != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(key_x509);
		return DNSSEC_PKCS8_IMPORT_ERROR;
	}

	// convert to abstract private key

	gnutls_privkey_t key_abs = NULL;
	result = gnutls_privkey_init(&key_abs);
	if (result != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(key_x509);
		return DNSSEC_ENOMEM;
	}

	int flags = GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE;
	result = gnutls_privkey_import_x509(key_abs, key_x509, flags);
	if (result != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(key_x509);
		gnutls_privkey_deinit(key_abs);
		return DNSSEC_ENOMEM;
	}

	// extract keytag

	dnssec_key_id_t id = { 0 };
	size_t id_size = DNSSEC_KEY_ID_SIZE;
	gnutls_x509_privkey_get_key_id(key_x509, 0, id, &id_size);
	assert(id_size == DNSSEC_KEY_ID_SIZE);

	*key = key_abs;
	dnssec_key_id_copy(id, key_id);

	return DNSSEC_EOK;
}

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

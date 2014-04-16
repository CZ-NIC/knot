#include <assert.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <stdio.h>

#include "dnssec/binary.h"
#include "dnssec/error.h"
#include "legacy/legacy.h"
#include "legacy/privkey.h"
#include "legacy/pubkey.h"
#include "pem.h"
#include "shared.h"

static gnutls_datum_t binary2datum(const dnssec_binary_t *from)
{
	gnutls_datum_t to = { .size = from->size, .data = from->data };
	return to;
}

static int rsa_params_to_pem(const legacy_privkey_t *params)
{
	_cleanup_x509_privkey_ gnutls_x509_privkey_t key = NULL;
	int result = gnutls_x509_privkey_init(&key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	gnutls_datum_t m = binary2datum(&params->modulus);
	gnutls_datum_t e = binary2datum(&params->public_exponent);
	gnutls_datum_t d = binary2datum(&params->private_exponent);
	gnutls_datum_t p = binary2datum(&params->prime_one);
	gnutls_datum_t q = binary2datum(&params->prime_two);
	gnutls_datum_t u = binary2datum(&params->coefficient);

	result = gnutls_x509_privkey_import_rsa_raw(key, &m, &e, &d, &p, &q, &u);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	dnssec_binary_t pem = { 0 };
	result = pem_gnutls_x509_export(key, &pem);
	if (result != DNSSEC_EOK) {
		return result;
	}

	fwrite(pem.data, pem.size, 1, stdout);
	printf("\n");

	dnssec_binary_free(&pem);

	//result = gnutls_x509_privkey_export_pkcs8(key, pem, NULL, pain
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

/* -- */

static void get_key_names(const char *input, char **public_ptr, char **private_ptr)
{
	assert(input);
	assert(public_ptr);
	assert(private_ptr);

	asprintf(public_ptr, "%s.key", input);
	asprintf(private_ptr, "%s.private", input);
}

int legacy_key_import(const char *filename)
{
	if (!filename) {
		return DNSSEC_EINVAL;
	}

	_cleanup_free_ char *filename_pubkey = NULL;
	_cleanup_free_ char *filename_private = NULL;
	get_key_names(filename, &filename_pubkey, &filename_private);
	if (!filename_pubkey || !filename_private) {
		return DNSSEC_EINVAL;
	}

	dnssec_key_t *key = legacy_pubkey_parse(filename_pubkey);
	if (!key) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	legacy_privkey_t params = { 0 };
	int r = legacy_privkey_parse(filename_private, &params);
	if (r != DNSSEC_EOK) {
		return r;
	}

	printf("public key %s (%d)\n", dnssec_key_get_id(key), dnssec_key_get_keytag(key));
	printf("conversion happens here\n");

	rsa_params_to_pem(&params);

	legacy_privkey_free(&params);

	return DNSSEC_EOK;
}

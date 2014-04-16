#pragma once

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "dnssec/binary.h"
#include "dnssec/error.h"
#include "shared.h"

/** -- **/

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

static gnutls_datum_t binary2datum(const dnssec_binary_t *from)
{
	gnutls_datum_t to = { .size = from->size, .data = from->data };
	return to;
}

static int rsa_params_to_pem(const key_params_t *params)
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

	//result = gnutls_x509_privkey_export_pkcs8(key, pem, NULL, pain

	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int params_to_pem(const key_params_t *params, dnssec_binary_t *pem)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

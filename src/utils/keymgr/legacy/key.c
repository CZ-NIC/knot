/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <stdio.h>
#include <string.h>

#include "dnssec/binary.h"
#include "dnssec/error.h"
#include "dnssec/kasp.h"
#include "shared/pem.h"
#include "shared/shared.h"
#include "utils/keymgr/legacy/key.h"
#include "utils/keymgr/legacy/privkey.h"
#include "utils/keymgr/legacy/pubkey.h"

static int rsa_params_to_pem(const legacy_privkey_t *params, dnssec_binary_t *pem)
{
	_cleanup_x509_privkey_ gnutls_x509_privkey_t key = NULL;
	int result = gnutls_x509_privkey_init(&key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	gnutls_datum_t m = binary_to_datum(&params->modulus);
	gnutls_datum_t e = binary_to_datum(&params->public_exponent);
	gnutls_datum_t d = binary_to_datum(&params->private_exponent);
	gnutls_datum_t p = binary_to_datum(&params->prime_one);
	gnutls_datum_t q = binary_to_datum(&params->prime_two);
	gnutls_datum_t u = binary_to_datum(&params->coefficient);

	result = gnutls_x509_privkey_import_rsa_raw(key, &m, &e, &d, &p, &q, &u);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	return pem_from_x509(key, pem);
}

static int dsa_params_to_pem(const legacy_privkey_t *params, dnssec_binary_t *pem)
{
	_cleanup_x509_privkey_ gnutls_x509_privkey_t key = NULL;
	int result = gnutls_x509_privkey_init(&key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	gnutls_datum_t p = binary_to_datum(&params->prime);
	gnutls_datum_t q = binary_to_datum(&params->subprime);
	gnutls_datum_t g = binary_to_datum(&params->base);
	gnutls_datum_t x = binary_to_datum(&params->private_value);
	gnutls_datum_t y = binary_to_datum(&params->public_value);

	result = gnutls_x509_privkey_import_dsa_raw(key, &p, &q, &g, &y, &x);
	if (result != DNSSEC_EOK) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	return pem_from_x509(key, pem);
}

/*!
 * \see lib/key/convert.h
 */
static gnutls_ecc_curve_t choose_ecdsa_curve(size_t pubkey_size)
{
	switch (pubkey_size) {
	case 64: return GNUTLS_ECC_CURVE_SECP256R1;
	case 96: return GNUTLS_ECC_CURVE_SECP384R1;
	default: return GNUTLS_ECC_CURVE_INVALID;
	}
}

static void ecdsa_extract_public_params(dnssec_key_t *key, gnutls_ecc_curve_t *curve,
					gnutls_datum_t *x, gnutls_datum_t *y)
{
	dnssec_binary_t pubkey = { 0 };
	dnssec_key_get_pubkey(key, &pubkey);

	*curve = choose_ecdsa_curve(pubkey.size);

	size_t param_size = pubkey.size / 2;
	x->data = pubkey.data;
	x->size = param_size;
	y->data = pubkey.data + param_size;
	y->size = param_size;
}

static int ecdsa_params_to_pem(dnssec_key_t *dnskey, const legacy_privkey_t *params,
			       dnssec_binary_t *pem)
{
	_cleanup_x509_privkey_ gnutls_x509_privkey_t key = NULL;
	int result = gnutls_x509_privkey_init(&key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	gnutls_ecc_curve_t curve = 0;
	gnutls_datum_t x = { 0 };
	gnutls_datum_t y = { 0 };
	ecdsa_extract_public_params(dnskey, &curve, &x, &y);

	gnutls_datum_t k = binary_to_datum(&params->private_key);

	result = gnutls_x509_privkey_import_ecc_raw(key, curve, &x, &y, &k);
	if (result != DNSSEC_EOK) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	gnutls_x509_privkey_fix(key);

	return pem_from_x509(key, pem);
}

static int params_to_pem(dnssec_key_t *key, legacy_privkey_t *params, dnssec_binary_t *pem)
{
	dnssec_key_algorithm_t algorithm = dnssec_key_get_algorithm(key);
	switch (algorithm) {
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3:
		return dsa_params_to_pem(params, pem);
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA256:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA512:
		return rsa_params_to_pem(params, pem);
	case DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256:
	case DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384:
		return ecdsa_params_to_pem(key, params, pem);
	default:
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}
}

static void params_to_timing(legacy_privkey_t *params, dnssec_kasp_key_timing_t *timing)
{
	// unsupported: time_created, time_revoke

	timing->publish = params->time_publish;
	timing->active  = params->time_activate;
	timing->retire  = params->time_inactive;
	timing->remove  = params->time_delete;
}

/*!
 * \brief Extract private and public key file names from input filename.
 *
 * If the input file name has an empty extension (ends with a dot),
 * extension 'private', or extension 'key', the appropriate filenames are
 * derived from the previous part of the string. Otherwise, just append the
 * extensions.
 */
static int get_key_names(const char *input, char **public_ptr, char **private_ptr)
{
	assert(input);
	assert(public_ptr);
	assert(private_ptr);

	char *name_end = strrchr(input, '.');
	int base_length;

	if (name_end && (*(name_end + 1) == '\0' ||
			 streq(name_end, ".key") ||
			 streq(name_end, ".private"))
	) {
		base_length = name_end - input;
	} else {
		base_length = strlen(input);
	}

	char *pub = NULL;
	if (asprintf(&pub, "%.*s.key", base_length, input) < 0) {
		return DNSSEC_ENOMEM;
	}

	char *priv = NULL;
	if (asprintf(&priv, "%.*s.private", base_length, input) < 0) {
		free(pub);
		return DNSSEC_ENOMEM;
	}

	*public_ptr = pub;
	*private_ptr = priv;

	return DNSSEC_EOK;
}

/*!
 * Parse legacy key files and get public key, private key, and key timing.
 */
int legacy_key_parse(const char *filename, dnssec_key_t **key_ptr,
		     dnssec_binary_t *pem_ptr, dnssec_kasp_key_timing_t *timing)
{
	if (!filename || !key_ptr || !pem_ptr || !timing) {
		return DNSSEC_EINVAL;
	}

	_cleanup_free_ char *filename_public = NULL;
	_cleanup_free_ char *filename_private = NULL;
	int result = get_key_names(filename, &filename_public, &filename_private);
	if (result != DNSSEC_EOK) {
		return result;
	}

	dnssec_key_t *key = NULL;
	result = legacy_pubkey_parse(filename_public, &key);
	if (result != DNSSEC_EOK) {
		return result;
	}

	legacy_privkey_t params = { 0 };
	result = legacy_privkey_parse(filename_private, &params);
	if (result != DNSSEC_EOK) {
		dnssec_key_free(key);
		return result;
	}

	dnssec_binary_t pem = { 0 };
	result = params_to_pem(key, &params, &pem);
	if (result != DNSSEC_EOK) {
		legacy_privkey_free(&params);
		return result;
	}

	*key_ptr = key;
	*pem_ptr = pem;
	params_to_timing(&params, timing);

	legacy_privkey_free(&params);

	return DNSSEC_EOK;
}

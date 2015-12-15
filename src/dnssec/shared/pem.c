/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <gnutls/x509.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "keyid.h"
#include "keyid_gnutls.h"
#include "pem.h"
#include "shared.h"

/* -- internal API --------------------------------------------------------- */

/*!
 * Create GnuTLS X.509 private key from unencrypted PEM data.
 */
int pem_x509(const dnssec_binary_t *data, gnutls_x509_privkey_t *key_ptr)
{
	assert(data);
	assert(key_ptr);

	gnutls_datum_t pem = binary_to_datum(data);

	gnutls_x509_privkey_t key = NULL;
	int r = gnutls_x509_privkey_init(&key);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	int format = GNUTLS_X509_FMT_PEM;
	char *password = NULL;
	int flags = GNUTLS_PKCS_PLAIN;
	r = gnutls_x509_privkey_import_pkcs8(key, &pem, format, password, flags);
	if (r != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(key);
		return DNSSEC_PKCS8_IMPORT_ERROR;
	}

	*key_ptr = key;

	return DNSSEC_EOK;
}

/*!
 * Create GnuTLS private key from unencrypted PEM data.
 */
int pem_privkey(const dnssec_binary_t *data, gnutls_privkey_t *key)
{
	assert(data);
	assert(key);

	gnutls_x509_privkey_t key_x509 = NULL;
	int r = pem_x509(data, &key_x509);
	if (r != DNSSEC_EOK) {
		return r;
	}

	gnutls_privkey_t key_abs = NULL;
	r = gnutls_privkey_init(&key_abs);
	if (r != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(key_x509);
		return DNSSEC_ENOMEM;
	}

	int flags = GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE;
	r = gnutls_privkey_import_x509(key_abs, key_x509, flags);
	if (r != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(key_x509);
		gnutls_privkey_deinit(key_abs);
		return DNSSEC_ENOMEM;
	}

	*key = key_abs;

	return DNSSEC_EOK;
}

/*!
 * Generate new key and export it in the PEM format.
 */
int pem_generate(gnutls_pk_algorithm_t algorithm, unsigned bits,
		 dnssec_binary_t *pem_ptr, char **id_ptr)
{
	assert(pem_ptr);
	assert(id_ptr);

	// generate key

	_cleanup_x509_privkey_ gnutls_x509_privkey_t key = NULL;
	int r = gnutls_x509_privkey_init(&key);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	r = gnutls_x509_privkey_generate(key, algorithm, bits, 0);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_GENERATE_ERROR;
	}

	// convert to PEM and export the ID

	dnssec_binary_t pem = { 0 };
	r = pem_from_x509(key, &pem);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// export key ID

	char *id = NULL;
	r = keyid_x509_hex(key, &id);
	if (r != DNSSEC_EOK) {
		dnssec_binary_free(&pem);
		return r;
	}

	*id_ptr = id;
	*pem_ptr = pem;

	return DNSSEC_EOK;
}

static int try_export_pem(gnutls_x509_privkey_t key, dnssec_binary_t *pem)
{
	assert(key);

	gnutls_x509_crt_fmt_t format = GNUTLS_X509_FMT_PEM;
	char *password = NULL;
	int flags = GNUTLS_PKCS_PLAIN;

	return gnutls_x509_privkey_export_pkcs8(key, format, password, flags,
						pem->data, &pem->size);
}

/*!
 * Export GnuTLS X.509 private key to PEM binary.
 */
int pem_from_x509(gnutls_x509_privkey_t key, dnssec_binary_t *pem_ptr)
{
	assert(key);
	assert(pem_ptr);

	dnssec_binary_t pem = { 0 };
	int r = try_export_pem(key, &pem);
	if (r != GNUTLS_E_SHORT_MEMORY_BUFFER || pem.size == 0) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	r = dnssec_binary_alloc(&pem, pem.size);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = try_export_pem(key, &pem);
	if (r != GNUTLS_E_SUCCESS) {
		dnssec_binary_free(&pem);
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	*pem_ptr = pem;

	return DNSSEC_EOK;
}

/*!
 * Get key ID of a private key in PEM format.
 */
int pem_keyid(const dnssec_binary_t *pem, char **keyid)
{
	assert(pem && pem->size > 0 && pem->data);
	assert(keyid);

	_cleanup_x509_privkey_ gnutls_x509_privkey_t key = NULL;
	int r = pem_x509(pem, &key);
	if (r != DNSSEC_EOK) {
		return r;
	}

	return keyid_x509_hex(key, keyid);
}

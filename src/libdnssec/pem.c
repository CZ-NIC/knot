/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "libdnssec/binary.h"
#include "libdnssec/error.h"
#include "libdnssec/key.h"
#include "libdnssec/pem.h"
#include "libdnssec/shared/shared.h"

_public_
int dnssec_pem_to_x509(const dnssec_binary_t *pem, gnutls_x509_privkey_t *key)
{
	if (!pem || !key) {
		return DNSSEC_EINVAL;
	}

	gnutls_datum_t data = binary_to_datum(pem);

	gnutls_x509_privkey_t _key = NULL;
	int r = gnutls_x509_privkey_init(&_key);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	int format = GNUTLS_X509_FMT_PEM;
	char *password = NULL;
	int flags = GNUTLS_PKCS_PLAIN;
	r = gnutls_x509_privkey_import_pkcs8(_key, &data, format, password, flags);
	if (r != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(_key);
		return DNSSEC_PKCS8_IMPORT_ERROR;
	}

	*key = _key;

	return DNSSEC_EOK;
}

_public_
int dnssec_pem_to_privkey(const dnssec_binary_t *pem, gnutls_privkey_t *key)
{
	if (!pem || !key) {
		return DNSSEC_EINVAL;
	}

	gnutls_x509_privkey_t key_x509 = NULL;
	int r = dnssec_pem_to_x509(pem, &key_x509);
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

static int try_export_pem(gnutls_x509_privkey_t key, dnssec_binary_t *pem)
{
	assert(key);

	gnutls_x509_crt_fmt_t format = GNUTLS_X509_FMT_PEM;
	char *password = NULL;
	int flags = GNUTLS_PKCS_PLAIN;

	return gnutls_x509_privkey_export_pkcs8(key, format, password, flags,
						pem->data, &pem->size);
}

_public_
int dnssec_pem_from_x509(gnutls_x509_privkey_t key, dnssec_binary_t *pem)
{
	if (!key || !pem) {
		return DNSSEC_EINVAL;
	}

	dnssec_binary_t _pem = { 0 };
	int r = try_export_pem(key, &_pem);
	if (r != GNUTLS_E_SHORT_MEMORY_BUFFER || _pem.size == 0) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	r = dnssec_binary_alloc(&_pem, _pem.size);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = try_export_pem(key, &_pem);
	if (r != GNUTLS_E_SUCCESS) {
		dnssec_binary_free(&_pem);
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	*pem = _pem;

	return DNSSEC_EOK;
}

static int privkey_export_x509(gnutls_privkey_t key, gnutls_x509_privkey_t *_key)
{
	if (gnutls_privkey_export_x509(key, _key) != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	return DNSSEC_EOK;
}

_public_
int dnssec_pem_from_privkey(gnutls_privkey_t key, dnssec_binary_t *pem)
{
	if (!key || !pem) {
		return DNSSEC_EINVAL;
	}

	_cleanup_x509_privkey_ gnutls_x509_privkey_t _key = NULL;

	int r = privkey_export_x509(key, &_key);
	if (r != DNSSEC_EOK) {
		return r;
	}

	dnssec_binary_t _pem = { 0 };
	r = dnssec_pem_from_x509(_key, &_pem);
	if (r != DNSSEC_EOK) {
		return r;
	}

	*pem = _pem;

	return DNSSEC_EOK;
}

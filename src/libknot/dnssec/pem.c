/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "libknot/dnssec/binary.h"
#include "libknot/errcode.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/pem.h"
#include "libknot/dnssec/shared/shared.h"

_public_
int dnssec_pem_to_x509(const dnssec_binary_t *pem, gnutls_x509_privkey_t *key)
{
	if (!pem || !key) {
		return KNOT_EINVAL;
	}

	gnutls_datum_t data = binary_to_datum(pem);

	gnutls_x509_privkey_t _key = NULL;
	int r = gnutls_x509_privkey_init(&_key);
	if (r != GNUTLS_E_SUCCESS) {
		return KNOT_ENOMEM;
	}

	int format = GNUTLS_X509_FMT_PEM;
	char *password = NULL;
	int flags = GNUTLS_PKCS_PLAIN;
	r = gnutls_x509_privkey_import_pkcs8(_key, &data, format, password, flags);
	if (r != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(_key);
		return KNOT_KEY_EIMPORT;
	}

	*key = _key;

	return KNOT_EOK;
}

_public_
int dnssec_pem_to_privkey(const dnssec_binary_t *pem, gnutls_privkey_t *key)
{
	if (!pem || !key) {
		return KNOT_EINVAL;
	}

	gnutls_x509_privkey_t key_x509 = NULL;
	int r = dnssec_pem_to_x509(pem, &key_x509);
	if (r != KNOT_EOK) {
		return r;
	}

	gnutls_privkey_t key_abs = NULL;
	r = gnutls_privkey_init(&key_abs);
	if (r != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(key_x509);
		return KNOT_ENOMEM;
	}

	int flags = GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE;
	r = gnutls_privkey_import_x509(key_abs, key_x509, flags);
	if (r != GNUTLS_E_SUCCESS) {
		gnutls_x509_privkey_deinit(key_x509);
		gnutls_privkey_deinit(key_abs);
		return KNOT_ENOMEM;
	}

	*key = key_abs;

	return KNOT_EOK;
}

_public_
int dnssec_pem_from_x509(gnutls_x509_privkey_t key, dnssec_binary_t *pem)
{
	if (!key || !pem) {
		return KNOT_EINVAL;
	}

	gnutls_x509_crt_fmt_t format = GNUTLS_X509_FMT_PEM;
	char *password = NULL;
	int flags = GNUTLS_PKCS_PLAIN;

	gnutls_datum_t _pem = { 0 };
	int r = gnutls_x509_privkey_export2_pkcs8(key, format, password, flags, &_pem);
	if (r != GNUTLS_E_SUCCESS) {
		return KNOT_KEY_EEXPORT;
	}

	*pem = binary_from_datum(&_pem);

	return KNOT_EOK;
}

static int privkey_export_x509(gnutls_privkey_t key, gnutls_x509_privkey_t *_key)
{
	if (gnutls_privkey_export_x509(key, _key) != GNUTLS_E_SUCCESS) {
		return KNOT_KEY_EEXPORT;
	}

	return KNOT_EOK;
}

_public_
int dnssec_pem_from_privkey(gnutls_privkey_t key, dnssec_binary_t *pem)
{
	if (!key || !pem) {
		return KNOT_EINVAL;
	}

	_cleanup_x509_privkey_ gnutls_x509_privkey_t _key = NULL;

	int r = privkey_export_x509(key, &_key);
	if (r != KNOT_EOK) {
		return r;
	}

	dnssec_binary_t _pem = { 0 };
	r = dnssec_pem_from_x509(_key, &_pem);
	if (r != KNOT_EOK) {
		return r;
	}

	*pem = _pem;

	return KNOT_EOK;
}

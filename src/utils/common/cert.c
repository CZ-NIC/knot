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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include "utils/common/cert.h"
#include "libknot/error.h"

static int spki_hash(gnutls_x509_crt_t cert, gnutls_digest_algorithm_t alg,
                     uint8_t *hash, size_t size)
{
	if (!cert || !hash || gnutls_hash_get_len(alg) != size) {
		return KNOT_EINVAL;
	}

	gnutls_pubkey_t key = { 0 };
	if (gnutls_pubkey_init(&key) != GNUTLS_E_SUCCESS) {
		return KNOT_ENOMEM;
	}

	if (gnutls_pubkey_import_x509(key, cert, 0) != GNUTLS_E_SUCCESS) {
		gnutls_pubkey_deinit(key);
		return KNOT_ERROR;
	}

	gnutls_datum_t der = { 0 };
	if (gnutls_pubkey_export2(key, GNUTLS_X509_FMT_DER, &der) != GNUTLS_E_SUCCESS) {
		gnutls_pubkey_deinit(key);
		return KNOT_ERROR;
	}

	int ret = gnutls_hash_fast(alg, der.data, der.size, hash);

	gnutls_free(der.data);
	gnutls_pubkey_deinit(key);

	if (ret != GNUTLS_E_SUCCESS) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int cert_get_pin(gnutls_x509_crt_t cert, uint8_t *pin, size_t size)
{
	return spki_hash(cert, GNUTLS_DIG_SHA256, pin, size);
}

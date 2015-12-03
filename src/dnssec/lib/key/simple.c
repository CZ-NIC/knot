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

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "key/dnskey.h"
#include "key/internal.h"
#include "key/privkey.h"
#include "pem.h"
#include "shared.h"

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_key_load_pkcs8(dnssec_key_t *key, const dnssec_binary_t *pem)
{
	if (!key || !pem || !pem->data) {
		return DNSSEC_EINVAL;
	}

	if (dnssec_key_get_algorithm(key) == 0) {
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	gnutls_privkey_t privkey = NULL;
	int r = pem_privkey(pem, &privkey);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = key_set_private_key(key, privkey);
	if (r != DNSSEC_EOK) {
		gnutls_privkey_deinit(privkey);
		return r;
	}

	return DNSSEC_EOK;
}

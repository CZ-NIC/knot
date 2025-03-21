/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

#include "libdnssec/binary.h"
#include "libdnssec/error.h"
#include "libdnssec/key.h"
#include "libdnssec/key/dnskey.h"
#include "libdnssec/key/internal.h"
#include "libdnssec/key/privkey.h"
#include "libdnssec/pem.h"
#include "libdnssec/shared/shared.h"

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
	int r = dnssec_pem_to_privkey(pem, &privkey);
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

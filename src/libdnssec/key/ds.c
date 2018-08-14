/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libdnssec/binary.h"
#include "libdnssec/error.h"
#include "libdnssec/key.h"
#include "libdnssec/key/internal.h"
#include "libdnssec/shared/dname.h"
#include "libdnssec/shared/shared.h"
#include "libdnssec/shared/binary_wire.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

/*!
 * Convert DNSSEC DS digest algorithm to GnuTLS digest algorithm.
 */
static gnutls_digest_algorithm_t lookup_algorithm(dnssec_key_digest_t algorithm)
{
	switch (algorithm) {
	case DNSSEC_KEY_DIGEST_SHA1:   return GNUTLS_DIG_SHA1;
	case DNSSEC_KEY_DIGEST_SHA256: return GNUTLS_DIG_SHA256;
	case DNSSEC_KEY_DIGEST_SHA384: return GNUTLS_DIG_SHA384;
#ifdef HAVE_GOST
	case DNSSEC_DIGEST_GOSTR_94:   return GNUTLS_DIG_GOSTR_94;
#endif
	default:
		return GNUTLS_DIG_UNKNOWN;
	};
}

_public_
bool dnssec_algorithm_digest_support(dnssec_key_digest_t algo)
{
	return lookup_algorithm(algo) != GNUTLS_DIG_UNKNOWN;
}

static void wire_write_digest(wire_ctx_t *wire,
			      gnutls_hash_hd_t digest, int digest_size)
{
	assert(wire_ctx_available(wire) >= digest_size);
	gnutls_hash_output(digest, wire->position);
	wire->position += digest_size;
}

_public_
int dnssec_key_create_ds(const dnssec_key_t *key,
			 dnssec_key_digest_t ds_algorithm,
			 dnssec_binary_t *rdata_ptr)
{
	if (!key || !rdata_ptr) {
		return DNSSEC_EINVAL;
	}

	if (!key->dname) {
		return DNSSEC_INVALID_KEY_NAME;
	}

	if (!key->public_key){
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	gnutls_digest_algorithm_t algorithm = lookup_algorithm(ds_algorithm);
	if (algorithm == GNUTLS_DIG_UNKNOWN) {
		return DNSSEC_INVALID_DS_ALGORITHM;
	}

	// compute DS hash

	_cleanup_hash_ gnutls_hash_hd_t digest = NULL;
	int r = gnutls_hash_init(&digest, algorithm);
	if (r < 0) {
		return DNSSEC_DS_HASHING_ERROR;
	}

	if (gnutls_hash(digest, key->dname, dname_length(key->dname)) != 0 ||
	    gnutls_hash(digest, key->rdata.data, key->rdata.size) != 0
	) {
		return DNSSEC_DS_HASHING_ERROR;
	}

	// build DS RDATA

	int digest_size = gnutls_hash_get_len(algorithm);
	if (digest_size == 0) {
		return DNSSEC_DS_HASHING_ERROR;
	}

	dnssec_binary_t rdata = { 0 };
	r = dnssec_binary_alloc(&rdata, 4 + digest_size);
	if (r != DNSSEC_EOK) {
		return r;
	}

	wire_ctx_t wire = binary_init(&rdata);
	wire_ctx_write_u16(&wire, dnssec_key_get_keytag(key));
	wire_ctx_write_u8(&wire, dnssec_key_get_algorithm(key));
	wire_ctx_write_u8(&wire, ds_algorithm);
	wire_write_digest(&wire, digest, digest_size);
	assert(wire_ctx_offset(&wire) == wire.size);

	*rdata_ptr = rdata;

	return DNSSEC_EOK;
}

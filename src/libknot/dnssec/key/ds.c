/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "libknot/dname.h"
#include "libknot/dnssec/binary.h"
#include "libknot/errcode.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/key/internal.h"
#include "libknot/dnssec/shared/shared.h"
#include "libknot/dnssec/shared/binary_wire.h"

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
	default:
		return GNUTLS_DIG_UNKNOWN;
	};
}

_public_
bool dnssec_algorithm_digest_support(dnssec_key_digest_t algorithm)
{
	/* GnuTLS docs:
	 * > It is not possible to query for insecure hash algorithms directly
	 * > (only indirectly through the signature API).
	 * So let's query combining the hash with RSA.
	 */
	gnutls_sign_algorithm_t rsa;
	switch (algorithm) {
	case DNSSEC_KEY_DIGEST_SHA1:   rsa = GNUTLS_SIGN_RSA_SHA1;   break;
	case DNSSEC_KEY_DIGEST_SHA256: rsa = GNUTLS_SIGN_RSA_SHA256; break;
	case DNSSEC_KEY_DIGEST_SHA384: rsa = GNUTLS_SIGN_RSA_SHA384; break;
	default:
		return false;
	};
	return gnutls_sign_is_secure(rsa);
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
		return KNOT_EINVAL;
	}

	if (!key->dname) {
		return KNOT_INVALID_KEY_NAME;
	}

	if (!key->public_key){
		return KNOT_INVALID_PUBLIC_KEY;
	}

	gnutls_digest_algorithm_t algorithm = lookup_algorithm(ds_algorithm);
	if (algorithm == GNUTLS_DIG_UNKNOWN) {
		return KNOT_EALGORITHM;
	}

	// compute DS hash

	_cleanup_hash_ gnutls_hash_hd_t digest = NULL;
	int r = gnutls_hash_init(&digest, algorithm);
	if (r < 0) {
		return KNOT_ECRYPTO;
	}

	if (gnutls_hash(digest, key->dname, knot_dname_size(key->dname)) != 0 ||
	    gnutls_hash(digest, key->rdata.data, key->rdata.size) != 0
	) {
		return KNOT_ECRYPTO;
	}

	// build DS RDATA

	int digest_size = gnutls_hash_get_len(algorithm);
	if (digest_size == 0) {
		return KNOT_ECRYPTO;
	}

	dnssec_binary_t rdata = { 0 };
	r = dnssec_binary_alloc(&rdata, 4 + digest_size);
	if (r != KNOT_EOK) {
		return r;
	}

	wire_ctx_t wire = binary_init(&rdata);
	wire_ctx_write_u16(&wire, dnssec_key_get_keytag(key));
	wire_ctx_write_u8(&wire, dnssec_key_get_algorithm(key));
	wire_ctx_write_u8(&wire, ds_algorithm);
	wire_write_digest(&wire, digest, digest_size);
	assert(wire_ctx_offset(&wire) == wire.size);

	*rdata_ptr = rdata;

	return KNOT_EOK;
}

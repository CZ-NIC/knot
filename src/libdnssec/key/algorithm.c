/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <gnutls/gnutls.h>

#include "libdnssec/error.h"
#include "libdnssec/key.h"
#include "libdnssec/key/algorithm.h"
#include "libdnssec/shared/shared.h"

/* -- internal ------------------------------------------------------------- */

struct limits {
	unsigned min;
	unsigned max;
	unsigned def;
	bool (*validate)(unsigned bits);
};

static const struct limits *get_limits(dnssec_key_algorithm_t algorithm)
{
	static const struct limits RSA = {
		.min = 1024,
		.max = 4096,
		.def = 2048,
	};

	static const struct limits EC256 = {
		.min = 256,
		.max = 256,
		.def = 256,
	};

	static const struct limits EC384 = {
		.min = 384,
		.max = 384,
		.def = 384,
	};

	static const struct limits ED25519 = {
		.min = 256,
		.max = 256,
		.def = 256,
	};

	static const struct limits ED448 = {
		.min = 456,
		.max = 456,
		.def = 456,
	};

	switch (algorithm) {
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA256:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA512:
		return &RSA;
	case DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256:
		return &EC256;
	case DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384:
		return &EC384;
	case DNSSEC_KEY_ALGORITHM_ED25519:
		return &ED25519;
	case DNSSEC_KEY_ALGORITHM_ED448:
		return &ED448;
	default:
		return NULL;
	}
}

/* -- internal API --------------------------------------------------------- */

gnutls_pk_algorithm_t algorithm_to_gnutls(dnssec_key_algorithm_t dnssec)
{
	switch (dnssec) {
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA256:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA512:
		return GNUTLS_PK_RSA;
	case DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256:
	case DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384:
		return GNUTLS_PK_EC;
#ifdef HAVE_ED25519
	case DNSSEC_KEY_ALGORITHM_ED25519:
		return GNUTLS_PK_EDDSA_ED25519;
#endif
#ifdef HAVE_ED448
	case DNSSEC_KEY_ALGORITHM_ED448:
		return GNUTLS_PK_EDDSA_ED448;
#endif
	default:
		return GNUTLS_PK_UNKNOWN;
	}
}

/* -- public API ----------------------------------------------------------- */

_public_
bool dnssec_algorithm_reproducible(dnssec_key_algorithm_t algorithm, bool enabled)
{
	(void)enabled;
	switch (algorithm) {
	case DNSSEC_KEY_ALGORITHM_ED25519:
	case DNSSEC_KEY_ALGORITHM_ED448:
		return true; // those are always reproducible
	case DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256:
	case DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384:
#ifdef HAVE_GNUTLS_REPRODUCIBLE
		return enabled; // Reproducible only if GnuTLS supports && enabled
#else
		return false;
#endif
	default:
		return false;
	}
}

_public_
int dnssec_algorithm_key_size_range(dnssec_key_algorithm_t algorithm,
				    unsigned *min_ptr, unsigned *max_ptr)
{
	if (!min_ptr && !max_ptr) {
		return DNSSEC_EINVAL;
	}

	const struct limits *limits = get_limits(algorithm);
	if (!limits) {
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	if (min_ptr) {
		*min_ptr = limits->min;
	}
	if (max_ptr) {
		*max_ptr = limits->max;
	}

	return DNSSEC_EOK;
}

_public_
bool dnssec_algorithm_key_size_check(dnssec_key_algorithm_t algorithm,
				     unsigned bits)
{
	const struct limits *limits = get_limits(algorithm);
	if (!limits) {
		return false;
	}

	if (bits < limits->min || bits > limits->max) {
		return false;
	}

	if (limits->validate && !limits->validate(bits)) {
		return false;
	}

	return true;
}

_public_
int dnssec_algorithm_key_size_default(dnssec_key_algorithm_t algorithm)
{
	const struct limits *limits = get_limits(algorithm);
	return limits ? limits->def : 0;
}

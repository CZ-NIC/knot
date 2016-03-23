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

#include <gnutls/gnutls.h>

#include "error.h"
#include "key.h"
#include "key/algorithm.h"
#include "shared.h"

/* -- internal ------------------------------------------------------------- */

static bool is_dsa(dnssec_key_algorithm_t algorithm)
{
	switch (algorithm) {
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3:
		return true;
	default:
		return false;
	}
}

/* -- internal API --------------------------------------------------------- */

gnutls_pk_algorithm_t algorithm_to_gnutls(dnssec_key_algorithm_t dnssec)
{
	switch (dnssec) {
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3:
		return GNUTLS_PK_DSA;
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA256:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA512:
		return GNUTLS_PK_RSA;
	case DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256:
	case DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384:
		return GNUTLS_PK_EC;
	default:
		return GNUTLS_PK_UNKNOWN;
	}
}

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_algorithm_key_size_range(dnssec_key_algorithm_t algorithm,
				    unsigned *min_ptr, unsigned *max_ptr)
{
	if (!min_ptr && !max_ptr) {
		return DNSSEC_EINVAL;
	}

	unsigned min = 0;
	unsigned max = 0;

	switch (algorithm) {
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3:
		min = 512; max = 1024; break;
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA256:
		min = 512; max = 4096; break;
	case DNSSEC_KEY_ALGORITHM_RSA_SHA512:
		min = 1024; max = 4096; break;
	case DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256:
		min = max = 256; break;
	case DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384:
		min = max = 384; break;
	default:
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	if (min_ptr) { *min_ptr = min; }
	if (max_ptr) { *max_ptr = max; }

	return DNSSEC_EOK;
}

_public_
bool dnssec_algorithm_key_size_check(dnssec_key_algorithm_t algorithm,
				     unsigned bits)
{
	unsigned min = 0;
	unsigned max = 0;

	int r = dnssec_algorithm_key_size_range(algorithm, &min, &max);
	if (r != DNSSEC_EOK) {
		return false;
	}

	if (bits < min || bits > max) {
		return false;
	}

	if (is_dsa(algorithm)) {
		return (bits % 64 == 0);
	}

	return true;
}

_public_
int dnssec_algorithm_key_size_default(dnssec_key_algorithm_t algorithm)
{
	switch (algorithm) {
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3:
		return 1024;
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA256:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA512:
		return 2048;
	case DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256:
		return 256;
	case DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384:
		return 384;
	default:
		return 0;
	}
}

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
#include <stdlib.h>

#include "shared.h"
#include "error.h"
#include "kasp.h"

#define HOURS(x) (x * 60 * 60)
#define DAYS(x) (x * HOURS(24))

/*!
 * Clear policy parameters, but keep references.
 */
static void clear_policy(dnssec_kasp_policy_t *policy)
{
	assert(policy);

	char *name = policy->name;
	char *keystore = policy->keystore;

	clear_struct(policy);

	policy->name = name;
	policy->keystore = keystore;
}

struct key_size {
	dnssec_key_algorithm_t algorithm;
	uint16_t zsk;
	uint16_t ksk;
};

static const struct key_size DEFAULT_KEY_SIZES[] = {
	// DSA: maximum supported by DNSSEC
	{ DNSSEC_KEY_ALGORITHM_DSA_SHA1,          1024, 1024 },
	{ DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3,    1024, 1024 },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3,    1024, 1024 },
	// RSA: small keys for short-lived keys (security/size compromise)
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA1,          1024, 2048 },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA256,        1024, 2048 },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA512,        1024, 2048 },
	// ECDSA: fixed key size
	{ DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256, 256,  256 },
	{ DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384, 384,  384 },
	{ 0 }
};

static void default_key_size(dnssec_key_algorithm_t algorithm,
			     uint16_t *zsk_size, uint16_t *ksk_size)
{
	for (const struct key_size *ks = DEFAULT_KEY_SIZES; ks->algorithm; ks++) {
		if (algorithm == ks->algorithm) {
			*zsk_size = ks->zsk;
			*ksk_size = ks->ksk;
			return;
		}
	}

	*zsk_size = 0;
	*ksk_size = 0;
}

/* -- public API ----------------------------------------------------------- */

_public_
dnssec_kasp_policy_t *dnssec_kasp_policy_new(const char *name)
{
	dnssec_kasp_policy_t *policy = malloc(sizeof(*policy));
	clear_struct(policy);

	if (name) {
		policy->name = strdup(name);
		if (!policy->name) {
			free(policy);
			return NULL;
		}
	}

	return policy;
}

_public_
void dnssec_kasp_policy_defaults(dnssec_kasp_policy_t *policy)
{
	if (!policy) {
		return;
	}

	// TODO: determine defaults for NSEC

	clear_policy(policy);

	policy->algorithm = DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256;
	default_key_size(policy->algorithm, &policy->zsk_size, &policy->ksk_size);
	policy->dnskey_ttl = 1200;

	policy->zsk_lifetime = DAYS(30);

	policy->rrsig_lifetime = DAYS(14);
	policy->rrsig_refresh_before = DAYS(7);

	policy->propagation_delay = HOURS(1);

	policy->nsec3_enabled = false;
}

_public_
void dnssec_kasp_policy_free(dnssec_kasp_policy_t *policy)
{
	if (!policy) {
		return;
	}

	free(policy->name);
	free(policy->keystore);
	free(policy);
}

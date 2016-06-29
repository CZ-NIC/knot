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
	policy->zsk_size = dnssec_algorithm_key_size_default(policy->algorithm);
	policy->ksk_size = dnssec_algorithm_key_size_default(policy->algorithm);
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

static bool valid_algorithm(const dnssec_kasp_policy_t *p)
{
	return dnssec_algorithm_key_size_check(p->algorithm, p->ksk_size) &&
	       dnssec_algorithm_key_size_check(p->algorithm, p->zsk_size);
}

_public_
int dnssec_kasp_policy_validate(const dnssec_kasp_policy_t *policy)
{
	if (!policy) {
		return DNSSEC_EINVAL;
	}

	/*
	 * NOTES:
	 *
	 * - Don't check if key store is set.
	 * - Allow zero TTL for any record.
	 *
	 */

	// required parameters

	if (policy->rrsig_lifetime == 0 ||
	    policy->rrsig_refresh_before == 0
	) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	// signing algorithm constraints

	if (!policy->manual && !valid_algorithm(policy)) {
		return DNSSEC_INVALID_KEY_SIZE;
	}

	return DNSSEC_EOK;
}

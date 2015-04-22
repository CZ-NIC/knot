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

#include <stdlib.h>

#include "shared.h"
#include "error.h"
#include "kasp.h"

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

	// TODO: not all fields are filled
	// TODO: key sizes not algorithm aware
	// TODO: determine defaults for NSEC

	policy->dnskey_ttl = 1200;

	policy->algorithm = DNSSEC_KEY_ALGORITHM_RSA_SHA256;
	policy->ksk_size = 2048;
	policy->zsk_size = 1024;
	policy->zsk_lifetime = 30 * 24 * 60 * 60;

	policy->rrsig_lifetime = 14 * 24 * 60 * 60;
	policy->rrsig_refresh_before = 7 * 24 * 60 * 60;

	policy->propagation_delay = 60 * 60;

	policy->nsec3_enabled = false;
}

_public_
void dnssec_kasp_policy_free(dnssec_kasp_policy_t *policy)
{
	if (!policy) {
		return;
	}

	free(policy->name);
	free(policy);
}

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

#include <stdint.h>
#include <string.h>
#include <time.h>

#include "libknot/dnssec/policy.h"
#include "common/macros.h"

_public_
uint32_t knot_dnssec_policy_refresh_time(const knot_dnssec_policy_t *policy,
                                         uint32_t earliest_expiration)
{
	if (policy == NULL) {
		return 0;
	}

	uint32_t signature_safety = policy->sign_lifetime / 10;
	if (earliest_expiration <= signature_safety) {
		return 0;
	}

	return earliest_expiration - signature_safety;
}

_public_
void knot_dnssec_policy_set_sign_lifetime(knot_dnssec_policy_t *policy,
                                          uint32_t sign_lifetime)
{
	if (policy == NULL) {
		return;
	}

	uint32_t max_expiration = policy->now + sign_lifetime;

	policy->sign_lifetime = sign_lifetime;
	policy->refresh_before = knot_dnssec_policy_refresh_time(policy,
	                                                         max_expiration);
}

_public_
void knot_dnssec_init_default_policy(knot_dnssec_policy_t *policy)
{
	if (policy == NULL) {
		return;
	}

	memset(policy, 0, sizeof(*policy));

	policy->now = time(NULL);
	policy->soa_up = KNOT_SOA_SERIAL_UPDATE;

	knot_dnssec_policy_set_sign_lifetime(policy, KNOT_DNSSEC_DEFAULT_LIFETIME);
}

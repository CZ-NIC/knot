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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>

#include "knot/dnssec/policy.h"
#include "libknot/rrtype/soa.h"

static uint32_t zone_soa_ttl(const zone_contents_t *zone)
{
	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	return soa.ttl;
}

void update_policy_from_zone(knot_kasp_policy_t *policy,
                             const zone_contents_t *zone)
{
	assert(policy);
	assert(zone);

	if (policy->dnskey_ttl == UINT32_MAX) {
		policy->dnskey_ttl = zone_soa_ttl(zone);
	}

	if (policy->zone_maximal_ttl == UINT32_MAX) {
		policy->zone_maximal_ttl = zone->max_ttl;
	}
}

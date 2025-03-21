/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
	if (policy->saved_key_ttl == 0) { // possibly not set yet
		policy->saved_key_ttl = policy->dnskey_ttl;
	}

	if (policy->zone_maximal_ttl == UINT32_MAX) {
		policy->zone_maximal_ttl = zone->max_ttl;
		if (policy->rrsig_refresh_before == UINT32_MAX) {
			uint32_t min = policy->propagation_delay +
			               policy->zone_maximal_ttl;
			uint32_t reserve = 0.1 * policy->rrsig_lifetime;
			policy->rrsig_refresh_before = MIN(
				policy->rrsig_lifetime - policy->rrsig_prerefresh - 1,
				min + reserve
			);
		}
	}
	if (policy->saved_max_ttl == 0) { // possibly not set yet
		policy->saved_max_ttl = policy->zone_maximal_ttl;
	}
}

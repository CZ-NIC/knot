/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>

#include "knot/common/log.h"
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
			policy->rrsig_refresh_before = rrsig_refresh(policy, YP_NIL);
			if (policy->rrsig_refresh_before + policy->rrsig_prerefresh >= policy->rrsig_lifetime) {
				log_zone_warning(zone->apex->owner, "RRSIG refresh + pre-refresh higher than RRSIG lifetime");
				policy->rrsig_refresh_before = policy->rrsig_lifetime - policy->rrsig_prerefresh - 1;
			}
		}
		if (policy->rrsig_refresh_before < policy->zone_maximal_ttl + policy->propagation_delay) {
			log_zone_warning(zone->apex->owner,
			                 "DNSSEC, RRSIG refresh lower than maximum zone TTL + propagation delay");
		}
	}
	if (policy->saved_max_ttl == 0) { // possibly not set yet
		policy->saved_max_ttl = policy->zone_maximal_ttl;
	}

	if (policy->single_type_signing) {
		if (policy->ksk_lifetime != 0 &&
		    policy->ksk_lifetime < 2 * policy->propagation_delay + policy->dnskey_ttl + policy->zone_maximal_ttl) {
			log_zone_warning(zone->apex->owner,
			                 "DNSSEC, CSK lifetime too low according to propagation delay, DNSKEY TTL, "
			                 "and maximum zone TTL");
		}
	} else {
		if (policy->ksk_lifetime != 0 &&
		    policy->ksk_lifetime < 2 * policy->propagation_delay + 2 * policy->dnskey_ttl) {
			log_zone_warning(zone->apex->owner,
			                 "DNSSEC, KSK lifetime too low according to propagation delay and DNSKEY TTL");
		}
		if (policy->zsk_lifetime != 0 &&
		    policy->zsk_lifetime < 2 * policy->propagation_delay + policy->dnskey_ttl + policy->zone_maximal_ttl) {
			log_zone_warning(zone->apex->owner,
			                 "DNSSEC, ZSK lifetime too low according to propagation delay, DNSKEY TTL, "
			                 "and maximum zone TTL");
		}
	}
}

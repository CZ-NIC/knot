/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "utils/kdig/dnssec_validation.h"

#include "knot/dnssec/zone-sign.h"

#include <string.h>

static const knot_rrset_t *find_first(knot_pkt_t *pkt, uint16_t rrtype, knot_section_t limit)
{
	for (int i = 0; i <= limit; i++) {
		for (int j = 0; j < pkt->sections[i].count; j++) {
			const knot_rrset_t *rr = knot_pkt_rr(&pkt->sections[i], j);
			if (rr->type == rrtype) {
				return rr;
			}
		}
	}
	return NULL;
}

static int rrsets_pkt2conts(knot_pkt_t *pkt, zone_contents_t *conts,
                            knot_section_t limit, uint16_t type_only)
{
	int ret = KNOT_EOK;
	for (int i = 0; i <= limit && ret == KNOT_EOK; i++) {
		for (int j = 0; j < pkt->sections[i].count && ret == KNOT_EOK; j++) {
			const knot_rrset_t *rr = knot_pkt_rr(&pkt->sections[i], j);
			if (rr->type == KNOT_RRTYPE_RRSIG) {
				assert(rr->rrs.count == 1);
				if (type_only && knot_rrsig_type_covered(rr->rrs.rdata) != type_only) {
					continue;
				}
			} else if (type_only && rr->type != type_only) {
				continue;
			}

			uint16_t rr_pos = knot_pkt_rr_offset(&pkt->sections[i], j);
			knot_dname_storage_t owner;
			knot_dname_unpack(owner, pkt->wire + rr_pos, sizeof(owner), pkt->wire);
			knot_dname_to_lower(owner);

			knot_rrset_t rrcpy = *rr;
			rrcpy.owner = (knot_dname_t *)&owner;

			zone_node_t *unused = NULL;
			ret = zone_contents_add_rr(conts, &rrcpy, &unused);
		}
	}
	return ret;
}

static int solve_missing_apex(knot_pkt_t *pkt, uint16_t rrtype, zone_contents_t *conts)
{
	if (node_rrtype_exists(conts->apex, rrtype)) {
		return KNOT_EOK;
	}
	if (knot_pkt_qtype(pkt) != rrtype || !knot_dname_is_equal(knot_pkt_qname(pkt), conts->apex->owner)) {
		return KNOT_EAGAIN;
	}
	int ret = rrsets_pkt2conts(pkt, conts, KNOT_ANSWER, rrtype);
	if (ret == KNOT_EOK && !node_rrtype_exists(conts->apex, rrtype)) {
		ret = KNOT_ENOENT;
	}
	return ret;
}

static int dv(knot_pkt_t *pkt, struct zone_contents **dv_contents,
	      knot_dname_t **zone_name, uint16_t *type_needed)
{
	if (pkt == NULL || dv_contents == NULL || zone_name == NULL ||
	    *zone_name != NULL || type_needed == NULL) {
		return KNOT_EINVAL;
	}

	*zone_name = malloc(KNOT_DNAME_MAXLEN + 1);
	if (*zone_name == NULL) {
		return KNOT_ENOMEM;
	}

	if (*dv_contents == NULL) {
		const knot_rrset_t *some_rrsig = find_first(pkt, KNOT_RRTYPE_RRSIG, KNOT_AUTHORITY);
		if (some_rrsig == NULL) {
			return KNOT_DNSSEC_ENOSIG;
		}
		const knot_dname_t *rrsig_zone = knot_rrsig_signer_name(some_rrsig->rrs.rdata);
		memcpy(*zone_name, rrsig_zone, knot_dname_size(rrsig_zone));

		*dv_contents = zone_contents_new(*zone_name, false);
		if (*dv_contents == NULL) {
			return KNOT_ENOMEM;
		}

		int ret = rrsets_pkt2conts(pkt, *dv_contents, KNOT_ADDITIONAL, 0);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
		memcpy(*zone_name, (*dv_contents)->apex->owner, knot_dname_size((*dv_contents)->apex->owner));
	}

	int ret = solve_missing_apex(pkt, KNOT_RRTYPE_SOA, *dv_contents);
	if (ret != KNOT_EOK) { // EAGAIN or failure
		*type_needed = KNOT_RRTYPE_SOA;
		return ret;
	}

	ret = solve_missing_apex(pkt, KNOT_RRTYPE_DNSKEY, *dv_contents);
	if (ret != KNOT_EOK) { // EAGAIN or failure
		*type_needed = KNOT_RRTYPE_DNSKEY;
		return ret;
	}

	// TODO validate RRSIGs

	// TODO validate NSECs and stuff

	// TODO kdig add paramt to trigger this all

	return ret;
}

int kdig_dnssec_validate(knot_pkt_t *pkt, struct zone_contents **dv_contents,
	                 knot_dname_t **zone_name, uint16_t *type_needed)
{
	int ret = dv(pkt, dv_contents, zone_name, type_needed);
	if (ret != KNOT_EAGAIN) {
		zone_contents_deep_free(*dv_contents);
		*dv_contents = NULL;
		free(*zone_name);
		*zone_name = NULL;
	}
	return ret;
}

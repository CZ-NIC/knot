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

#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/adjust.h"

#include <string.h>

typedef struct kdig_dnssec_ctx {
	zone_contents_t *conts;
	knot_dname_t *orig_qname;
	uint16_t orig_qtype;
	dnssec_validation_hint_t hint;
} kdig_dnssec_ctx_t;

static bool has_nsec3(const zone_contents_t *conts)
{
        return conts->nsec3_params.algorithm > 0;
}

static bool bitmap_covers_nsec(const knot_rdata_t *rdata, uint16_t covered_type)
{
	const uint8_t *bitmap = knot_nsec_bitmap(rdata);
	uint16_t bm_len = knot_nsec_bitmap_len(rdata);
	return dnssec_nsec_bitmap_contains(bitmap, bm_len, covered_type);
}

static bool bitmap_covers_nsec3(const knot_rdata_t *rdata, uint16_t covered_type)
{
	const uint8_t *bitmap = knot_nsec3_bitmap(rdata);
	uint16_t bm_len = knot_nsec3_bitmap_len(rdata);
	return dnssec_nsec_bitmap_contains(bitmap, bm_len, covered_type);
}

static bool has_nodata(zone_contents_t *conts, const knot_dname_t *name, uint16_t type)
{
	if (!has_nsec3(conts)) {
		const zone_node_t *node = zone_contents_find_node(conts, name);
		knot_rrset_t nsec = node_rrset(node, KNOT_RRTYPE_NSEC);
		return !knot_rrset_empty(&nsec) && (!type || !bitmap_covers_nsec(nsec.rrs.rdata, type));
	}

	const zone_node_t *nsec3_node = NULL, *nsec3_prev = NULL;
	int ret = zone_contents_find_nsec3_for_name(conts, name, &nsec3_node, &nsec3_prev);
	if (ret != ZONE_NAME_FOUND) {
		return false; // best effort
	}
	knot_rrset_t nsec3 = node_rrset(nsec3_node, KNOT_RRTYPE_NSEC3);
	return !knot_rrset_empty(&nsec3) && (!type || !bitmap_covers_nsec3(nsec3.rrs.rdata, type));
}

static bool nsec_covers_name(const knot_dname_t *nsec_owner, const knot_rdata_t *nsec_rdata,
                             const knot_dname_t *name)
{
	const knot_dname_t *nsec_next = knot_nsec_next(nsec_rdata);
	return knot_dname_cmp(nsec_owner, name) <= 0 && knot_dname_cmp(name, nsec_next) > 0;
}

static bool nsec3_covers_name(const knot_dname_t *nsec3_owner, const knot_rdata_t *nsec3_rdata,
                              const knot_dname_t *name, const knot_dname_t *apex)
{
	const uint8_t *nsec3_hash = knot_nsec3_next(nsec3_rdata);
	uint16_t n3h_len = knot_nsec3_next_len(nsec3_rdata);
	uint8_t nsec3_next[KNOT_DNAME_MAXLEN] = { 0 };
	int ret = knot_nsec3_hash_to_dname(nsec3_next, sizeof(nsec3_next), nsec3_hash, n3h_len, apex);
	return ret == KNOT_EOK /* best effort */ && knot_dname_cmp(nsec3_owner, name) <= 0 && knot_dname_cmp(name, nsec3_next) > 0;
}

static bool has_nxdomain_for_wildcard(zone_contents_t *conts, const knot_dname_t *closest);

static bool has_nxdomain(zone_contents_t *conts, const knot_dname_t *name, bool also_wildcard, bool opt_out)
{
	if (!has_nsec3(conts)) {
		const zone_node_t *match = NULL, *closest = NULL, *prev = NULL;
		int ret = zone_contents_find_dname(conts, name, &match, &closest, &prev, false /*FIXME*/);
		if (ret != 0) { // either found or error
			return false;
		}
		knot_rrset_t nsec = node_rrset(closest, KNOT_RRTYPE_NSEC);
		return !knot_rrset_empty(&nsec) && nsec_covers_name(closest->owner, nsec.rrs.rdata, name) &&
		       (!also_wildcard || has_nxdomain_for_wildcard(conts, closest->owner)) && !opt_out;
	}

	// scan for closest encloser represented by some NSEC3, because the closest encloser node might not be here
	size_t apex_lbs = knot_dname_labels(conts->apex->owner, NULL);
	const knot_dname_t *encloser = knot_dname_next_label(name);
	for (size_t name_lbs = knot_dname_labels(name, NULL); name_lbs > apex_lbs; name_lbs--) {
		if (has_nodata(conts, encloser, 0)) {
			break;
		}
		name = encloser;
		encloser = knot_dname_next_label(name);
	}

	const zone_node_t *nsec3_node = NULL, *nsec3_prev = NULL;
	int ret = zone_contents_find_nsec3_for_name(conts, name, &nsec3_node, &nsec3_prev);
	if (ret != ZONE_NAME_NOT_FOUND) {
		return false; // best effort
	}
	knot_rrset_t nsec3 = node_rrset(nsec3_prev, KNOT_RRTYPE_NSEC3);
	return !knot_rrset_empty(&nsec3) && nsec3_covers_name(nsec3_prev->owner, nsec3.rrs.rdata, name, conts->apex->owner) &&
	       (!also_wildcard || has_nxdomain_for_wildcard(conts, encloser)) &&
	       (!opt_out || (knot_nsec3_flags(nsec3.rrs.rdata) & KNOT_NSEC3_FLAG_OPT_OUT));
}

static bool has_nxdomain_for_wildcard(zone_contents_t *conts, const knot_dname_t *closest)
{
	uint8_t wc[KNOT_DNAME_MAXLEN + 2] = { 1, '*', 0 };
	memcpy(wc + 2, closest, knot_dname_size(closest));
	return has_nxdomain(conts, wc, false, false);
}

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

static int dv(knot_pkt_t *pkt, kdig_dnssec_ctx_t **dv_ctx,
	      knot_dname_t **zone_name, uint16_t *type_needed)
{
	zone_contents_t *conts = NULL;
	if (pkt == NULL || dv_ctx == NULL || zone_name == NULL ||
	    *zone_name != NULL || type_needed == NULL) {
		return KNOT_EINVAL;
	}

	*zone_name = malloc(KNOT_DNAME_MAXLEN + 1);
	if (*zone_name == NULL) {
		return KNOT_ENOMEM;
	}

	if (*dv_ctx == NULL) {
		const knot_rrset_t *some_rrsig = find_first(pkt, KNOT_RRTYPE_RRSIG, KNOT_AUTHORITY);
		if (some_rrsig == NULL) {
			return KNOT_DNSSEC_ENOSIG;
		}
		const knot_dname_t *rrsig_zone = knot_rrsig_signer_name(some_rrsig->rrs.rdata);
		memcpy(*zone_name, rrsig_zone, knot_dname_size(rrsig_zone));

		*dv_ctx = calloc(1, sizeof(**dv_ctx));
		knot_dname_t *orig_qname = knot_dname_copy(knot_pkt_qname(pkt), NULL);
		conts = zone_contents_new(*zone_name, false);
		if (*dv_ctx == NULL || orig_qname == NULL || conts == NULL) {
			return KNOT_ENOMEM;
		}
		(*dv_ctx)->conts = conts;
		(*dv_ctx)->orig_qname = orig_qname;
		(*dv_ctx)->orig_qtype = knot_pkt_qtype(pkt);

		int ret = rrsets_pkt2conts(pkt, conts, KNOT_ADDITIONAL, 0);
		if (ret != KNOT_EOK) {
			return ret;
		}

		const knot_rrset_t *some_nsec3 = find_first(pkt, KNOT_RRTYPE_NSEC3, KNOT_AUTHORITY);
		if (some_nsec3 != NULL) {
			// NOTE assuming here that all NSEC3s have the same salt
			dnssec_binary_t nsec3rd = { .data = some_nsec3->rrs.rdata->data, .size = some_nsec3->rrs.rdata->len };
			ret = dnssec_nsec3_params_from_rdata(&conts->nsec3_params, &nsec3rd);
			if (ret != KNOT_EOK) {
				return knot_error_from_libdnssec(ret);
			}
		}
	} else {
		conts = (*dv_ctx)->conts;
		memcpy(*zone_name, conts->apex->owner, knot_dname_size(conts->apex->owner));
	}

	int ret = solve_missing_apex(pkt, KNOT_RRTYPE_SOA, conts);
	if (ret != KNOT_EOK) { // EAGAIN or failure
		*type_needed = KNOT_RRTYPE_SOA;
		return ret;
	}

	ret = solve_missing_apex(pkt, KNOT_RRTYPE_DNSKEY, conts);
	if (ret != KNOT_EOK) { // EAGAIN or failure
		*type_needed = KNOT_RRTYPE_DNSKEY;
		return ret;
	}

	ret = zone_adjust_contents(conts, adjust_cb_flags, NULL, false, false, 1, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// NOTE at this point we have complete "contents" filled with the answer, relevant SOA and DNSKEY and their RRSIGs

	dnssec_validation_hint_t *hint = &(*dv_ctx)->hint;

	const zone_node_t *match = NULL, *closest = NULL, *prev = NULL;
	ret = zone_contents_find_dname(conts, (*dv_ctx)->orig_qname, &match, &closest, &prev, false/*FIME*/);
	if (ret < 0) {
		return ret;
	}
	while ((closest->flags & NODE_FLAGS_NONAUTH)) {
		closest = node_parent(closest);
	}
	if ((closest->flags & NODE_FLAGS_DELEG)) {
		if (!node_rrtype_exists(closest, KNOT_RRTYPE_DS) &&
		    !has_nodata(conts, closest->owner, KNOT_RRTYPE_DS) &&
		    !has_nxdomain(conts, closest->owner, false, true)) {
			hint->warning = KNOT_DNSSEC_ENONSEC;
			hint->node = closest->owner;
			hint->rrtype = KNOT_RRTYPE_DS;
			return 1;
		}
	} else if (ret == ZONE_NAME_NOT_FOUND) {
		if (!has_nxdomain(conts, (*dv_ctx)->orig_qname, true, false)) {
			hint->warning = KNOT_DNSSEC_ENSEC_CHAIN;
			hint->node = (*dv_ctx)->orig_qname;
			hint->rrtype = (*dv_ctx)->orig_qtype;
			return 1;
		}
	} else if (!node_rrtype_exists(match, (*dv_ctx)->orig_qtype)) {
		if (!has_nodata(conts, match->owner, (*dv_ctx)->orig_qtype)) {
			hint->warning = KNOT_DNSSEC_ENSEC_BITMAP;
			hint->node = match->owner;
			hint->rrtype = (*dv_ctx)->orig_qtype;
			return 1;
		}
	}

	kdnssec_ctx_t kd_ctx = { 0 };
	ret = kdnssec_validation_ctx(NULL, &kd_ctx, conts);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zone_update_t fake_up = { .new_cont = conts };
	ret = knot_zone_sign(&fake_up, NULL, &kd_ctx);
	kdnssec_ctx_deinit(&kd_ctx);
	if (ret == KNOT_DNSSEC_ENOSIG) { // TODO also KNOT_DNSSEC_EKEYTAG_LIMIT?
		memcpy(hint, &fake_up.validation_hint, sizeof(*hint));
		hint->warning = ret;
		return 1;
	}

	return ret;
}

int kdig_dnssec_validate(knot_pkt_t *pkt, struct kdig_dnssec_ctx **dv_ctx,
	                 knot_dname_t **zone_name, uint16_t *type_needed)
{
	int ret = dv(pkt, dv_ctx, zone_name, type_needed);
	if (ret == 1) {
		// TODO print error and hint
	}
	if (ret != KNOT_EAGAIN) {
		zone_contents_deep_free((*dv_ctx)->conts);
		free((*dv_ctx)->orig_qname);
		free(*dv_ctx);
		*dv_ctx = NULL;
		free(*zone_name);
		*zone_name = NULL;
	}
	return ret;
}

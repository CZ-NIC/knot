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

#define CNAME_LIMIT 3

typedef struct kdig_dnssec_ctx {
	zone_contents_t *conts;
	knot_dname_t *orig_qname;
	uint16_t orig_qtype;
	knot_rcode_t orig_rcode;
	dnssec_validation_hint_t hint;
} kdig_dnssec_ctx_t;

void set_hint(dnssec_validation_hint_t *hint, const knot_dname_t *name,
              uint16_t type, int ret)
{
	hint->node = knot_dname_copy(name, NULL);
	hint->rrtype = type;
	hint->warning = ret;
}

static int restore_orig_ttls(zone_node_t *node, void *unused)
{
	knot_rdataset_t *rrsig = node_rdataset(node, KNOT_RRTYPE_RRSIG);
	if (rrsig != NULL) {
		knot_rdata_t *rd = rrsig->rdata;
		for (int i = 0; i < rrsig->count; i++) {
			(void)node_set_ttl(node, knot_rrsig_type_covered(rd), knot_rrsig_original_ttl(rd));
			rd = knot_rdataset_next(rd);
		}
	}
	return KNOT_EOK;
}

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

static bool has_nodata_nolog(zone_contents_t *conts, const knot_dname_t *name, uint16_t type,
                             const knot_dname_t **where)
{
	if (!has_nsec3(conts)) {
		const zone_node_t *node = zone_contents_find_node(conts, name);
		knot_rrset_t nsec = node_rrset(node, KNOT_RRTYPE_NSEC);
		*where = nsec.owner;
		return !knot_rrset_empty(&nsec) && (!type || !bitmap_covers_nsec(nsec.rrs.rdata, type));
	}

	const zone_node_t *nsec3_node = NULL, *nsec3_prev = NULL;
	int ret = zone_contents_find_nsec3_for_name(conts, name, &nsec3_node, &nsec3_prev);
	if (ret != ZONE_NAME_FOUND) {
		return false; // best effort
	}
	knot_rrset_t nsec3 = node_rrset(nsec3_node, KNOT_RRTYPE_NSEC3);
	*where = nsec3.owner;
	return !knot_rrset_empty(&nsec3) && (!type || !bitmap_covers_nsec3(nsec3.rrs.rdata, type));
}

static bool has_nodata(zone_contents_t *conts, const knot_dname_t *name, uint16_t type, bool is_deleg, int debug)
{
	const knot_dname_t *where = NULL;
	bool res = has_nodata_nolog(conts, name, type, &where);
	if (debug > 1) {
		char where_txt[KNOT_DNAME_TXT_MAXLEN] = { 0 };
		if (where != NULL) {
			knot_dname_to_str(where_txt, where, sizeof(where_txt));
		}
		printf(";; INFO: DNSSEC VALIDATION: %s proof %s %s\n",
		       type == 0 ? "encloser" : is_deleg ? "DS nonexistence" : "NODATA",
		       res ? "found" : "not found", where_txt);
	}
	return res;
}

static bool nsec_covers_name(const knot_dname_t *nsec_owner, const knot_rdata_t *nsec_rdata,
                             const knot_dname_t *name)
{
	const knot_dname_t *nsec_next = knot_nsec_next(nsec_rdata);
	return knot_dname_cmp(nsec_owner, name) <= 0 && knot_dname_cmp(name, nsec_next) < 0;
}

static bool nsec3_covers_name(const knot_dname_t *nsec3_owner, const knot_rdata_t *nsec3_rdata,
                              const knot_dname_t *name, const knot_dname_t *apex)
{
	const uint8_t *nsec3_hash = knot_nsec3_next(nsec3_rdata);
	uint16_t n3h_len = knot_nsec3_next_len(nsec3_rdata);
	uint8_t nsec3_next[KNOT_DNAME_MAXLEN] = { 0 };
	int ret = knot_nsec3_hash_to_dname(nsec3_next, sizeof(nsec3_next), nsec3_hash, n3h_len, apex);
	return ret == KNOT_EOK /* best effort */ && knot_dname_cmp(nsec3_owner, name) <= 0 && knot_dname_cmp(name, nsec3_next) < 0;
}

static bool has_nxdomain_nolog(zone_contents_t *conts, const knot_dname_t *name, bool opt_out, int debug,
                               const knot_dname_t **where, const knot_dname_t **encloser)
{
	if (!has_nsec3(conts)) {
		const zone_node_t *match = NULL, *closest = NULL, *prev = NULL;
		int ret = zone_contents_find_dname(conts, name, &match, &closest, &prev, false /*FIXME*/);
		if (ret != 0) { // either found or error
			return false;
		}
		knot_rrset_t nsec = node_rrset(prev, KNOT_RRTYPE_NSEC);
		*where = nsec.owner;
		*encloser = closest->owner;
		if (!knot_rrset_empty(&nsec) && knot_dname_in_bailiwick(knot_nsec_next(nsec.rrs.rdata), name) >= 0) {
			*encloser = name; // empty-non-terminal detected
		}
		return !opt_out && !knot_rrset_empty(&nsec) && nsec_covers_name(prev->owner, nsec.rrs.rdata, name);
	}

	// scan for closest encloser represented by some NSEC3, because the closest encloser node might not be here
	size_t apex_lbs = knot_dname_labels(conts->apex->owner, NULL);
	*encloser = knot_dname_next_label(name);
	for (size_t name_lbs = knot_dname_labels(name, NULL); name_lbs > apex_lbs; name_lbs--) {
		if (has_nodata(conts, *encloser, 0, false, debug)) {
			break;
		}
		name = *encloser;
		*encloser = knot_dname_next_label(name);
	}

	const zone_node_t *nsec3_node = NULL, *nsec3_prev = NULL;
	knot_dname_storage_t nsec3_name;
	int ret = knot_create_nsec3_owner(nsec3_name, sizeof(nsec3_name), name,
	                                  conts->apex->owner, &conts->nsec3_params);
	if (ret == KNOT_EOK) {
		ret = zone_contents_find_nsec3(conts, nsec3_name, &nsec3_node, &nsec3_prev);
	}
	if (ret != ZONE_NAME_NOT_FOUND) {
		return false; // best effort
	}
	knot_rrset_t nsec3 = node_rrset(nsec3_prev, KNOT_RRTYPE_NSEC3);
	*where = nsec3.owner;
	return !knot_rrset_empty(&nsec3) && nsec3_covers_name(nsec3_prev->owner, nsec3.rrs.rdata, nsec3_name, conts->apex->owner) &&
	       (!opt_out || (knot_nsec3_flags(nsec3.rrs.rdata) & KNOT_NSEC3_FLAG_OPT_OUT));
}

static bool has_nxdomain(zone_contents_t *conts, const knot_dname_t *name,
                         bool opt_out, int debug,
                         const knot_dname_t **encloser)
{
	const knot_dname_t *where = NULL;
	bool res = has_nxdomain_nolog(conts, name, opt_out, debug, &where, encloser);
	if (debug > 1) {
		char name_txt[KNOT_DNAME_TXT_MAXLEN] = { 0 }, where_txt[KNOT_DNAME_TXT_MAXLEN] = { 0 };
		knot_dname_to_str(name_txt, name, sizeof(name_txt));
		if (where != NULL) {
			knot_dname_to_str(where_txt, where, sizeof(where_txt));
		}
		printf(";; INFO: DNSSEC VALIDATION: %s proof of %s %s %s\n",
		       opt_out ? "opt-out" : *encloser == name ? "empty non-terminal" : "NXDOMAIN",
		       name_txt, res ? "found" : "not found", where_txt);
	}
	return res;
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

int remove_cnames(zone_node_t *node, void *data)
{
	knot_rrset_t cname = node_rrset(node, KNOT_RRTYPE_CNAME);
	if (!knot_rrset_empty(&cname)) {
		zone_node_t *unused = NULL;
		return zone_contents_remove_rr(data, &cname, &unused);
	}
	return KNOT_EOK;
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
			} else if ((type_only && rr->type != type_only) || knot_rrtype_is_metatype(rr->type)) {
				continue;
			}

			uint16_t rr_pos = knot_pkt_rr_offset(&pkt->sections[i], j);
			knot_dname_storage_t owner;
			knot_dname_unpack(owner, pkt->wire + rr_pos, sizeof(owner), pkt->wire);
			knot_dname_to_lower(owner);

			knot_rrset_t rrcpy = *rr;
			rrcpy.owner = (knot_dname_t *)&owner;

			zone_node_t *inserted = NULL, *unused = NULL;
			ret = zone_contents_add_rr(conts, &rrcpy, &inserted);
			if (ret == KNOT_ETTL) {
				char rrtype[16] = { 0 };
				knot_rrtype_to_string(rr->type, rrtype, sizeof(rrtype));
				fprintf(stderr, ";; WARNING: DNSSSEC VALIDATION: mismatched TTLs for type %s\n", rrtype);
				ret = KNOT_EOK;
			}

			if (rr->type == KNOT_RRTYPE_CNAME) { // revert the addition if synthesized from DNAME
				while (inserted != NULL && ret == KNOT_EOK) {
					if (node_rrtype_exists(inserted, KNOT_RRTYPE_DNAME)) {
						ret = zone_contents_remove_rr(conts, &rrcpy, &unused);
						break;
					}
					inserted = node_parent(inserted);
				}
			} else if (rr->type == KNOT_RRTYPE_DNAME && ret == KNOT_EOK) {
				ret = zone_tree_sub_apply(conts->nodes, rr->owner, true, remove_cnames, conts);
			}
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

static int check_cname(zone_contents_t *conts, const knot_dname_t *cname,
                       uint16_t type, dnssec_validation_hint_t *hint, int debug,
                       unsigned cname_visit, knot_rcode_t *expected_rcode);

static int check_name(zone_contents_t *conts, const knot_dname_t *name,
                      uint16_t type, dnssec_validation_hint_t *hint, int debug,
                      unsigned cname_visit, knot_rcode_t *expected_rcode)
{
	const knot_dname_t *encloser = NULL;
	const zone_node_t *match = NULL, *closest = NULL, *prev = NULL;
	int ret = zone_contents_find_dname(conts, name, &match, &closest, &prev, false/*FIME*/);
	if (ret < 0) {
		return ret;
	}
	if (expected_rcode != NULL) {
		*expected_rcode = KNOT_RCODE_NOERROR;
	}
	while ((closest->flags & NODE_FLAGS_NONAUTH)) {
		closest = node_parent(closest);
	}
	if ((closest->flags & NODE_FLAGS_DELEG)) {
		if (!node_rrtype_exists(closest, KNOT_RRTYPE_DS) &&
		    !has_nodata(conts, closest->owner, KNOT_RRTYPE_DS, true, debug) &&
		    !has_nxdomain(conts, closest->owner, true, debug, &encloser)) {
			set_hint(hint, closest->owner, KNOT_RRTYPE_DS, KNOT_DNSSEC_ENONSEC);
			return 1;
		}
	} else if (ret == ZONE_NAME_NOT_FOUND) {
		if (node_rrtype_exists(closest, KNOT_RRTYPE_DNAME)) {
			const knot_dname_t *dname_tgt = knot_dname_target(node_rdataset(closest, KNOT_RRTYPE_DNAME)->rdata);
			size_t labels = knot_dname_labels(closest->owner, NULL);
			knot_dname_t *cname = knot_dname_replace_suffix(name, labels, dname_tgt, NULL);
			ret = cname == NULL ? KNOT_ENOMEM : check_cname(conts, cname, type, hint, debug, cname_visit, expected_rcode);
			knot_dname_free(cname, NULL);
			return ret;
		}
		if (!has_nxdomain(conts, name, false, debug, &encloser)) {
			if (cname_visit > 0) {
				return KNOT_EOK; // auth is not obligated to follow the chain whole
			}
			set_hint(hint, name, type, KNOT_DNSSEC_ENSEC_CHAIN);
			return 1;
		}
		if (encloser == name) {
			return KNOT_EOK; // empty non-terminal
		}
		// at this point it is NXDOMAIN answer
		if (expected_rcode != NULL) {
			*expected_rcode = KNOT_RCODE_NXDOMAIN;
		}
		knot_dname_t wc[2 + knot_dname_size(encloser)];
		memcpy(wc, "\x01*", 2);
		memcpy(wc + 2, encloser, knot_dname_size(encloser));
		if (!has_nxdomain(conts, wc, false, debug, &encloser/*NOTE*/)) {
			set_hint(hint, wc, type, KNOT_DNSSEC_ENSEC_CHAIN);
			return 1;
		}
	} else if (node_rrtype_exists(match, KNOT_RRTYPE_CNAME)) {
		const knot_rdataset_t *cn = node_rdataset(match, KNOT_RRTYPE_CNAME);
		return check_cname(conts, knot_cname_name(cn->rdata), type, hint, debug, cname_visit, expected_rcode);
	} else if (!node_rrtype_exists(match, type)) {
		if (!has_nodata(conts, match->owner, type, false, debug)) {
			set_hint(hint, match->owner, type, KNOT_DNSSEC_ENSEC_BITMAP);
			return 1;
		}
	}
	return KNOT_EOK;
}

static int check_cname(zone_contents_t *conts, const knot_dname_t *cname,
                       uint16_t type, dnssec_validation_hint_t *hint, int debug,
                       unsigned cname_visit, knot_rcode_t *expected_rcode)
{
	if (knot_dname_in_bailiwick(cname, conts->apex->owner) < 0) {
		return KNOT_EOK;
	}
	if (cname_visit >= CNAME_LIMIT) {
		printf(";; INFO: DNSSEC VALIDATION: limit of CNAME/DNAME chain reached, giving up\n");
		return KNOT_EOK;
	}
	return check_name(conts, cname, type, hint, debug, cname_visit + 1, expected_rcode);
}

static int dv(knot_pkt_t *pkt, kdig_dnssec_ctx_t **dv_ctx, int debug,
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
		if (debug > 1) {
			char zn[KNOT_DNAME_TXT_MAXLEN] = { 0 };
			knot_dname_to_str(zn, rrsig_zone, sizeof(zn));
			fprintf(stderr, ";; INFO: DNSSEC VALIDATION for zone: %s\n", zn);
		}

		*dv_ctx = calloc(1, sizeof(**dv_ctx));
		knot_dname_t *orig_qname = knot_dname_copy(knot_pkt_qname(pkt), NULL);
		conts = zone_contents_new(*zone_name, false);
		if (*dv_ctx == NULL || orig_qname == NULL || conts == NULL) {
			return KNOT_ENOMEM;
		}
		(*dv_ctx)->conts = conts;
		(*dv_ctx)->orig_qname = orig_qname;
		(*dv_ctx)->orig_qtype = knot_pkt_qtype(pkt);
		(*dv_ctx)->orig_rcode = knot_pkt_ext_rcode(pkt);

		int ret = rrsets_pkt2conts(pkt, conts, KNOT_AUTHORITY, 0);
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

	ret = zone_adjust_contents(conts, adjust_cb_flags, adjust_cb_nsec3_flags, false, true, false, 1, NULL);
	if (ret == KNOT_EOK) {
		ret = zone_tree_apply(conts->nodes, restore_orig_ttls, NULL);
	}
	if (ret == KNOT_EOK) {
		ret = zone_tree_apply(conts->nsec3_nodes, restore_orig_ttls, NULL);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	// NOTE at this point we have complete "contents" filled with the answer, relevant SOA and DNSKEY and their RRSIGs

	dnssec_validation_hint_t *hint = &(*dv_ctx)->hint;
	knot_rcode_t expected_rcode = KNOT_RCODE_NOERROR;

	ret = check_name(conts, (*dv_ctx)->orig_qname, (*dv_ctx)->orig_qtype, hint, debug, 0, &expected_rcode);
	if (ret < 0) {
		return ret;
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
		hint->node = knot_dname_copy(hint->node, NULL);
		return 1;
	}

	if (expected_rcode != (*dv_ctx)->orig_rcode) {
		const knot_lookup_t *item = knot_lookup_by_id(knot_rcode_names, expected_rcode);
		fprintf(stderr, ";; INFO: DNSSEC VALIDATION expected RCODE was: %s\n", item->name);
	} else if (debug > 1) {
		printf(";; INFO: DNSSEC VALIDATION: correct RCODE found\n");
	}

	return ret;
}

int kdig_dnssec_validate(knot_pkt_t *pkt, struct kdig_dnssec_ctx **dv_ctx, int debug,
	                 knot_dname_t **zone_name, uint16_t *type_needed)
{
	int ret = dv(pkt, dv_ctx, debug, zone_name, type_needed);
	if (ret == 1) {
		fprintf(stderr, ";; INFO: DNSSEC VALIDATION NOK! (%s)\n", knot_strerror((*dv_ctx)->hint.warning));
		if ((*dv_ctx)->hint.node != NULL) {
			char hint_name[KNOT_DNAME_TXT_MAXLEN] = { 0 }, hint_type[16] = { 0 };
			knot_dname_to_str(hint_name, (*dv_ctx)->hint.node, sizeof(hint_name));
			knot_rrtype_to_string((*dv_ctx)->hint.rrtype, hint_type, sizeof(hint_type));
			fprintf(stderr, ";; INFO: DNSSEC VALIDATION HINT: %s %s\n", hint_name, hint_type);
			knot_dname_free((void*)(*dv_ctx)->hint.node, NULL);
			(*dv_ctx)->hint.node = NULL;
		}
		ret = KNOT_EOK;
	} else if (ret == KNOT_EOK) {
		fprintf(stderr, ";; INFO: DNSSEC VALIDATION OK!\n");
	}

	if (ret != KNOT_EAGAIN) {
		if (*dv_ctx != NULL) {
			zone_contents_deep_free((*dv_ctx)->conts);
			free((*dv_ctx)->orig_qname);
			free(*dv_ctx);
			*dv_ctx = NULL;
		}
		free(*zone_name);
		*zone_name = NULL;
	}
	return ret;
}

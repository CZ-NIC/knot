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
	knot_dname_t    *orig_qname;
	uint16_t        orig_qtype;
	knot_rcode_t    orig_rcode;
	unsigned        cname_visit;
} kdig_dnssec_ctx_t;

typedef struct {
	zone_contents_t *conts;
	kdig_validation_log_level_t level;
} tree_cb_ctx_t;

static void kdv_log(kdig_validation_log_level_t log_level, kdig_validation_log_level_t set_level,
                    const knot_dname_t *at, const char *msg, ...)
{
	if (set_level >= log_level) {
		fprintf(stdout, ";; DNSSEC VALIDATION: ");
		va_list args;
		va_start(args, msg);
		vfprintf(stdout, msg, args);
		va_end(args);
		if (at != NULL) {
			char at_txt[KNOT_DNAME_TXT_MAXLEN] = { 0 };
			knot_dname_to_str(at_txt, at, sizeof(at_txt));
			fprintf(stdout, " at %s\n", at_txt);
		} else {
			fprintf(stdout, "\n");
		}
	}
}

#define LOG_OUTCOME(level, at, msg, ...) kdv_log(KDIG_VALIDATION_LOG_OUTCOME,   level, at, msg, ##__VA_ARGS__)
#define LOG_ERROR(level, at, msg, ...)   kdv_log(KDIG_VALIDATION_LOG_ERRORS,    level, at, msg, ##__VA_ARGS__)
#define LOG_INF(level, at, msg, ...)     kdv_log(KDIG_VALIDATION_LOG_INFOS,     level, at, msg, ##__VA_ARGS__)

static bool dname_between(const knot_dname_t *first, const knot_dname_t *between, const knot_dname_t *second)
{
	if (knot_dname_cmp(first, second) < 0) {
		return knot_dname_cmp(first, between) < 0 && knot_dname_cmp(between, second) < 0;
	} else {
		return knot_dname_cmp(first, between) < 0 || knot_dname_cmp(between, second) < 0;
	}
}

static bool nsec_covers_name(const knot_dname_t *nsec_owner, const knot_rdata_t *nsec_rdata,
                             const knot_dname_t *name)
{
	const knot_dname_t *nsec_next = knot_nsec_next(nsec_rdata);
	return dname_between(nsec_owner, name, nsec_next);
}

static bool nsec3_covers_name(const knot_dname_t *nsec3_owner,
			      const knot_rdata_t *nsec3_rdata,
			      const knot_dname_t *name,
			      const knot_dname_t *apex)
{
	const uint8_t *nsec3_hash = knot_nsec3_next(nsec3_rdata);
	uint16_t n3h_len = knot_nsec3_next_len(nsec3_rdata);
	uint8_t nsec3_next[KNOT_DNAME_MAXLEN] = { 0 };
	int ret = knot_nsec3_hash_to_dname(nsec3_next, sizeof(nsec3_next), nsec3_hash, n3h_len, apex);
	return ret == KNOT_EOK /* best effort */ && dname_between(nsec3_owner, name, nsec3_next);
}

static int check_nsec3(zone_node_t *node, void *data)
{
	tree_cb_ctx_t *ctx = data;
	dnssec_nsec3_params_t *params = &ctx->conts->nsec3_params;
	dnssec_nsec3_params_t found = { 0 };
	knot_rdataset_t *nsec3 = node_rdataset(node, KNOT_RRTYPE_NSEC3);
	dnssec_binary_t rd = { .data = nsec3->rdata->data, .size = nsec3->rdata->len };
	int ret;
	if ((ret = dnssec_nsec3_params_from_rdata(&found, &rd)) != KNOT_EOK
	    || !dnssec_nsec3_params_match(&found, params)) {
		LOG_ERROR(ctx->level, node->owner, "invalid or unmatching NSEC3");
		return 1;
	}
	free(found.salt.data);

	zone_node_t *prev = node_prev(node);
	nsec3 = node_rdataset(prev, KNOT_RRTYPE_NSEC3);
	if (prev != node && nsec3_covers_name(prev->owner, nsec3->rdata, node->owner, ctx->conts->apex->owner)) {
		LOG_ERROR(ctx->level, node->owner, "overlapping NSEC3 ranges");
		return 1;
	}
	return KNOT_EOK;
}

static bool parents_have_rrtype(zone_node_t *n, uint16_t type)
{
	while ((n = node_parent(n)) != NULL) {
		if (node_rrtype_exists(n, type)) {
			return true;
		}
	}
	return false;
}

static int move_rrset(zone_contents_t *c, zone_node_t *n, uint16_t type, const knot_dname_t *target)
{
	zone_node_t *unused = NULL;
	knot_rrset_t rr = node_rrset(n, type);
	if (knot_rrset_empty(&rr)) {
		return KNOT_EOK;
	}

	const knot_rrset_t rr2 = {
		.owner = (knot_dname_t *)target,
		.type = rr.type,
		.rclass = rr.rclass,
		.ttl = rr.ttl,
		.rrs = rr.rrs,
	};

	int ret = zone_contents_add_rr(c, &rr2, &unused);
	if (ret == KNOT_EOK) {
		ret = zone_contents_remove_rr(c, &rr, &n);
	}
	return ret;
}

static int rrsig_types_labelcnt(const knot_rdataset_t *rrsig,
			     uint16_t *types, /* must be pre-allocated to rrsig->count+1 */
			     uint16_t *lbcnt)
{
	knot_rdata_t *rd = rrsig->rdata;
	for (int i = 0; i < rrsig->count; i++) {
		if (*lbcnt == 0) {
			*lbcnt = knot_rrsig_labels(rd);
		} else if (*lbcnt != knot_rrsig_labels(rd)) {
			return KNOT_ESEMCHECK;
		}
		types[i] = knot_rrsig_type_covered(rd);
		rd = knot_rdataset_next(rd);
	}
	return KNOT_EOK;
}

static int restore_orig_ttls(zone_node_t *node, [[__maybe_unused__]] void *unused)
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

static bool bitmap_covers(const uint8_t *bitmap, uint16_t bm_len,
                          uint16_t rrtype, const zone_node_t *node)
{
	if (node != NULL) {
		for (int i = 0; i < node->rrset_count; i++) {
			uint16_t rrt = node->rrs[i].type;
			if (!dnssec_nsec_bitmap_contains(bitmap, bm_len, rrt)) {
				return true;
			}
		}
		return false;
	} else if (rrtype == 0) {
		return true;
	} else {
		return !dnssec_nsec_bitmap_contains(bitmap, bm_len, rrtype);
	}
}

static bool has_nodata(zone_contents_t *conts, const knot_dname_t *name, uint16_t type,
                       const zone_node_t *from_node, const knot_dname_t **where)
{
	if (!has_nsec3(conts)) {
		const zone_node_t *node = zone_contents_find_node(conts, name);
		knot_rrset_t nsec = node_rrset(node, KNOT_RRTYPE_NSEC);
		if (where != NULL) {
			*where = nsec.owner;
		}
		return !knot_rrset_empty(&nsec)
		       && bitmap_covers(knot_nsec_bitmap(nsec.rrs.rdata),
					knot_nsec_bitmap_len(nsec.rrs.rdata), type, from_node);
	}

	const zone_node_t *nsec3_node = NULL, *nsec3_prev = NULL;
	int ret = zone_contents_find_nsec3_for_name(conts, name, &nsec3_node, &nsec3_prev);
	if (ret != ZONE_NAME_FOUND) {
		return false; // best effort
	}
	knot_rrset_t nsec3 = node_rrset(nsec3_node, KNOT_RRTYPE_NSEC3);
	if (where != NULL) {
		*where = nsec3.owner;
	}
	return !knot_rrset_empty(&nsec3)
	       && bitmap_covers(knot_nsec3_bitmap(nsec3.rrs.rdata),
				knot_nsec3_bitmap_len(nsec3.rrs.rdata), type, from_node);
}

static bool has_nxdomain(zone_contents_t *conts, const knot_dname_t *name, bool opt_out,
                         kdig_validation_log_level_t level, bool *has_opt_out,
                         const knot_dname_t **where, const knot_dname_t **encloser)
{
	if (!has_nsec3(conts)) {
		const zone_node_t *match = NULL, *closest = NULL, *prev = NULL;
		int ret = zone_contents_find_dname(conts, name, &match, &closest, &prev,
						   knot_dname_with_null(name));
		if (ret < 0 || match == prev) {
			return false;
		}
		while (prev->rrset_count == 0) {
			prev = node_prev(prev);
		}
		knot_rrset_t nsec = node_rrset(prev, KNOT_RRTYPE_NSEC);
		*where = nsec.owner;
		*encloser = closest->owner;
		if (!knot_rrset_empty(&nsec)
		    && knot_dname_in_bailiwick(knot_nsec_next(nsec.rrs.rdata), name) >= 0) {
			*encloser = name; // empty-non-terminal detected
		}
		return !opt_out && !knot_rrset_empty(&nsec)
		       && nsec_covers_name(prev->owner, nsec.rrs.rdata, name);
	}

	// scan for closest encloser represented by some NSEC3, because the closest encloser node
	// might not be here
	size_t apex_nlabels = knot_dname_labels(conts->apex->owner, NULL);
	size_t name_nlabels = knot_dname_labels(name, NULL);
	const knot_dname_t *enc_where = NULL;
	*encloser = knot_dname_next_label(name);
	for (; name_nlabels > apex_nlabels; name_nlabels--) {
		if (has_nodata(conts, *encloser, 0, NULL, &enc_where) ||
		    // tricky exception: in some cases the closest encloser is
		    // proven by existence of stuff, e.g. RFC 5155 § 7.2.6
		    zone_contents_find_node(conts, *encloser) != NULL) {
			break;
		}
		name = *encloser;
		*encloser = knot_dname_next_label(name);
	}
	if (name_nlabels <= apex_nlabels) {
		LOG_ERROR(level, name, "NSEC3 encloser proof missing");
		return false;
	} else {
		char enc_name[KNOT_DNAME_TXT_MAXLEN] = { 0 };
		(void)knot_dname_to_str(enc_name, *encloser, sizeof(enc_name));
		LOG_INF(level, enc_where != NULL ? enc_where : *encloser, "NSEC3 encloser %s found", enc_name);
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
	if (has_opt_out != NULL) {
		*has_opt_out = (knot_nsec3_flags(nsec3.rrs.rdata) & KNOT_NSEC3_FLAG_OPT_OUT);
	}
	return !knot_rrset_empty(&nsec3)
	       && nsec3_covers_name(nsec3_prev->owner, nsec3.rrs.rdata, nsec3_name, conts->apex->owner)
	       && (!opt_out || (knot_nsec3_flags(nsec3.rrs.rdata) & KNOT_NSEC3_FLAG_OPT_OUT));
}

static int check_existing_with_nsecs(zone_node_t *node, void *data)
{
	tree_cb_ctx_t *ctx = data;
	const knot_dname_t *where = NULL, *encloser = NULL;
	bool has_opt_out = false;
	if (node->flags & NODE_FLAGS_DELEG) {
		bool has_nxd = has_nxdomain(ctx->conts, node->owner, false, KDIG_VALIDATION_LOG_NONE,
				            &has_opt_out, &where, &encloser);
		if (node_rrtype_exists(node, KNOT_RRTYPE_DS)) {
			if (has_nodata(ctx->conts, node->owner, KNOT_RRTYPE_DS, NULL, NULL)) {
				LOG_ERROR(ctx->level, node->owner,
					  "NSEC(3) wrongly proves insecure delegation");
				return 1;
			} else if (has_nxd) {
				if (has_opt_out) {
					LOG_ERROR(ctx->level, node->owner,
						  "NSEC3 opt-out wrongly applied to secure delegation");
				} else {
					LOG_ERROR(ctx->level, node->owner,
						  "NSEC(3) wrongly proves NXDOMAIN for secure delegation");
				}
				return 1;
			}
		} else if (has_nxd && !has_opt_out) {
			if (has_nsec3(ctx->conts)) {
				LOG_ERROR(ctx->level, node->owner,
					  "NSEC3 opt-out flag missing, proving NXDOMAIN fro insecure delegation");
			} else {
				LOG_ERROR(ctx->level, node->owner,
					  "NSEC wrongly proves NXDOMAIN for insecure delegation");
			}
			return 1;
		}
	} else if (!(node->flags & NODE_FLAGS_NONAUTH)) {
		if (has_nodata(ctx->conts, node->owner, 0, node, NULL)) {
			LOG_ERROR(ctx->level, node->owner, "NSEC(3) wrongly proves NODATA");
			return 1;
		} else if (has_nxdomain(ctx->conts, node->owner, false, KDIG_VALIDATION_LOG_NONE,
					&has_opt_out, &where, &encloser)
			   && (!has_opt_out || (node->flags & NODE_FLAGS_SUBTREE_AUTH))) {
			LOG_ERROR(ctx->level, node->owner, "NSEC(3) wrongly proves NXDOMAIN");
			return 1;
		}
	}
	return KNOT_EOK;
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
                            knot_section_t limit, uint16_t type_only,
                            kdig_validation_log_level_t level)
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
			} else if ((type_only && rr->type != type_only)
				   || knot_rrtype_is_metatype(rr->type)) {
				continue;
			}

			uint16_t rr_pos = knot_pkt_rr_offset(&pkt->sections[i], j);
			knot_dname_storage_t owner;
			knot_dname_unpack(owner, pkt->wire + rr_pos, sizeof(owner), pkt->wire);

			knot_rrset_t rrcpy = *rr;
			rrcpy.owner = (knot_dname_t *)&owner;
			ret = knot_rrset_rr_to_canonical(&rrcpy);
			if (ret != KNOT_EOK) {
				break;
			}

			zone_node_t *inserted = NULL;
			ret = zone_contents_add_rr(conts, &rrcpy, &inserted);
			if (ret == KNOT_ETTL) {
				char rrtype[16] = { 0 };
				knot_rrtype_to_string(rr->type, rrtype, sizeof(rrtype));
				LOG_INF(level, rr->owner, "WARNING: mismatched TTLs for type %s", rrtype);
				ret = KNOT_EOK;
			}
		}
	}
	return ret;
}

static int solve_missing_apex(knot_pkt_t *pkt,
			      uint16_t rrtype,
			      zone_contents_t *conts,
			      kdig_validation_log_level_t level)
{
	if (node_rrtype_exists(conts->apex, rrtype)) {
		return KNOT_EOK;
	}
	if (knot_pkt_qtype(pkt) != rrtype
	    || !knot_dname_is_equal(knot_pkt_qname(pkt), conts->apex->owner)) {
		return KNOT_EAGAIN;
	}
	int ret = rrsets_pkt2conts(pkt, conts, KNOT_ANSWER, rrtype, level);
	if (ret == KNOT_EOK && !node_rrtype_exists(conts->apex, rrtype)) {
		ret = KNOT_ENOENT;
	}
	return ret;
}

static int check_cname(kdig_dnssec_ctx_t *ctx, const knot_dname_t *cname,
                       uint16_t type, kdig_validation_log_level_t level,
                       knot_rcode_t *expected_rcode);

static int check_name(kdig_dnssec_ctx_t *ctx, const knot_dname_t *name,
                      uint16_t type, kdig_validation_log_level_t level,
                      knot_rcode_t *expected_rcode)
{
	const knot_dname_t *where = NULL, *encloser = NULL;
	const zone_node_t *match = NULL, *closest = NULL, *prev = NULL;
	bool has_opt_out = false;
	bool wc_match = knot_dname_is_wildcard(name) && !knot_dname_is_wildcard(ctx->orig_qname);
	int ret = zone_contents_find_dname(ctx->conts, name, &match, &closest, &prev,
					   knot_dname_with_null(name));
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
		if (node_rrtype_exists(closest, KNOT_RRTYPE_DS)) {
			LOG_INF(level, closest->owner, "secure delegation, DS found");
			return KNOT_EOK;
		} else if (has_nodata(ctx->conts, closest->owner, KNOT_RRTYPE_DS, NULL, &where)) {
			LOG_INF(level, where, "insecure delegation, DS NODATA proof found");
		} else if (has_nxdomain(ctx->conts, closest->owner, true, level, &has_opt_out,
					&where, &encloser)) {
			assert(has_opt_out);
			LOG_INF(level, where, "insecure delegation, opt-out proof found");
		} else {
			LOG_ERROR(level, closest->owner,
				  "delegation, DS non-existence proof missing");
			return 1;
		}
	} else if (ret == ZONE_NAME_NOT_FOUND) {
		if (!wc_match && has_nsec3(ctx->conts)
		    && has_nodata(ctx->conts, name, 0, NULL, &where)) {
			if (has_nodata(ctx->conts, name, type, NULL, &where)) {
				LOG_INF(level, where, "NSEC3 NODATA proof found");
				return KNOT_EOK;
			} else {
				LOG_ERROR(level, where, "NSEC3 NODATA proof missing");
				return 1;
			}
		}
		if (node_rrtype_exists(closest, KNOT_RRTYPE_DNAME)) {
			const knot_rdata_t *rdata_tmp = node_rdataset(closest, KNOT_RRTYPE_DNAME)->rdata;
			const knot_dname_t *dname_tgt = knot_dname_target(rdata_tmp);
			size_t labels = knot_dname_labels(closest->owner, NULL);
			knot_dname_t *cname = knot_dname_replace_suffix(name, labels, dname_tgt, NULL);
			if (cname == NULL) {
				return KNOT_ENOMEM;
			}
			LOG_INF(level, cname, "DNAME found, continuing validation");
			ret = check_cname(ctx, cname, type, level, expected_rcode);
			knot_dname_free(cname, NULL);
			return ret;
		}
		if (has_nxdomain(ctx->conts, name, false, level, &has_opt_out, &where, &encloser)) {
			if (wc_match) {
				LOG_INF(level, where, "wildcard non-existence proven");
			} else {
				LOG_INF(level, where, "NXDOMAIN proven");
			}
		} else {
			if (ctx->cname_visit > 0) {
				LOG_INF(level, name,
					"CNAME/DNAME chain not returned whole, please re-query for the target");
				return KNOT_EOK; // auth is not obligated to follow the chain whole
			}
			if (wc_match) {
				LOG_INF(level, where, "wildcard non-existence proof missing");
			} else {
				LOG_INF(level, where, "NXDOMAIN proof missing");
			}
			return 1;
		}
		if (encloser == name) {
			LOG_INF(level, name, "empty non-terminal detected, wildcard not applicable");
			return KNOT_EOK;
		}
		if (knot_dname_is_wildcard(name)) {
			if (expected_rcode != NULL) {
				*expected_rcode = KNOT_RCODE_NXDOMAIN;
			}
		} else {
			knot_dname_t wc[2 + knot_dname_size(encloser)];
			knot_dname_wildcard(encloser, wc, sizeof(wc));
			if (has_opt_out && ctx->orig_rcode == KNOT_RCODE_NOERROR &&
			    zone_contents_find_node(ctx->conts, wc) == NULL) {
				LOG_INF(level, wc, "this is empty non-terminal NODATA unprovable due to NSEC3 opt-out, "
						   "skipping wildcard non-existence proof");
				return KNOT_EOK;
			}
			LOG_INF(level, wc, "checking wildcard non/existence");
			return check_name(ctx, wc, type, level, expected_rcode);
		}
	} else if (node_rrtype_exists(match, KNOT_RRTYPE_CNAME)) {
		const knot_rdataset_t *cn = node_rdataset(match, KNOT_RRTYPE_CNAME);
		LOG_INF(level, knot_cname_name(cn->rdata), "CNAME found, continuing validation");
		return check_cname(ctx, knot_cname_name(cn->rdata), type, level, expected_rcode);
	} else if (!node_rrtype_exists(match, type)) {
		if (has_nodata(ctx->conts, match->owner, type, NULL, &where)) {
			LOG_INF(level, match->owner, "NSEC NODATA proof found");
		} else {
			LOG_ERROR(level, match->owner, "NODATA proof missing");
			return 1;
		}
	} else {
		LOG_INF(level, match->owner, "positive answer found");
	}
	return KNOT_EOK;
}

static int check_cname(kdig_dnssec_ctx_t *ctx, const knot_dname_t *cname,
                       uint16_t type, kdig_validation_log_level_t level,
                       knot_rcode_t *expected_rcode)
{
	if (knot_dname_in_bailiwick(cname, ctx->conts->apex->owner) < 0) {
		return KNOT_EOK;
	}
	if (++ctx->cname_visit >= CNAME_LIMIT) {
		LOG_INF(level, cname, "limit of CNAME/DNAME chain reached, giving up");
		return KNOT_EOK;
	}
	return check_name(ctx, cname, type, level, expected_rcode);
}

static int init_conts_from_pkt(knot_pkt_t *pkt, kdig_dnssec_ctx_t *ctx,
                               kdig_validation_log_level_t level)
{
	const knot_rrset_t *some_rrsig = find_first(pkt, KNOT_RRTYPE_RRSIG, KNOT_AUTHORITY);
	if (some_rrsig == NULL) {
		return KNOT_DNSSEC_ENOSIG;
	}
	const knot_dname_t *rrsig_zone = knot_rrsig_signer_name(some_rrsig->rrs.rdata);

	ctx->orig_qname = knot_dname_copy(knot_pkt_qname(pkt), NULL);
	ctx->conts = zone_contents_new(rrsig_zone, false);
	if (ctx->orig_qname == NULL || ctx->conts == NULL) {
		return KNOT_ENOMEM;
	}
	ctx->orig_qtype = knot_pkt_qtype(pkt);
	ctx->orig_rcode = knot_pkt_ext_rcode(pkt);

	int ret = rrsets_pkt2conts(pkt, ctx->conts, KNOT_AUTHORITY, 0, level);
	if (ret != KNOT_EOK) {
		return ret;
	}

	const knot_rrset_t *some_nsec3 = find_first(pkt, KNOT_RRTYPE_NSEC3, KNOT_AUTHORITY);
	if (some_nsec3 != NULL) {
		dnssec_binary_t nsec3rd = {
			.data = some_nsec3->rrs.rdata->data,
			.size = some_nsec3->rrs.rdata->len,
		};
		ret = dnssec_nsec3_params_from_rdata(&ctx->conts->nsec3_params, &nsec3rd);
		if (ret != KNOT_EOK) {
			return knot_error_from_libdnssec(ret);
		}
	}

	return KNOT_EOK;
}

static int dnssec_validate(knot_pkt_t *pkt,
			   kdig_dnssec_ctx_t **dv_ctx,
			   kdig_validation_log_level_t loglevel,
			   knot_dname_t zone_name[KNOT_DNAME_MAXLEN],
			   uint16_t *type_needed)
{
	if (pkt == NULL || dv_ctx == NULL || zone_name == NULL ||
	    zone_name == NULL || type_needed == NULL) {
		return KNOT_EINVAL;
	}

	if (*dv_ctx == NULL) {
		*dv_ctx = calloc(1, sizeof(**dv_ctx));
		if (*dv_ctx == NULL) {
			return KNOT_ENOMEM;
		}

		int ret = init_conts_from_pkt(pkt, *dv_ctx, loglevel);
		if (ret != KNOT_EOK) {
			return ret;
		} else if (loglevel >= KDIG_VALIDATION_LOG_INFOS) {
			char zn[KNOT_DNAME_TXT_MAXLEN] = { 0 };
			knot_dname_to_str(zn, (*dv_ctx)->conts->apex->owner, sizeof(zn));
			LOG_INF(loglevel, NULL, "for zone: %s", zn);
		}
	}

	zone_contents_t *conts = (*dv_ctx)->conts;
	memcpy(zone_name, conts->apex->owner, knot_dname_size(conts->apex->owner));

	int ret = solve_missing_apex(pkt, KNOT_RRTYPE_DNSKEY, conts, loglevel);
	if (ret != KNOT_EOK) { // EAGAIN or failure
		*type_needed = KNOT_RRTYPE_DNSKEY;
		return ret;
	}

	// revert answering quirks: wildcard expansion and CNAME synthesis
	zone_tree_delsafe_it_t it = { 0 };
	ret = zone_tree_delsafe_it_begin(conts->nodes, &it, false);
	while (ret == KNOT_EOK && !zone_tree_delsafe_it_finished(&it)) {
		zone_node_t *n = zone_tree_delsafe_it_val(&it);
		knot_rrset_t cname = node_rrset(n, KNOT_RRTYPE_CNAME);
		knot_rrset_t rrsig = node_rrset(n, KNOT_RRTYPE_RRSIG);
		if (!knot_rrset_empty(&cname) && parents_have_rrtype(n, KNOT_RRTYPE_DNAME)) {
			ret = zone_contents_remove_rr(conts, &cname, &n);
			zone_tree_delsafe_it_next(&it);
			continue;
		}

		uint16_t nlabels = knot_dname_labels(n->owner, NULL);
		uint16_t rrsig_nlabels = 0;
		uint16_t types[rrsig.rrs.count + 1];
		ret = rrsig_types_labelcnt(&rrsig.rrs, (uint16_t *)&types, &rrsig_nlabels);
		types[rrsig.rrs.count] = KNOT_RRTYPE_RRSIG;
		if (nlabels > rrsig_nlabels && rrsig_nlabels > 0 && !knot_dname_is_wildcard(n->owner)) {
			knot_dname_t wcbuf[knot_dname_size(n->owner)];
			const knot_dname_t *stripped = knot_dname_next_labels(n->owner, nlabels - rrsig_nlabels);
			knot_dname_t *wc = knot_dname_wildcard(stripped, wcbuf, sizeof(wcbuf));
			assert(wc != NULL);
			for (int i = 0; i < rrsig.rrs.count + 1 && ret == KNOT_EOK; i++) {
				ret = move_rrset(conts, n, types[i], wc);
			}
		}
		zone_tree_delsafe_it_next(&it);
	}
	zone_tree_delsafe_it_free(&it);

	if (ret == KNOT_EOK) {
		ret = zone_adjust_contents(conts, adjust_cb_flags, adjust_cb_nsec3_flags, false,
					   true, false, 1, NULL);
	}
	if (ret == KNOT_EOK) {
		ret = zone_tree_apply(conts->nodes, restore_orig_ttls, NULL);
	}
	if (ret == KNOT_EOK) {
		ret = zone_tree_apply(conts->nsec3_nodes, restore_orig_ttls, NULL);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	// NOTE at this point we have complete "contents" filled with the answer, DNSKEY and their RRSIGs

	knot_rcode_t expected_rcode = KNOT_RCODE_NOERROR;
	tree_cb_ctx_t cb_ctx = { .conts = conts, .level = loglevel };

	// check NSEC3 tree consistence
	ret = zone_tree_apply(conts->nsec3_nodes, check_nsec3, &cb_ctx);
	if (ret != KNOT_EOK) { // also '1'
		return ret;
	}

	// check the NSEC(3) proofs relevant for the queried name
	ret = check_name(*dv_ctx, (*dv_ctx)->orig_qname, (*dv_ctx)->orig_qtype, loglevel, &expected_rcode);
	if (ret != KNOT_EOK) { // also '1'
		return ret;
	}

	// check that any NSEC does not prove non-existence of anything existing
	ret = zone_tree_apply(conts->nodes, check_existing_with_nsecs, &cb_ctx);
	if (ret != KNOT_EOK) { // also '1'
		return ret;
	}

	// check validity of all RRSIGs
	kdnssec_ctx_t kd_ctx = { 0 };
	ret = kdnssec_validation_ctx(NULL, &kd_ctx, conts);
	if (ret != KNOT_EOK) {
		return ret;
	}
	kd_ctx.policy->signing_threads = 1;
	zone_update_t fake_up = { .new_cont = conts };
	ret = knot_zone_sign(&fake_up, NULL, &kd_ctx);
	kdnssec_ctx_deinit(&kd_ctx);
	if (ret == KNOT_DNSSEC_ENOSIG) {
		char type_txt[16] = { 0 };
		(void)knot_rrtype_to_string(fake_up.validation_hint.rrtype, type_txt, sizeof(type_txt));
		LOG_ERROR(loglevel, fake_up.validation_hint.node, "invalid or missing RRSIG for %s", type_txt);
		return 1;
	}

	// check RCODE
	if (expected_rcode != (*dv_ctx)->orig_rcode) {
		const knot_lookup_t *item = knot_lookup_by_id(knot_rcode_names, expected_rcode);
		LOG_ERROR(loglevel, NULL, "expected RCODE was: %s", item->name);
		return 1;
	} else {
		LOG_INF(loglevel, NULL, "correct RCODE found");
	}

	return ret;
}

int kdig_dnssec_validate(knot_pkt_t *pkt, kdig_dnssec_ctx_t **dv_ctx,
                         kdig_validation_log_level_t level,
                         knot_dname_t zone_name[KNOT_DNAME_MAXLEN], uint16_t *type_needed)
{
	char type_txt[16] = { 0 };
	int ret = dnssec_validate(pkt, dv_ctx, level, zone_name, type_needed);
	if (ret == 1) {
		LOG_OUTCOME(level, NULL, "NOK!");
		ret = KNOT_EOK;
	} else if (ret == KNOT_DNSSEC_ENOSIG) { // ONLY the case when no RRSIG at all
		LOG_ERROR(level, NULL, "Missing any RRSIGs.");
		LOG_OUTCOME(level, NULL, "NOK!");
		ret = KNOT_EOK;
	} else if (ret == KNOT_EOK) {
		LOG_OUTCOME(level, NULL, "OK!");
	}

	if (ret == KNOT_EAGAIN) {
		knot_rrtype_to_string(*type_needed, type_txt, sizeof(type_txt));
		LOG_INF(level, zone_name, "need to re-query for %s", type_txt);
	} else {
		if (*dv_ctx != NULL) {
			zone_contents_deep_free((*dv_ctx)->conts);
			free((*dv_ctx)->orig_qname);
			free(*dv_ctx);
			*dv_ctx = NULL;
		}
	}
	return ret;
}
